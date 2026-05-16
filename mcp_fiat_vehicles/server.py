"""
FIAT Vehicle Diagnostics MCP Server
==========================================
Industrial vehicle diagnostics platform for Stellantis.

AUTHENTICATION
--------------
  - MCP_AUTH_TOKEN in .env enables OAuth 2.0 at the MCP protocol level
  - ConsentOAuthProvider + PersistentOAuthProvider
  - HTML consent page at /oauth/consent with password field
  - Single password grants access to all tools
  - _RegistrationCompatMiddleware for Antigravity client compatibility

SECTIONS
--------
  A. OAuth Provider
  B. Lifespan context manager
  C. Custom Exceptions
  D. Pydantic models
  E. Utility functions & Domain classes: thresholds, traffic light, similarity, TechnicalParametersVector
  F. File I/O helpers
  G. build_app() factory function
     G1. MCP Resources
     G2. MCP Tools
     G3. MCP Prompts
     G4. Custom HTTP routes
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import re
import shutil
import inspect
from contextlib import asynccontextmanager
from datetime import datetime
from functools import wraps
from pathlib import Path
from string import Template
from typing import Any, Literal

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FILE SYSTEM PATHS
# All paths are resolved relative to the package root so the server works
# regardless of the working directory from which it is launched.
# ---------------------------------------------------------------------------

BASE_DIR  = Path(__file__).parent.parent  # project root: mcp_vehicle_diagnostics/
DIAG_DIR  = BASE_DIR / "Diagnostic"            # vehicles currently in diagnostic (FAIL)
PROD_DIR  = BASE_DIR / "Manufactured Vehicles"    # vehicles that passed diagnostic (PASS)
HIST_DIR  = BASE_DIR / "Intervention History"     # resolved cases used for similarity search
NOTES_DIR = BASE_DIR / "Technical Notes"          # persistent technician notes
CRED_DIR  = BASE_DIR / "credentials"              # OAuth state persistence

# Ensure all required directories exist on startup
for _d in (DIAG_DIR, PROD_DIR, HIST_DIR, NOTES_DIR, CRED_DIR):
    _d.mkdir(exist_ok=True)

_TEMPLATES = Path(__file__).parent / "templates"  # HTML templates for OAuth consent pages

# Global lock to prevent race conditions during file writing
_file_io_lock = asyncio.Lock()

# ---------------------------------------------------------------------------
# A. OAUTH 2.0 PROVIDER
# ---------------------------------------------------------------------------

if _MCP_AUTH_ENABLED := bool(os.getenv("MCP_AUTH_TOKEN")):
    import secrets
    import time
    import urllib.parse
    from mcp.server.auth.provider import (
        AccessToken,
        AuthorizationCode,
        AuthorizationParams,
        RefreshToken,
        construct_redirect_uri,
    )
    from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
    from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
    from fastmcp.server.auth.providers.in_memory import InMemoryOAuthProvider

    class ConsentOAuthProvider(InMemoryOAuthProvider):
        """InMemoryOAuthProvider that redirects to an HTML consent page."""

        def __init__(self, base_url: str) -> None:
            super().__init__(
                base_url=base_url,
                client_registration_options=ClientRegistrationOptions(
                    enabled=True,
                    valid_scopes=["mcp:full"],
                    default_scopes=["mcp:full"],
                ),
                revocation_options=RevocationOptions(enabled=True),
                required_scopes=["mcp:full"],
            )
            self._base_url = base_url.rstrip("/")
            self.pending: dict[str, tuple[OAuthClientInformationFull, AuthorizationParams]] = {}

        async def authorize(
            self,
            client: OAuthClientInformationFull,
            params: AuthorizationParams,
        ) -> str:
            key = secrets.token_urlsafe(16)
            self.pending[key] = (client, params)
            return f"{self._base_url}/oauth/consent?key={urllib.parse.quote(key)}"

        def approve(self, key: str) -> str | None:
            item = self.pending.pop(key, None)
            if item is None:
                return None
            client, params = item
            scopes = params.scopes or []
            if client.scope:
                allowed = set(client.scope.split())
                scopes = [s for s in scopes if s in allowed]
            code_value = f"code_{secrets.token_hex(16)}"
            self.auth_codes[code_value] = AuthorizationCode(
                code=code_value,
                client_id=client.client_id or "",
                redirect_uri=params.redirect_uri,
                redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
                scopes=scopes,
                expires_at=time.time() + 300,
                code_challenge=params.code_challenge,
            )
            return construct_redirect_uri(
                str(params.redirect_uri), code=code_value, state=params.state
            )

        def deny(self, key: str) -> str | None:
            item = self.pending.pop(key, None)
            if item is None:
                return None
            _, params = item
            return construct_redirect_uri(
                str(params.redirect_uri),
                error="access_denied",
                error_description="User denied access",
                state=params.state,
            )

    class PersistentOAuthProvider(ConsentOAuthProvider):
        """ConsentOAuthProvider which persistently stores clients and tokens on disk."""

        def __init__(self, base_url: str, state_path: Path) -> None:
            super().__init__(base_url=base_url)
            self._state_path = state_path
            self._load()

        def _load(self) -> None:
            if not self._state_path.exists():
                return
            try:
                data = json.loads(self._state_path.read_text())
                now = time.time()
                for cdata in data.get("clients", {}).values():
                    c = OAuthClientInformationFull.model_validate(cdata)
                    if c.client_id:
                        self.clients[c.client_id] = c
                for tdata in data.get("refresh_tokens", {}).values():
                    t = RefreshToken.model_validate(tdata)
                    self.refresh_tokens[t.token] = t
                for tdata in data.get("access_tokens", {}).values():
                    t = AccessToken.model_validate(tdata)
                    if t.expires_at is None or t.expires_at > now:
                        self.access_tokens[t.token] = t
                self._access_to_refresh_map.update(data.get("access_to_refresh", {}))
                self._refresh_to_access_map.update(data.get("refresh_to_access", {}))
                logger.info(
                    "OAuth state loaded: %d client(s), %d access token(s)",
                    len(self.clients), len(self.access_tokens),
                )
            except Exception as exc:
                logger.warning("OAuth state unreadable (%s) — starting fresh", exc)
                try:
                    self._state_path.unlink()
                except OSError:
                    pass

        def _save(self) -> None:
            try:
                now = time.time()
                self._state_path.parent.mkdir(parents=True, exist_ok=True)
                data = {
                    "version": 1,
                    "clients": {
                        cid: c.model_dump(mode="json")
                        for cid, c in self.clients.items()
                    },
                    "refresh_tokens": {
                        tok: t.model_dump(mode="json")
                        for tok, t in self.refresh_tokens.items()
                    },
                    "access_tokens": {
                        tok: t.model_dump(mode="json")
                        for tok, t in self.access_tokens.items()
                        if t.expires_at is None or t.expires_at > now
                    },
                    "access_to_refresh": dict(self._access_to_refresh_map),
                    "refresh_to_access": dict(self._refresh_to_access_map),
                }
                self._state_path.write_text(json.dumps(data, indent=2))
            except Exception as exc:
                logger.warning("Failed to save OAuth state: %s", exc)

        async def register_client(self, client_info: OAuthClientInformationFull) -> None:
            await super().register_client(client_info)
            self._save()

        async def exchange_authorization_code(
            self,
            client: OAuthClientInformationFull,
            authorization_code: AuthorizationCode,
        ) -> OAuthToken:
            token = await super().exchange_authorization_code(client, authorization_code)
            self._save()
            return token

        async def exchange_refresh_token(
            self,
            client: OAuthClientInformationFull,
            refresh_token: RefreshToken,
            scopes: list[str],
        ) -> OAuthToken:
            token = await super().exchange_refresh_token(client, refresh_token, scopes)
            self._save()
            return token

        async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
            await super().revoke_token(token)
            self._save()

    _OAUTH_STATE_PATH = Path(
        os.getenv("MCP_OAUTH_STATE_PATH")
        or (CRED_DIR / "oauth_state.json")
    )
    _oauth_provider: PersistentOAuthProvider | None = PersistentOAuthProvider(
        base_url=f"http://localhost:{int(os.getenv('MCP_PORT', '8001'))}",
        state_path=_OAUTH_STATE_PATH,
    )
else:
    _oauth_provider = None

# ---------------------------------------------------------------------------
# B. LIFESPAN CONTEXT MANAGER
# FastMCP calls this async generator once at startup (yields) and once at
# shutdown (finally). The yielded dict becomes ctx.lifespan_context inside
# every tool, allowing shared server-wide state without global variables.
# ---------------------------------------------------------------------------

_lifespan: dict[str, Any] = {}  # module-level reference for custom HTTP routes


@asynccontextmanager
async def lifespan(server: FastMCP):
    """Initialize shared server state and clean up on shutdown."""
    logger.info("FIAT Diagnostics Server started")
    _lifespan.clear()
    try:
        yield _lifespan  # available as ctx.lifespan_context in all tools
    finally:
        logger.info("Server shutting down")

# ---------------------------------------------------------------------------
# C. CUSTOM EXCEPTIONS
# ---------------------------------------------------------------------------

class DiagnosticsError(Exception):
    """Base exception for all FIAT Diagnostics domain errors."""
    pass

class VehicleNotFoundError(DiagnosticsError):
    """Raised when a vehicle serial number does not exist."""
    def __init__(self, serial: str):
        self.serial = serial
        super().__init__(f"Vehicle '{serial}' not found in Diagnostic or Manufactured folders.")

class InvalidSerialError(DiagnosticsError):
    """Raised when a serial number does not match the expected format."""
    def __init__(self, serial: str):
        self.serial = serial
        super().__init__(
            f"Invalid serial '{serial}'. "
            "Expected format: 3 letters + 3 digits + 2 letters (e.g. FKZ125HZ)."
        )

def _validate_serial(serial: str) -> None:
    if not re.fullmatch(r"[A-Z]{3}[0-9]{3}[A-Z]{2}", serial):
        raise InvalidSerialError(serial)

def _handle_domain_errors(func):
    """Decorator to convert domain errors to FastMCP ToolErrors."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            bound_args = inspect.signature(func).bind(*args, **kwargs)
            bound_args.apply_defaults()
            
            if "serial_number" in bound_args.arguments:
                _validate_serial(bound_args.arguments["serial_number"])
                
            return await func(*args, **kwargs)
        except DiagnosticsError as e:
            raise ToolError(str(e))
    return wrapper

# ---------------------------------------------------------------------------
# D. PYDANTIC MODELS
# ---------------------------------------------------------------------------

class AreaStatus(BaseModel):
    area: str
    status: Literal["GREEN", "YELLOW", "RED"]
    anomalies: list[str] = Field(default_factory=list)

class AreaBreakdown(BaseModel):
    serial_number: str
    model: str
    overall_status: Literal["GREEN", "YELLOW", "RED"]
    areas: list[AreaStatus]

class SimilarCase(BaseModel):
    serial_number: str
    model: str
    similarity_score: float
    primary_area: str
    actions_taken: list[str]
    resolved_date: str

class VehicleComparison(BaseModel):
    serial_a: str
    serial_b: str
    differences: dict[str, dict]

class FleetAnomaly(BaseModel):
    serial_number: str
    model: str
    collaudo_date: str
    red_count: int
    yellow_count: int
    worst_area: str

class FleetStats(BaseModel):
    total_vehicles: int
    in_diagnostic: int
    manufactured: int
    pass_rate_pct: float
    avg_days_to_pass: float
    most_common_fail_area: str

class FailAreaHeatmap(BaseModel):
    powertrain_failures: int
    electrical_failures: int
    chassis_failures: int
    adas_failures: int
    total_history_entries: int

class SalesSummary(BaseModel):
    total_sold: int
    total_unsold: int
    total_revenue_eur: float
    avg_price_eur: float

class RevenueByModel(BaseModel):
    model: str
    units_sold: int
    total_revenue_eur: float
    avg_price_eur: float

class TopCustomer(BaseModel):
    customer_name: str
    customer_id: str
    purchases: int
    total_spent_eur: float

class VehicleStatusSummary(BaseModel):
    serial_number: str
    model: str
    status: Literal["PASS", "FAIL"]
    collaudo_date: str
    technician: str

class SaleRecord(BaseModel):
    serial_number: str
    sold: bool
    sale_date: str
    customer_name: str
    customer_id: str
    sale_price_eur: float
    dealer: str
    warranty_years: int

class UnsoldVehicle(BaseModel):
    serial_number: str
    model: str
    collaudo_date: str
    days_since_collaudo: int

class PromotionResult(BaseModel):
    success: bool = Field(description="True if the vehicle was promoted to PASS")
    previous_status: str = Field(description="Previous status of the vehicle")
    current_status: str = Field(description="New status of the vehicle")
    message: str = Field(description="Technical details of the operation")

class InterventionResult(BaseModel):
    serial_number: str
    primary_area: str
    area_status: str
    outcome: str
    actions_taken: list[str]
    date: str
    message: str

class NoteResult(BaseModel):
    title: str
    associated_serial: str | None
    message: str

# ---------------------------------------------------------------------------
# E. UTILITY FUNCTIONS & DOMAIN CLASSES
# ---------------------------------------------------------------------------

# THRESHOLDS maps each parameter name to a 4-tuple:
# (green_min, green_max, yellow_min, yellow_max)
# Values outside the yellow range are classified as RED.
THRESHOLDS: dict[str, tuple] = {
    "engine_compression_bar":   (12.0, 99,   10.0, 11.99),
    "idle_rpm":                 (750,  850,  700,  950),
    "throttle_response_ms":     (0,    150,  151,  200),
    "exhaust_co_ppm":           (0,    499,  500,  700),
    "battery_voltage_v":        (12.4, 99,   12.0, 12.39),
    "battery_soh_pct":          (85,   100,  70,   84),
    "alternator_output_v":      (13.8, 14.4, 13.4, 13.79),
    "can_bus_error_count":      (0,    0,    1,    2),
    "brake_pressure_bar":       (100,  999,  85,   99),
    "brake_balance_pct":        (60,   65,   55,   70),
    "steering_play_deg":        (0,    4.99, 5,    8),
    "suspension_drop_mm":       (0,    7.99, 8,    12),
    "headlight_alignment_mrad": (0,    9.99, 10,   15),
    "abs_response_ms":          (0,    79,   80,   100),
    "ecu_fault_codes":          (0,    0,    1,    1),
    "adas_calibration_score":   (95,   100,  85,   94),
}

# NORM_RANGES defines the absolute min/max for each parameter used to
# normalise raw values into a [0, 1] vector for cosine similarity.
NORM_RANGES: list[tuple] = [
    ("engine_compression_bar",   6,    15),
    ("idle_rpm",                 600,  1000),
    ("throttle_response_ms",     50,   300),
    ("exhaust_co_ppm",           0,    1000),
    ("battery_voltage_v",        10.5, 15.0),
    ("battery_soh_pct",          0,    100),
    ("alternator_output_v",      12.0, 15.0),
    ("can_bus_error_count",      0,    10),
    ("brake_pressure_bar",       50,   150),
    ("brake_balance_pct",        40,   80),
    ("steering_play_deg",        0,    20),
    ("suspension_drop_mm",       0,    25),
    ("headlight_alignment_mrad", 0,    30),
    ("abs_response_ms",          30,   180),
    ("ecu_fault_codes",          0,    10),
    ("adas_calibration_score",   50,   100),
]

def _traffic_light(key: str, val: float) -> str:
    """Return GREEN / YELLOW / RED for a single parameter value.

    Unknown keys default to GREEN to avoid false positives on
    parameters not yet covered by the threshold table.
    """
    if key not in THRESHOLDS:
        return "GREEN"
    g_lo, g_hi, y_lo, y_hi = THRESHOLDS[key]
    if g_lo <= val <= g_hi:
        return "GREEN"
    if y_lo <= val <= y_hi:
        return "YELLOW"
    return "RED"

def _area_status(area_name: str, params: dict) -> AreaStatus:
    """Compute the aggregate traffic-light status for one functional area.

    The area status equals the worst status among its parameters:
    any RED parameter makes the area RED; otherwise any YELLOW makes it YELLOW.
    """
    anomalies, worst = [], "GREEN"
    for key, val in params.items():
        light = _traffic_light(key, val)
        if light == "RED":
            anomalies.append(f"{key}={val} [RED]")
            worst = "RED"
        elif light == "YELLOW" and worst != "RED":
            anomalies.append(f"{key}={val} [YELLOW]")
            worst = "YELLOW"
    return AreaStatus(area=area_name, status=worst, anomalies=anomalies)

def _flatten_params(tp: dict) -> list[float]:
    """Flatten the nested technical_parameters dict into an ordered 16-dim vector.

    The fixed ordering is required for cosine similarity to be meaningful
    across different vehicles.
    """
    order = [
        ("powertrain", "engine_compression_bar"),
        ("powertrain", "idle_rpm"),
        ("powertrain", "throttle_response_ms"),
        ("powertrain", "exhaust_co_ppm"),
        ("electrical", "battery_voltage_v"),
        ("electrical", "battery_soh_pct"),
        ("electrical", "alternator_output_v"),
        ("electrical", "can_bus_error_count"),
        ("chassis",    "brake_pressure_bar"),
        ("chassis",    "brake_balance_pct"),
        ("chassis",    "steering_play_deg"),
        ("chassis",    "suspension_drop_mm"),
        ("adas",       "headlight_alignment_mrad"),
        ("adas",       "abs_response_ms"),
        ("adas",       "ecu_fault_codes"),
        ("adas",       "adas_calibration_score"),
    ]
    return [tp[area][key] for area, key in order]

def _normalize(vec: list[float]) -> list[float]:
    """Min-max normalise a raw parameter vector to the [0, 1] range.

    Clamps values outside the expected range to avoid negative or >1 scores.
    """
    return [
        max(0.0, min(1.0, (val - lo) / (hi - lo)))
        for val, (_, lo, hi) in zip(vec, NORM_RANGES)
    ]

def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two normalised parameter vectors.

    Returns a score in [0, 1] where 1 means identical parameter profiles.
    Returns 0.0 for zero vectors to avoid division by zero.
    """
    dot   = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x ** 2 for x in a))
    mag_b = math.sqrt(sum(x ** 2 for x in b))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return round(dot / (mag_a * mag_b), 4)

def _overall_status(areas: list[AreaStatus]) -> Literal["GREEN", "YELLOW", "RED"]:
    """Return the worst status across all functional areas."""
    s = [a.status for a in areas]
    return "RED" if "RED" in s else "YELLOW" if "YELLOW" in s else "GREEN"

class TechnicalParametersVector:
    """Wraps the 16 technical parameters and exposes computed properties."""
    def __init__(self, tp: dict):
        self._tp = tp
        self._vector = _flatten_params(tp)
        self._normalized = _normalize(self._vector)

    @property
    def normalized(self) -> list[float]:
        """Normalised 16-dim vector for cosine similarity."""
        return self._normalized

    @property
    def overall_status(self) -> str:
        """Worst traffic-light status across all 4 areas."""
        areas = [
            _area_status("powertrain", self._tp["powertrain"]),
            _area_status("electrical", self._tp["electrical"]),
            _area_status("chassis",    self._tp["chassis"]),
            _area_status("adas",       self._tp["adas"]),
        ]
        return _overall_status(areas)

    def __repr__(self) -> str:
        return f"TechnicalParametersVector(status={self.overall_status})"

    def __len__(self) -> int:
        return len(self._vector)

    def __iter__(self):
        return iter(self._normalized)


# ---------------------------------------------------------------------------
# F. FILE I/O HELPERS
# All vehicle data is stored as JSON files inside named subdirectories.
# Folder name convention: "{Model} - {SerialNumber}" (e.g. "500 - FKZ125HZ")
# ---------------------------------------------------------------------------

def _find_vehicle(serial: str) -> tuple[Path, dict] | tuple[None, None]:
    """Search Diagnostic and Manufactured Vehicles for a vehicle by serial number.

    Returns (folder_path, parsed_json) on success, (None, None) if not found.
    The serial is matched against the suffix of the folder name so it works
    for both "Model - Serial" naming formats.
    """
    for base in (DIAG_DIR, PROD_DIR):
        for folder in base.iterdir():
            if folder.is_dir() and folder.name.endswith(serial):
                f = folder / "diagnostic_report.json"
                if f.exists():
                    return folder, json.loads(f.read_text())
    return None, None

def _load_history() -> list[dict]:
    """Load all resolved intervention records from the Intervention History folder.

    Silently skips malformed files to avoid crashing the similarity search
    when a single history entry is corrupted.
    """
    entries = []
    for f in HIST_DIR.glob("*_history.json"):
        try:
            entries.append(json.loads(f.read_text()))
        except Exception:
            pass
    return entries

def _compute_breakdown(serial: str, tp: dict, model: str) -> AreaBreakdown:
    """Build a full AreaBreakdown for all four functional systems.

    This is the central diagnostic summary used by get_area_breakdown,
    confirm_repair_and_promote, and generate_repair_report.
    """
    areas = [
        _area_status("powertrain", tp["powertrain"]),
        _area_status("electrical", tp["electrical"]),
        _area_status("chassis",    tp["chassis"]),
        _area_status("adas",       tp["adas"]),
    ]
    return AreaBreakdown(
        serial_number=serial,
        model=model,
        overall_status=_overall_status(areas),
        areas=areas,
    )

# ---------------------------------------------------------------------------
# G. BUILD_APP — FACTORY FUNCTION
# Using a factory instead of module-level decoration allows the server to be
# instantiated multiple times (e.g. in tests) and keeps all MCP primitives
# (tools, resources, prompts, routes) encapsulated in a single call.
# ---------------------------------------------------------------------------

def build_app() -> FastMCP:
    mcp = FastMCP(
        "FIAT Vehicle Diagnostics",
        instructions=(
            "MCP server for industrial diagnostics of Stellantis vehicles. "
            "Vehicle serial numbers consist of 3 letters + 3 digits + 2 letters (e.g., FKZ125HZ). "
            "Available tools: vehicle diagnostics, fault analysis, search for similar cases, "
            "PASS promotion, fleet statistics, sales, and revenue."
        ),
        lifespan=lifespan,
        auth=_oauth_provider,
    )

    # ── G1. RESOURCE ──────────────────────────────────────────────────────────

    @mcp.resource("fiat://config/thresholds")
    async def get_thresholds() -> str:
        """GREEN/YELLOW/RED thresholds for all 16 technical parameters."""
        return json.dumps(THRESHOLDS, indent=2)

    @mcp.resource("fiat://config/benchmarks")
    async def get_benchmarks() -> str:
        """Factory default settings for the 4 functional systems."""
        return json.dumps({
            "powertrain": {
                "engine_compression_bar": "12.0 – 14.0",
                "idle_rpm": "750 – 850",
                "throttle_response_ms": "< 150 ms",
                "exhaust_co_ppm": "< 500 ppm",
            },
            "electrical": {
                "battery_voltage_v": "12.4 – 12.8 V",
                "battery_soh_pct": "> 85%",
                "alternator_output_v": "13.8 – 14.4 V",
                "can_bus_error_count": "0",
            },
            "chassis": {
                "brake_pressure_bar": "> 100 bar",
                "brake_balance_pct": "60 – 65%",
                "steering_play_deg": "< 5°",
                "suspension_drop_mm": "< 8 mm",
            },
            "adas": {
                "headlight_alignment_mrad": "< 10 mrad",
                "abs_response_ms": "< 80 ms",
                "ecu_fault_codes": "0",
                "adas_calibration_score": "> 95",
            },
        }, indent=2)

    @mcp.resource("fiat://vehicles/diagnostic")
    async def get_diagnostic_list() -> str:
        """Updated list of vehicles undergoing diagnostics (FAIL)."""
        vehicles = []
        for folder in DIAG_DIR.iterdir():
            if folder.is_dir():
                f = folder / "diagnostic_report.json"
                if f.exists():
                    d = json.loads(f.read_text())
                    vehicles.append({
                        "serial_number": d["serial_number"],
                        "model": d["model"],
                        "status": d["status"],
                        "collaudo_date": d["collaudo_date"],
                        "technician": d["technician"],
                    })
        return json.dumps(vehicles, indent=2)

    @mcp.resource("fiat://vehicles/manufactured")
    async def get_manufactured_list() -> str:
        """List of vehicles that have passed the diagnostic test (PASS)."""
        vehicles = []
        for folder in PROD_DIR.iterdir():
            if folder.is_dir():
                f = folder / "diagnostic_report.json"
                if f.exists():
                    d = json.loads(f.read_text())
                    vehicles.append({
                        "serial_number": d["serial_number"],
                        "model": d["model"],
                        "collaudo_date": d["collaudo_date"],
                    })
        return json.dumps(vehicles, indent=2)

    @mcp.resource("fiat://notes/")
    async def get_notes_index() -> str:
        """Index of technical notes saved to a file."""
        notes = sorted(NOTES_DIR.glob("*.json"))
        if not notes:
            return "(No notes available)"
        return "\n".join(f.stem for f in notes)

    @mcp.resource("fiat://notes/{title}")
    async def get_note_content(title: str) -> str:
        """Contents of a specific technical note."""
        note_file = NOTES_DIR / f"{title}.json"
        if not note_file.exists():
            return f"Note '{title}' not found."
        return json.dumps(json.loads(note_file.read_text()), indent=2, ensure_ascii=False)

    # ── G2. TOOL ──────────────────────────────────────────────────────────────

    @mcp.tool()
    async def list_vehicles(
        category: Literal["diagnostic", "manufactured"] = "diagnostic",
        ctx: Context = None,
    ) -> list[dict]:
        """
        List vehicles by category.
        - diagnostic: FAIL vehicles currently being processed
        - manufactured: PASS vehicles that have already been tested

        Args:
            category: ‘diagnostic’ or ‘manufactured’.
        """
        target = DIAG_DIR if category == "diagnostic" else PROD_DIR
        result = []
        for folder in target.iterdir():
            if folder.is_dir():
                f = folder / "diagnostic_report.json"
                if f.exists():
                    d = json.loads(f.read_text())
                    result.append({
                        "serial_number": d["serial_number"],
                        "model": d["model"],
                        "status": d["status"],
                        "collaudo_date": d["collaudo_date"],
                        "technician": d["technician"],
                    })
        await ctx.info(f"list_vehicles({category}): {len(result)} vehicles")
        return result

    @mcp.tool()
    @_handle_domain_errors
    async def get_diagnostic_details(
        serial_number: str,
        ctx: Context = None,
    ) -> dict:
        """
        Returns a complete diagnostic report for a vehicle, including
        all 16 technical parameters grouped by category (powertrain, electrical,
        chassis, ADAS), the current status, and service history.

        Examples of natural language requests:
          “Tell me everything about vehicle ABC123DE”
          “Show me the technical parameters of vehicle XYZ789AB”
          “How is vehicle ABC123DE doing?”

        Args:
            serial_number: Vehicle serial number (e.g., ‘FKZ125HZ’).
        """
        folder, data = _find_vehicle(serial_number)
        if not data:
            raise VehicleNotFoundError(serial_number)
        await ctx.info(f"Details: {serial_number} ({data['model']}, {data['status']})")
        return data

    @mcp.tool()
    @_handle_domain_errors
    async def get_area_breakdown(
        serial_number: str,
        ctx: Context = None,
    ) -> AreaBreakdown:
        """
        Analyze the vehicle's four functional areas (powertrain, electrical,
        chassis, ADAS) and assign each a GREEN/YELLOW/RED status.
        Show exactly which parameters are outside the threshold and by how much.
        Use this tool to determine where to intervene on a vehicle that has failed.

        Examples of natural language requests:
          “Analyze the areas of vehicle ABC123DE”
          “Where does vehicle XYZ789AB have problems?”
          “What is the status of vehicle ABC123DE area by area?”

        Args:
            serial_number: Vehicle serial number.
        """
        folder, data = _find_vehicle(serial_number)
        if not data:
            raise VehicleNotFoundError(serial_number)
        bd = _compute_breakdown(serial_number, data["technical_parameters"], data["model"])
        await ctx.info(f"Breakdown {serial_number}: {bd.overall_status}")
        return bd

    @mcp.tool()
    @_handle_domain_errors
    async def find_similar_cases(
        serial_number: str,
        top_k: int = 3,
        ctx: Context = None,
    ) -> list[SimilarCase]:
        """
        Compare the vehicle's parameters with all previously resolved cases
        using cosine similarity on the 16 normalized parameters. Returns
        the most similar cases along with the corrective actions that worked.
        Use this tool to understand how to resolve a known anomaly.

        Examples of natural language queries:
          “Are there any cases similar to vehicle ABC123DE in the history?”
          “How was a similar problem resolved in the past?”
          “Find the cases closest to vehicle XYZ789AB”

        Args:
            serial_number: Serial number of the FAIL vehicle to analyze.
            top_k: How many similar cases to return (default 3).
        """
        folder, data = _find_vehicle(serial_number)
        if not data:
            raise VehicleNotFoundError(serial_number)
        if data["status"] != "FAIL":
            raise DiagnosticsError(f"Vehicle {serial_number} is already PASS — similarity search is only for FAIL.")

        tp_vector = TechnicalParametersVector(data["technical_parameters"])
        query_vec = tp_vector.normalized
        
        history = _load_history()
        if not history:
            raise DiagnosticsError("No historical cases available.")

        await ctx.info(f"Similarity analysis {serial_number}: {len(history)} historical cases")
        scored = []
        for i, entry in enumerate(history):
            await ctx.report_progress(progress=i + 1, total=len(history))
            if entry["serial_number"] == serial_number:
                continue
            hist_vec = entry.get("similarity_vector")
            if not hist_vec or len(hist_vec) != 16:
                hist_vec = TechnicalParametersVector(entry["technical_parameters_at_failure"]).normalized
            scored.append((_cosine_similarity(query_vec, hist_vec), entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        top = scored[:top_k]
        await ctx.info(f"Top-{top_k} scores: {[round(s, 3) for s, _ in top]}")
        return [
            SimilarCase(
                serial_number=e["serial_number"],
                model=e["model"],
                similarity_score=s,
                primary_area=e["primary_area"],
                actions_taken=e["actions_taken"],
                resolved_date=e["resolved_date"],
            )
            for s, e in top
        ]

    @mcp.tool()
    async def compare_vehicles(
        serial_a: str,
        serial_b: str,
        ctx: Context = None,
    ) -> VehicleComparison:
        """
        Parameter-by-parameter comparison between two vehicles.
        For each parameter: value A, value B, delta, which is worse.

        Args:
            serial_a: Serial number of the first vehicle.
            serial_b: Serial number of the second vehicle.
        """
        _validate_serial(serial_a)
        _validate_serial(serial_b)
        
        _, data_a = _find_vehicle(serial_a)
        _, data_b = _find_vehicle(serial_b)
        if not data_a:
            raise ToolError(str(VehicleNotFoundError(serial_a)))
        if not data_b:
            raise ToolError(str(VehicleNotFoundError(serial_b)))

        vec_a = _flatten_params(data_a["technical_parameters"])
        vec_b = _flatten_params(data_b["technical_parameters"])
        keys  = [name for name, _, _ in NORM_RANGES]
        sev   = {"GREEN": 0, "YELLOW": 1, "RED": 2}

        differences = {
            key: {
                "value_a": va, "status_a": _traffic_light(key, va),
                "value_b": vb, "status_b": _traffic_light(key, vb),
                "delta": round(abs(va - vb), 4),
                "worse": serial_a if sev[_traffic_light(key, va)] >= sev[_traffic_light(key, vb)] else serial_b,
            }
            for key, va, vb in zip(keys, vec_a, vec_b)
        }
        await ctx.info(f"Comparison {serial_a} vs {serial_b}")
        return VehicleComparison(serial_a=serial_a, serial_b=serial_b, differences=differences)

    @mcp.tool()
    async def get_fleet_anomalies(ctx: Context = None) -> list[FleetAnomaly]:
        """
        List all vehicles currently undergoing diagnostics with faults, sorted by
        decreasing severity. Useful for prioritizing repairs.
        """
        result = []
        for folder in DIAG_DIR.iterdir():
            if not folder.is_dir():
                continue
            f = folder / "diagnostic_report.json"
            if not f.exists():
                continue
            data = json.loads(f.read_text())
            tp = data["technical_parameters"]
            areas = [
                _area_status("powertrain", tp["powertrain"]),
                _area_status("electrical", tp["electrical"]),
                _area_status("chassis",    tp["chassis"]),
                _area_status("adas",       tp["adas"]),
            ]
            red_c    = sum(1 for a in areas if a.status == "RED")
            yellow_c = sum(1 for a in areas if a.status == "YELLOW")
            worst = max(areas, key=lambda a: (
                2 if a.status == "RED" else 1 if a.status == "YELLOW" else 0
            )).area
            result.append(FleetAnomaly(
                serial_number=data["serial_number"], model=data["model"],
                collaudo_date=data["collaudo_date"],
                red_count=red_c, yellow_count=yellow_c, worst_area=worst,
            ))
        result.sort(key=lambda x: (-x.red_count, -x.yellow_count))
        await ctx.info(f"Fleet anomalies: {len(result)} vehicles")
        return result

    @mcp.tool()
    @_handle_domain_errors
    async def get_vehicle_status(
        serial_number: str,
        ctx: Context = None,
    ) -> VehicleStatusSummary:
        """
        Vehicle summary: model, status, inspection date, technician.

        Args:
            serial_number: Vehicle serial number.
        """
        folder, data = _find_vehicle(serial_number)
        if not data:
            raise VehicleNotFoundError(serial_number)
        await ctx.info(f"Status {serial_number}: {data['status']}")
        return VehicleStatusSummary(
            serial_number=data["serial_number"],
            model=data["model"],
            status=data["status"],
            collaudo_date=data["collaudo_date"],
            technician=data["technician"],
        )

    @mcp.tool()
    @_handle_domain_errors
    async def log_intervention(
        serial_number: str,
        primary_area: Literal["powertrain", "electrical", "chassis", "adas"],
        actions_taken: list[str] = [],
        outcome: Literal["PASS", "PARTIAL", "OPEN"] = "OPEN",
        technician_notes: str = "",
        ctx: Context = None,
    ) -> InterventionResult:
        """
        Record a technical service call on a vehicle undergoing diagnostics.
        Use this tool when a technician has performed or needs to perform
        work on one of the four functional areas (powertrain, electrical,
        chassis, ADAS). The tool automatically verifies whether the area
        actually requires service — it blocks the entry if the area is already GREEN.
        It populates the history for future similarity searches.

        Examples of natural language requests:
          “Record a service on the electrical system of vehicle ABC123DE”
          “I replaced the battery on vehicle ABC123DE, electrical system, partial result”
          “Note that I repaired the brakes on vehicle XYZ789AB”

        Args:
            serial_number: Vehicle serial number (e.g., ‘FKZ125HZ’).
            primary_area: Affected system: powertrain, electrical, chassis, or ADAS.
            actions_taken: Actions performed (e.g., [‘Battery replacement’]). Default empty.
            outcome: Result: PASS (resolved), PARTIAL (partial), OPEN (open). Default is OPEN.
            technician_notes: Additional notes from the technician. Default is empty.
        """
        folder, data = _find_vehicle(serial_number)
        if not data:
            raise VehicleNotFoundError(serial_number)

        if data["status"] != "FAIL":
            raise DiagnosticsError(f"Vehicle {serial_number} is already PASS — no intervention needed.")

        tp = data["technical_parameters"]
        area_st = _area_status(primary_area, tp[primary_area])
        if area_st.status == "GREEN":
            raise DiagnosticsError(
                f"Area {primary_area} for vehicle {serial_number} is GREEN — "
                "all parameters are nominal. No intervention needed. "
                "Check get_area_breakdown to see which areas require attention."
            )

        today = datetime.now().date().isoformat()
        data["intervention_history"].append({
            "date": today,
            "primary_area": primary_area,
            "actions_taken": actions_taken,
            "outcome": outcome,
            "technician_notes": technician_notes,
        })
        
        async with _file_io_lock:
            (folder / "diagnostic_report.json").write_text(json.dumps(data, indent=2))
            (HIST_DIR / f"{serial_number}_history.json").write_text(json.dumps({
                "serial_number": serial_number,
                "model": data["model"],
                "resolved_date": today,
                "technician": data["technician"],
                "primary_area": primary_area,
                "actions_taken": actions_taken,
                "outcome": outcome,
                "technical_parameters_at_failure": data["technical_parameters"],
                "similarity_vector": TechnicalParametersVector(data["technical_parameters"]).normalized,
            }, indent=2))

        await ctx.info(f"Intervention: {serial_number} | {primary_area} [{area_st.status}] | {outcome}")
        await ctx.session.send_resource_updated("fiat://vehicles/diagnostic")
        
        return InterventionResult(
            serial_number=serial_number,
            primary_area=primary_area,
            area_status=area_st.status,
            outcome=outcome,
            actions_taken=actions_taken,
            date=today,
            message="Intervention registered successfully."
        )

    @mcp.tool()
    @_handle_domain_errors
    async def confirm_repair_and_promote(
        serial_number: str,
        performed_action: str = "",
        force_yellow: bool = False,
        ctx: Context = None,
    ) -> PromotionResult:
        """
        Attempts to promote a vehicle from FAIL to PASS by moving it to
        Manufactured Vehicles. Before promotion, it automatically checks
        the status of all 4 functional areas:
          - All GREEN -> immediate promotion.
          - One or more YELLOW -> the tool blocks and shows the anomalies to
            the user. Wait for the human user to explicitly confirm in chat
            before proceeding. If the client supports MCP elicitation, an
            interactive form is shown. If not, a ToolError is raised.
          - At least one RED -> blocks the process and suggests log_intervention.

        IMPORTANT — force_yellow parameter:
          force_yellow must NEVER be set to True autonomously.
          It must be set to True ONLY after the human user has explicitly
          typed a confirmation in the chat (e.g. "Yes, proceed with promotion
          despite YELLOW parameters"). Do not assume confirmation — always
          wait for the user to respond before setting force_yellow=True.

        Examples of natural requests:
          "Promote vehicle ABC123DE"
          "Vehicle XYZ789AB is ready; move it to the tested vehicles"
          "Move vehicle ABC123DE to the vehicles that have passed diagnostics"

        Args:
            serial_number: Serial number of the vehicle to be promoted.
            performed_action: Optional description of the last action performed.
            force_yellow: Set to True ONLY after the human user has explicitly
                          confirmed in chat that they want to proceed despite
                          YELLOW parameters. Never set autonomously.
        """
        source = next(DIAG_DIR.glob(f"* - {serial_number}"), None)
        if not source:
            raise VehicleNotFoundError(serial_number)

        data = json.loads((source / "diagnostic_report.json").read_text())
        tp   = data["technical_parameters"]

        areas = [
            _area_status("powertrain", tp["powertrain"]),
            _area_status("electrical", tp["electrical"]),
            _area_status("chassis",    tp["chassis"]),
            _area_status("adas",       tp["adas"]),
        ]
        red_areas    = [a for a in areas if a.status == "RED"]
        yellow_areas = [a for a in areas if a.status == "YELLOW"]

        # CASE 1 — at least one RED: block and indicate corrective actions
        if red_areas:
            details = [f"{a.area.upper()}: {', '.join(a.anomalies)}" for a in red_areas]
            msg = (
                "Promotion BLOCKED. The following areas are in RED status and require intervention:\n"
                + "\n".join(details)
                + "\nUse log_intervention to record necessary repairs."
            )
            raise DiagnosticsError(msg)

        # CASE 2 — at least one YELLOW: requires explicit human confirmation.
        # The tool blocks here and waits for the user to confirm in chat.
        # The agent must NOT call this tool again with force_yellow=True
        # until the human has explicitly confirmed in the conversation.
        if yellow_areas and not force_yellow:
            yellow_list = ", ".join(a.area for a in yellow_areas)
            details = [f"{a.area.upper()}: {', '.join(a.anomalies)}" for a in yellow_areas]
            warning_msg = (
                f"Vehicle {serial_number} has YELLOW parameters in: {yellow_list}.\n"
                + "\n".join(details)
                + "\n\nDo you want to proceed with the promotion to PASS anyway?"
            )
            try:
                from pydantic import BaseModel as _BM
                class _YellowConfirm(_BM):
                    confirm: bool = Field(
                        default=False,
                        description="Confirm promotion despite YELLOW parameters"
                    )
                result = await ctx.elicit(message=warning_msg, schema=_YellowConfirm)
                if result.action != "accept" or not (result.data and result.data.confirm):
                    return PromotionResult(
                        success=False,
                        previous_status="FAIL",
                        current_status="FAIL",
                        message="Promotion cancelled by user due to YELLOW parameters."
                    )
            except Exception as exc:
                await ctx.warning(f"Elicitation not supported: {type(exc).__name__}: {exc}")
                raise DiagnosticsError(
                    "PROMOTION SUSPENDED — mandatory confirmation required.\n"
                    f"Vehicle {serial_number} has YELLOW parameters in: {yellow_list}.\n\n"
                    + "\n".join(details) + "\n\n"
                    "Show this message to the user and wait for their response. "
                    "Only if the user explicitly confirms in chat, "
                    "call the tool again with force_yellow=True."
                )

        # CASE 3 — all GREEN (or YELLOW confirmed by human): promote
        data["status"] = "PASS"
        data["intervention_history"].append({
            "date": datetime.now().date().isoformat(),
            "action": performed_action or "Inspection completed.",
            "notes": "Promoted to PASS after complete diagnostic verification.",
        })

        target = PROD_DIR / source.name
        
        async with _file_io_lock:
            target.mkdir(exist_ok=True)
            (target / "diagnostic_report.json").write_text(json.dumps(data, indent=2))
            (target / "sales_record.json").write_text(json.dumps({
                "serial_number": serial_number, "sold": False,
                "sale_date": None, "customer_name": None,
                "customer_id": None, "sale_price_eur": None,
                "dealer": None, "warranty_years": None,
            }, indent=2))

            (source / "diagnostic_report.json").unlink()
            try:
                source.rmdir()
            except OSError:
                shutil.rmtree(source)

        all_green = not yellow_areas
        await ctx.info(f"Promoted to PASS: {serial_number} (all_green={all_green})")
        await ctx.session.send_resource_updated("fiat://vehicles/diagnostic")
        await ctx.session.send_resource_updated("fiat://vehicles/manufactured")

        return PromotionResult(
            success=True,
            previous_status="FAIL",
            current_status="PASS",
            message="Vehicle successfully promoted to PASS."
        )

    @mcp.tool()
    @_handle_domain_errors
    async def generate_repair_report(
        serial_number: str,
        ctx: Context = None,
    ) -> str:
        """
        Generate a formal repair report directly from the server.
        Includes identification data, fault analysis by area, service history,
        and a final recommendation based on the current status.
        It always works, with no external dependencies.

        Examples of natural language requests:
          “Generate the repair report for vehicle ABC123DE”
          “I want the formal report for vehicle XYZ789AB”
          “Prepare the test documentation for ABC123DE”

        Args:
            serial_number: Vehicle serial number.
        """
        folder, data = _find_vehicle(serial_number)
        if not data:
            raise VehicleNotFoundError(serial_number)

        await ctx.report_progress(progress=0, total=3)
        tp = data["technical_parameters"]
        bd = _compute_breakdown(serial_number, tp, data["model"])
        await ctx.report_progress(progress=1, total=3)

        today = datetime.now().date().isoformat()

        # -----------------------------------------------------------------------
        # MCP SAMPLING — ALTERNATIVE IMPLEMENTATION (currently commented out)
        #
        # The block below delegates report generation to the host LLM via the
        # MCP sampling protocol (ctx.sample). This approach produces richer,
        # more natural language output because the connected agent writes the
        # report using its full reasoning capability — no predefined template.
        #
        # HOW IT WORKS:
        #   1. The server builds a structured prompt with vehicle data.
        #   2. ctx.sample() sends a sampling/createMessage request to the client.
        #   3. The client LLM generates the text and returns it to the server.
        #   4. The server returns the LLM-generated text as the tool result.
        #
        # WHY IT IS COMMENTED OUT:
        #   Gemini on Antigravity does not yet implement the MCP sampling
        #   protocol (sampling/createMessage). Calling ctx.sample() raises an
        #   exception on this client. The server-side implementation below is
        #   used instead because it works on any MCP client without dependencies.
        #
        # TO RE-ENABLE: uncomment this block, comment out the server-side
        # implementation, and connect a sampling-capable client such as
        # Claude Code >= 2.1.76.
        #
        # anomalies_text = "\n".join(
        #     "  " + a.area.upper() + " [" + a.status + "]: " + ", ".join(a.anomalies)
        #     for a in bd.areas if a.status != "GREEN"
        # ) or "  No anomalies detected."
        #
        # history_lines = [
        #     "  " + h.get("date", "?") + " | "
        #     + h.get("primary_area", h.get("action", "?"))
        #     + " | outcome: " + h.get("outcome", "?")
        #     for h in data["intervention_history"]
        # ]
        # history_text = "\n".join(history_lines) or "  No interventions recorded."
        #
        # sampling_prompt = (
        #     "You are a senior Stellantis quality technician. "
        #     "Write a formal repair report in Italian (max 400 words).\n\n"
        #     "VEHICLE: " + data["model"] + " | Serial: " + serial_number
        #     + " | VIN: " + data["vin"] + "\n"
        #     "Collaudo date: " + data["collaudo_date"]
        #     + " | Technician: " + data["technician"] + "\n"
        #     "Current status: " + data["status"] + "\n\n"
        #     "ANOMALIES:\n" + anomalies_text + "\n\n"
        #     "INTERVENTION HISTORY:\n" + history_text + "\n\n"
        #     "The report must include: executive summary, area-by-area anomaly "
        #     "analysis, interventions and their effectiveness, final recommendation, "
        #     "technician signature and date."
        # )
        #
        # await ctx.info("Requesting report via MCP sampling for " + serial_number)
        # try:
        #     result = await ctx.sample(sampling_prompt)
        #     await ctx.report_progress(progress=3, total=3)
        #     await ctx.info("MCP sampling report complete")
        #     return result.text  # type: ignore[union-attr]
        # except Exception as exc:
        #     raise ToolError(
        #         "generate_repair_report requires MCP sampling support. "
        #         "The connected client does not support it (" + type(exc).__name__ + "). "
        #         "Switch to Claude Code >= 2.1.76 or another sampling-capable host, "
        #         "or use the server-side implementation below."
        #     ) from exc
        # -----------------------------------------------------------------------
 
        # SERVER-SIDE IMPLEMENTATION
        # Used because Gemini on Antigravity does not support MCP sampling.
        # Produces a deterministic, structured report directly from vehicle data.
        # Produces identical output for identical inputs — no LLM variability.

        area_lines = []
        for a in bd.areas:
            if a.anomalies:
                area_lines.append(f"  {a.area.upper()} [{a.status}]: {', '.join(a.anomalies)}")
            else:
                area_lines.append(f"  {a.area.upper()} [{a.status}]: no anomalies")
        areas_text = "\n".join(area_lines)

        if data["intervention_history"]:
            hist_lines = []
            for i, h in enumerate(data["intervention_history"], 1):
                date_h    = h.get("date", "?")
                area_h    = h.get("primary_area", h.get("action", "?"))
                outcome_h = h.get("outcome", "?")
                actions_h = h.get("actions_taken", [])
                notes_h   = h.get("technician_notes", h.get("notes", ""))
                line = f"  {i}. [{date_h}] Area: {area_h} | Outcome: {outcome_h}"
                if actions_h:
                    line += f"\n     Actions: {', '.join(actions_h)}"
                if notes_h:
                    line += f"\n     Notes: {notes_h}"
                hist_lines.append(line)
            history_text = "\n".join(hist_lines)
        else:
            history_text = "  No interventions recorded."

        red_areas    = [a.area for a in bd.areas if a.status == "RED"]
        yellow_areas = [a.area for a in bd.areas if a.status == "YELLOW"]

        if bd.overall_status == "GREEN":
            recommendation = (
                "All parameters are within factory nominal values. "
                "The vehicle is suitable for PASS promotion and delivery."
            )
        elif bd.overall_status == "YELLOW":
            recommendation = (
                f"The vehicle has YELLOW parameters in: {', '.join(yellow_areas)}. "
                "Close monitoring is recommended. Promotion requires confirmation."
            )
        else:
            recommendation = (
                f"The vehicle has critical (RED) anomalies in: {', '.join(red_areas)}. "
                "Complete corrective interventions before PASS promotion."
            )

        await ctx.report_progress(progress=2, total=3)

        sep = "=" * 60
        sep2 = "-" * 30
        report = "\n".join([
            sep,
            "REPAIR REPORT — STELLANTIS FIAT DIAGNOSTICS",
            sep,
            "",
            "IDENTIFICATION DATA",
            sep2,
            f"Serial:        {serial_number}",
            f"VIN:           {data['vin']}",
            f"Model:         {data['model']}",
            f"Status:        {data['status']}",
            f"Test date:     {data['collaudo_date']}",
            f"Technician:    {data['technician']}",
            f"Report date:   {today}",
            "",
            "FUNCTIONAL AREAS ANALYSIS",
            sep2,
            areas_text,
            "",
            "INTERVENTION HISTORY",
            sep2,
            history_text,
            "",
            "FINAL RECOMMENDATION",
            sep2,
            recommendation,
            "",
            sep,
            f"Technician signature: {data['technician']}",
            f"Date:                 {today}",
            sep,
        ])

        await ctx.report_progress(progress=3, total=3)
        await ctx.info(f"Report generated for {serial_number} — status: {bd.overall_status}")
        return report

    @mcp.tool()
    async def log_technical_note(
        title: str,
        content: str,
        serial_number: str | None = None,
        ctx: Context = None,
    ) -> NoteResult:
        """
        Save a persistent technical note to a JSON file.
        Accessible via the resource fiat://notes/{title}.

        Args:
            title: Note title.
            content: Note content.
            serial_number: Optional vehicle serial number to associate.
        """
        if serial_number:
            _validate_serial(serial_number)
            
        note_file = NOTES_DIR / f"{title}.json"
        
        async with _file_io_lock:
            note_file.write_text(json.dumps({
                "title": title, "content": content,
                "serial_number": serial_number,
                "created_at": datetime.now().isoformat(),
            }, indent=2, ensure_ascii=False))
            
        await ctx.info(f"Note saved: '{title}'")
        await ctx.session.send_resource_updated("fiat://notes/")
        await ctx.session.send_resource_updated(f"fiat://notes/{title}")
        return NoteResult(
            title=title,
            associated_serial=serial_number,
            message="Technical note successfully saved and indexed."
        )

    @mcp.tool()
    @_handle_domain_errors
    async def update_diagnostic_parameters(
        serial_number: str,
        area: Literal["powertrain", "electrical", "chassis", "adas"],
        new_values: dict,
        ctx: Context = None,
    ) -> AreaBreakdown:
        """
        Update a vehicle's technical parameters after a physical repair
        performed by the technician, then immediately recalculate the
        area traffic-light status with the new measured values.

        IMPORTANT - when to use this tool:
          - ONLY when the user explicitly states they physically repaired
            something and now wants to record the new sensor readings.
          - NEVER call this tool autonomously to bypass a YELLOW or RED
            promotion gate. If confirm_repair_and_promote detects YELLOW
            or RED areas, follow the correct flow:
              * YELLOW: stop and ask the user for explicit confirmation
                        before promoting. Do NOT update parameters first.
              * RED: tell the user which areas need repair and suggest
                     log_intervention with appropriate corrective actions.

        Parameters by area:
          powertrain: engine_compression_bar, idle_rpm, throttle_response_ms, exhaust_co_ppm
          electrical: battery_voltage_v, battery_soh_pct, alternator_output_v, can_bus_error_count
          chassis:    brake_pressure_bar, brake_balance_pct, steering_play_deg, suspension_drop_mm
          adas:       headlight_alignment_mrad, abs_response_ms, ecu_fault_codes, adas_calibration_score

        Examples of correct natural language requests:
          "I physically replaced the battery; voltage now reads 12.6V, SOH is 92%."
          "After the repair the brake pressure is now 108 bar. Update chassis for XYZ789AB."

        Args:
            serial_number: Vehicle serial number.
            area: Functional area that was physically repaired.
            new_values: Dictionary of new measured values for the repaired area.
        """
        folder, data = _find_vehicle(serial_number)
        if not data:
            raise VehicleNotFoundError(serial_number)
        if data["status"] != "FAIL":
            raise DiagnosticsError(f"Vehicle {serial_number} is already PASS — no update needed.")

        valid_keys = {
            "powertrain": {"engine_compression_bar", "idle_rpm", "throttle_response_ms", "exhaust_co_ppm"},
            "electrical": {"battery_voltage_v", "battery_soh_pct", "alternator_output_v", "can_bus_error_count"},
            "chassis":    {"brake_pressure_bar", "brake_balance_pct", "steering_play_deg", "suspension_drop_mm"},
            "adas":       {"headlight_alignment_mrad", "abs_response_ms", "ecu_fault_codes", "adas_calibration_score"},
        }
        invalid = set(new_values.keys()) - valid_keys[area]
        if invalid:
            raise DiagnosticsError(
                f"Invalid parameters for area {area}: {invalid}. "
                f"Accepted parameters: {valid_keys[area]}"
            )

        current_area = data["technical_parameters"][area]
        current_area.update(new_values)
        data["technical_parameters"][area] = current_area

        data["intervention_history"].append({
            "date": datetime.now().date().isoformat(),
            "primary_area": area,
            "actions_taken": ["Post-intervention diagnostic parameters update"],
            "outcome": "PARTIAL",
            "technician_notes": f"New measured values: {new_values}",
        })
        
        async with _file_io_lock:
            (folder / "diagnostic_report.json").write_text(json.dumps(data, indent=2))

        bd = _compute_breakdown(serial_number, data["technical_parameters"], data["model"])
        new_area_status = next(a for a in bd.areas if a.area == area)

        await ctx.info(
            f"Parameters updated: {serial_number} | {area} → {new_area_status.status}"
        )
        await ctx.session.send_resource_updated("fiat://vehicles/diagnostic")
        return bd

    @mcp.tool()
    async def fleet_stats(ctx: Context = None) -> FleetStats:
        """
        Complete overview of the fleet: total number of vehicles,
        number in diagnostics, number tested, success rate,
        average time to testing, and which area causes the most issues.

        Examples of natural language queries:
          “How's production going?”
          “Give me the fleet statistics”
          “How many vehicles do we have in total, and how many have passed diagnostics?”
        """
        diag_n = sum(1 for f in DIAG_DIR.iterdir() if f.is_dir())
        prod_n = sum(1 for f in PROD_DIR.iterdir() if f.is_dir())
        total  = diag_n + prod_n
        rate   = round(prod_n / total * 100, 1) if total else 0.0

        history = _load_history()
        area_c: dict[str, int] = {}
        for e in history:
            a = e.get("primary_area", "unknown")
            area_c[a] = area_c.get(a, 0) + 1
        most_common = max(area_c, key=area_c.get) if area_c else "N/A"

        from datetime import date
        days = []
        for folder in PROD_DIR.iterdir():
            if folder.is_dir():
                f = folder / "diagnostic_report.json"
                if f.exists():
                    d = json.loads(f.read_text())
                    try:
                        days.append((date.today() - date.fromisoformat(d["collaudo_date"])).days)
                    except Exception:
                        pass
        avg = round(sum(days) / len(days), 1) if days else 0.0
        await ctx.info(f"Fleet: total={total}, PASS={prod_n}, FAIL={diag_n}")
        return FleetStats(
            total_vehicles=total, in_diagnostic=diag_n, manufactured=prod_n,
            pass_rate_pct=rate, avg_days_to_pass=avg, most_common_fail_area=most_common,
        )

    @mcp.tool()
    async def failure_area_heatmap(ctx: Context = None) -> FailAreaHeatmap:
        """
        Distribution of failures by functional area based on historical
        maintenance records. Identifies the most problematic area in the production process.
        """
        history = _load_history()
        counts = {"powertrain": 0, "electrical": 0, "chassis": 0, "adas": 0}
        for e in history:
            a = e.get("primary_area", "")
            if a in counts:
                counts[a] += 1
        await ctx.info(f"Heatmap: {counts}")
        return FailAreaHeatmap(
            powertrain_failures=counts["powertrain"],
            electrical_failures=counts["electrical"],
            chassis_failures=counts["chassis"],
            adas_failures=counts["adas"],
            total_history_entries=len(history),
        )

    @mcp.tool()
    async def sales_summary(ctx: Context = None) -> SalesSummary:
        """
        Sales Summary: How many vehicles were sold, how many are
        still available, total revenue, and average price per vehicle.

        Examples of natural queries:
          “How many sales did we make?”
          “What is the total revenue?”
          “Tell me the sales status”
        """
        sold, unsold, rev = 0, 0, 0.0
        for folder in PROD_DIR.iterdir():
            if not folder.is_dir():
                continue
            s = folder / "sales_record.json"
            if s.exists():
                rec = json.loads(s.read_text())
                if rec.get("sold"):
                    sold += 1
                    rev += rec.get("sale_price_eur", 0) or 0
                else:
                    unsold += 1
        avg = round(rev / sold, 2) if sold else 0.0
        await ctx.info(f"Sales: sold={sold}, rev={rev:.0f}€")
        return SalesSummary(total_sold=sold, total_unsold=unsold, total_revenue_eur=rev, avg_price_eur=avg)

    @mcp.tool()
    async def revenue_by_model(ctx: Context = None) -> list[RevenueByModel]:
        """
        Breakdown of revenue by vehicle model, sorted by descending revenue.
        """
        model_data: dict[str, dict] = {}
        for folder in PROD_DIR.iterdir():
            if not folder.is_dir():
                continue
            r = folder / "diagnostic_report.json"
            s = folder / "sales_record.json"
            if not (r.exists() and s.exists()):
                continue
            model = json.loads(r.read_text())["model"]
            sale  = json.loads(s.read_text())
            if model not in model_data:
                model_data[model] = {"units": 0, "revenue": 0.0}
            if sale.get("sold"):
                model_data[model]["units"] += 1
                model_data[model]["revenue"] += sale.get("sale_price_eur", 0) or 0

        result = sorted([
            RevenueByModel(
                model=m, units_sold=v["units"],
                total_revenue_eur=v["revenue"],
                avg_price_eur=round(v["revenue"] / v["units"], 2) if v["units"] else 0.0,
            )
            for m, v in model_data.items()
        ], key=lambda x: x.total_revenue_eur, reverse=True)
        await ctx.info(f"Revenue by model: {len(result)} models")
        return result

    @mcp.tool()
    async def top_customers(
        top_k: int = 5,
        ctx: Context = None,
    ) -> list[TopCustomer]:
        """
        Sort customers by number of purchases and total spending.

        Args:
            top_k: Number of customers to return (default 5).
        """
        cust: dict[str, dict] = {}
        for folder in PROD_DIR.iterdir():
            if not folder.is_dir():
                continue
            s = folder / "sales_record.json"
            if not s.exists():
                continue
            rec = json.loads(s.read_text())
            if not rec.get("sold"):
                continue
            cid = rec.get("customer_id", "UNKNOWN")
            if cid not in cust:
                cust[cid] = {"name": rec.get("customer_name", "?"), "n": 0, "tot": 0.0}
            cust[cid]["n"] += 1
            cust[cid]["tot"] += rec.get("sale_price_eur", 0) or 0

        result = sorted([
            TopCustomer(customer_name=v["name"], customer_id=cid, purchases=v["n"], total_spent_eur=v["tot"])
            for cid, v in cust.items()
        ], key=lambda x: (-x.purchases, -x.total_spent_eur))
        await ctx.info(f"Top customers: {len(result)}")
        return result[:top_k]

    @mcp.tool()
    async def avg_time_to_pass(
        model_filter: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """
        Average time in days from test date to today for PASS vehicles.

        Args:
            model_filter: Filter by model (e.g., ‘500’). Omit to include all.
        """
        from datetime import date
        by_model: dict[str, list[int]] = {}
        for folder in PROD_DIR.iterdir():
            if not folder.is_dir():
                continue
            f = folder / "diagnostic_report.json"
            if not f.exists():
                continue
            d = json.loads(f.read_text())
            m = d["model"]
            if model_filter and m != model_filter:
                continue
            try:
                by_model.setdefault(m, []).append(
                    (date.today() - date.fromisoformat(d["collaudo_date"])).days
                )
            except Exception:
                pass
        result = {
            m: {"count": len(v), "avg_days": round(sum(v) / len(v), 1)}
            for m, v in by_model.items()
        }
        await ctx.info(f"Avg time to pass: {result}")
        return result

    @mcp.tool()
    @_handle_domain_errors
    async def register_sale(
        serial_number: str,
        customer_name: str,
        customer_id: str,
        sale_price_eur: float,
        dealer: str,
        warranty_years: int = 3,
        ctx: Context = None,
    ) -> SaleRecord:
        """
        Register the sale of a vehicle that has passed diagnostics.
        Updates the sales_record.json file in Manufactured Vehicles and
        notifies the manufactured resource. Only works on PASS vehicles
        that have not yet been sold.

        Examples of natural language requests:
          "Register the sale of vehicle ABC123DE to Mario Rossi for 18500 euros"
          "Vehicle XYZ789AB was sold to customer CUST-042 at dealer Fiat Roma Nord"
          "Mark vehicle ABC123DE as sold"

        Args:
            serial_number: Serial number of the vehicle to sell.
            customer_name: Full name of the buyer.
            customer_id: Customer ID (e.g., 'CUST-042').
            sale_price_eur: Sale price in euros.
            dealer: Name of the dealership handling the sale.
            warranty_years: Warranty duration in years (default 3).
        """
        folder, data = _find_vehicle(serial_number)
        if not data:
            raise VehicleNotFoundError(serial_number)
        if data["status"] != "PASS":
            raise DiagnosticsError(
                f"Vehicle {serial_number} has status {data['status']}. "
                "Only PASS vehicles can be sold. "
                "Use confirm_repair_and_promote to promote the vehicle first."
            )

        sales_path = folder / "sales_record.json"
        if sales_path.exists():
            existing = json.loads(sales_path.read_text())
            if existing.get("sold"):
                raise DiagnosticsError(
                    f"Vehicle {serial_number} has already been sold "
                    f"to {existing['customer_name']} on {existing['sale_date']}."
                )

        today = datetime.now().date().isoformat()
        record = {
            "serial_number": serial_number,
            "sold": True,
            "sale_date": today,
            "customer_name": customer_name,
            "customer_id": customer_id,
            "sale_price_eur": sale_price_eur,
            "dealer": dealer,
            "warranty_years": warranty_years,
        }
        
        async with _file_io_lock:
            sales_path.write_text(json.dumps(record, indent=2))

        await ctx.info(
            f"Sale registered: {serial_number} → {customer_name} "
            f"| €{sale_price_eur} | {dealer}"
        )
        await ctx.session.send_resource_updated("fiat://vehicles/manufactured")

        return SaleRecord(**record)

    @mcp.tool()
    async def unsold_vehicles(
        days_threshold: int = 30,
        ctx: Context = None,
    ) -> list[UnsoldVehicle]:
        """
        List PASS vehicles that have not been sold within the given number
        of days since the collaudo date. Useful for identifying stagnant stock
        that may require a commercial push or price revision.

        Examples of natural language requests:
          "Which vehicles have been sitting unsold for more than 30 days?"
          "Show me the stagnant stock"
          "Are there vehicles that passed diagnostics but haven't been sold yet?"

        Args:
            days_threshold: Minimum days since collaudo to flag a vehicle (default 30).
        """
        from datetime import date

        result = []
        today = date.today()

        for folder in PROD_DIR.iterdir():
            if not folder.is_dir():
                continue
            r = folder / "diagnostic_report.json"
            s = folder / "sales_record.json"
            if not (r.exists() and s.exists()):
                continue

            rec  = json.loads(s.read_text())
            data = json.loads(r.read_text())

            if rec.get("sold"):
                continue

            try:
                col_date = date.fromisoformat(data["collaudo_date"])
                days_elapsed = (today - col_date).days
            except Exception:
                continue

            if days_elapsed >= days_threshold:
                result.append(UnsoldVehicle(
                    serial_number=data["serial_number"],
                    model=data["model"],
                    collaudo_date=data["collaudo_date"],
                    days_since_collaudo=days_elapsed,
                ))

        result.sort(key=lambda x: x.days_since_collaudo, reverse=True)

        await ctx.info(
            f"Unsold vehicles older than {days_threshold} days: {len(result)}"
        )
        return result

    # ── G3. PROMPT ────────────────────────────────────────────────────────────

    @mcp.prompt()
    def complete_diagnosis(serial_number: str) -> str:
        """Complete diagnostic workflow for a FAIL vehicle."""
        return (
            f"Perform a complete diagnosis of the vehicle {serial_number}:\n\n"
            f"1. get_diagnostic_details('{serial_number}') — technical parameters\n"
            f"2. get_area_breakdown('{serial_number}') — traffic light by area\n"
            f"3. find_similar_cases('{serial_number}', top_k=3) — similar historical cases\n"
            f"4. If similarity_score > 0.85, propose the same actions as the similar case.\n"
            f"   Otherwise, analyze the RED anomalies and formulate a recommendation.\n"
            f"5. If requested, call generate_repair_report('{serial_number}').\n"
        )

    @mcp.prompt()
    def report_fleet() -> str:
        """Comprehensive executive report on the fleet and sales."""
        return (
            "Generate a complete executive report:\n\n"
            "1. fleet_stats() — general overview\n"
            "2. failure_area_heatmap() — failure distribution by area\n"
            "3. sales_summary() — sales and revenue summary\n"
            "4. revenue_by_model() — revenue by model\n"
            "5. top_customers(top_k=5) — top customers\n\n"
            "Structure: Executive Summary, Production Quality, Commercial Performance, Recommendations."
        )

    @mcp.prompt()
    def vehicle_comparison(serial_a: str, serial_b: str) -> str:
        """Diagnostic comparison of two vehicles."""
        return (
            f"Compare vehicles {serial_a} and {serial_b}:\n\n"
            f"1. compare_vehicles('{serial_a}', '{serial_b}') — parameter delta\n"
            f"2. get_area_breakdown('{serial_a}') and get_area_breakdown('{serial_b}')\n"
            f"3. Identify: parameters with the largest delta, most problematic area for each vehicle.\n"
        )

    # ── G4. CUSTOM ROUTES ──────────────────────────────

    @mcp.custom_route("/health", methods=["GET"])
    async def health(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "version": "5.0.0", "auth_enabled": _MCP_AUTH_ENABLED})

    @mcp.custom_route("/auth-status", methods=["GET"])
    async def auth_status(request: Request) -> JSONResponse:
        return JSONResponse({"mcp_auth_enabled": _MCP_AUTH_ENABLED})

    _CONSENT_HTML     = (_TEMPLATES / "consent.html").read_text()
    _CONSENT_EXPIRED  = (_TEMPLATES / "consent_expired.html").read_text()

    def _render_consent(key: str, client_name: str, scopes: list[str], error: str = "") -> str:
        scope_items = "".join(f"<li>{s}</li>" for s in scopes)
        error_html  = f'<p class="error">{error}</p>' if error else ""
        return Template(_CONSENT_HTML).substitute(
            key=key, client_name=client_name,
            scope_items=scope_items, error_html=error_html,
        )

    @mcp.custom_route("/oauth/consent", methods=["GET"])
    async def oauth_consent_page(request: Request) -> Response:
        if _oauth_provider is None:
            return Response("MCP auth disabled.", status_code=404)
        key  = request.query_params.get("key", "")
        item = _oauth_provider.pending.get(key)
        if item is None:
            return Response(_CONSENT_EXPIRED, media_type="text/html", status_code=400)
        client, params = item
        client_name = client.client_name or client.client_id or "MCP Client"
        scopes = params.scopes or ["mcp:full"]
        return Response(_render_consent(key, client_name, scopes), media_type="text/html")

    @mcp.custom_route("/oauth/consent", methods=["POST"])
    async def oauth_consent_action(request: Request) -> Response:
        if _oauth_provider is None:
            return Response("MCP auth disabled.", status_code=404)
        form   = await request.form()
        key    = str(form.get("key", ""))
        action = str(form.get("action", "deny"))

        if action == "deny":
            redirect_url = _oauth_provider.deny(key)
            if redirect_url is None:
                return Response(_CONSENT_EXPIRED, media_type="text/html", status_code=400)
            return RedirectResponse(redirect_url, status_code=302)

        entered  = str(form.get("token", ""))
        expected = os.getenv("MCP_AUTH_TOKEN", "")
        if entered != expected:
            item = _oauth_provider.pending.get(key)
            if item is None:
                return Response(_CONSENT_EXPIRED, media_type="text/html", status_code=400)
            client, params = item
            client_name = client.client_name or client.client_id or "MCP Client"
            scopes = params.scopes or ["mcp:full"]
            html = _render_consent(key, client_name, scopes, error="Incorrect password. Try again.")
            return Response(html, media_type="text/html", status_code=401)

        redirect_url = _oauth_provider.approve(key)
        if redirect_url is None:
            return Response(_CONSENT_EXPIRED, media_type="text/html", status_code=400)
        return RedirectResponse(redirect_url, status_code=302)

    return mcp


# ---------------------------------------------------------------------------
# _RegistrationCompatMiddleware
# Antigravity's OAuth client omits "refresh_token" from the grant_types list
# when registering. This ASGI middleware intercepts POST /register and patches
# the request body to add it, preventing a 400 error from the auth provider.
# ---------------------------------------------------------------------------

class _RegistrationCompatMiddleware:
    def __init__(self, app: Any) -> None:
        self._app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if (
            scope.get("type") == "http"
            and scope.get("path") == "/register"
            and scope.get("method") == "POST"
        ):
            chunks: list[bytes] = []
            more = True
            while more:
                msg = await receive()
                chunks.append(msg.get("body", b""))
                more = msg.get("more_body", False)
            body = b"".join(chunks)

            try:
                data = json.loads(body)
                grant_types: list[str] = data.get("grant_types", ["authorization_code", "refresh_token"])
                if (
                    isinstance(grant_types, list)
                    and "authorization_code" in grant_types
                    and "refresh_token" not in grant_types
                ):
                    data["grant_types"] = grant_types + ["refresh_token"]
                    body = json.dumps(data).encode()
                    logger.info("RegistrationCompat: added refresh_token for %r", data.get("client_name"))
            except (json.JSONDecodeError, TypeError):
                pass

            delivered = False

            async def patched_receive() -> Any:
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return {"type": "http.disconnect"}

            await self._app(scope, patched_receive, send)
        else:
            await self._app(scope, receive, send)