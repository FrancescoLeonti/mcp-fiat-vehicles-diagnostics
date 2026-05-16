# FIAT Vehicle Diagnostics MCP Server

An industrial vehicle diagnostics platform for Stellantis built with [FastMCP](https://github.com/jlowin/fastmcp). Implements every core MCP primitive — tools, resources, prompts, lifespan, OAuth 2.0, elicitation, progress reporting — applied to a realistic automotive quality-control use case.

---

## What's inside

| MCP Feature | Where |
|---|---|
| **Tools — read** | `list_vehicles`, `get_diagnostic_details`, `get_area_breakdown`, `get_vehicle_status`, `get_fleet_anomalies` |
| **Tools — similarity search** | `find_similar_cases` — cosine similarity on 16-dim normalised parameter vector |
| **Tools — side effects** | `log_intervention`, `confirm_repair_and_promote`, `log_technical_note`, `update_diagnostic_parameters`, `register_sale` |
| **Tools — report generation** | `generate_repair_report` — server-side structured report (MCP sampling alternative commented inside) |
| **Tools — analytics** | `fleet_stats`, `failure_area_heatmap`, `sales_summary`, `revenue_by_model`, `top_customers`, `avg_time_to_pass`, `get_unsold_stock` |
| **Tools — comparison** | `compare_vehicles` — parameter-by-parameter delta with traffic-light status |
| **Resources (static)** | `fiat://config/thresholds`, `fiat://config/benchmarks` |
| **Resources (dynamic list)** | `fiat://vehicles/diagnostic`, `fiat://vehicles/manufactured`, `fiat://notes/` |
| **Resources (template)** | `fiat://notes/{title}` — read a technical note by title |
| **Resource notifications** | `send_resource_updated` on every write operation |
| **Prompts** | `complete_diagnosis`, `report_fleet`, `vehicle_comparison` |
| **Lifespan** | Shared server state initialised once per process |
| **Context injection** | `ctx: Context` in every async tool |
| **Client logging** | `ctx.info()`, `ctx.warning()` — structured log stream visible with `-v` |
| **Progress reporting** | `ctx.report_progress()` in `find_similar_cases` and `generate_repair_report` |
| **MCP elicitation (form)** | `ctx.elicit()` in `confirm_repair_and_promote` — human-in-the-loop for YELLOW promotion |
| **MCP sampling** | Commented block in `generate_repair_report` — active when client supports it |
| **MCP spec OAuth 2.0** | `ConsentOAuthProvider` + `PersistentOAuthProvider` — browser consent page, PKCE |
| **Custom routes** | `GET /health`, `GET /auth-status`, `GET+POST /oauth/consent` |
| **StreamableHTTP stateful** | `stateless_http=False` — persistent SSE channel for server-initiated notifications |
| **Middleware** | `_RegistrationCompatMiddleware` — Antigravity OAuth compatibility patch |

---

## Project structure

```
mcp_vehicle_diagnostics/
├── Diagnostic/                     # Vehicles currently in diagnostic (FAIL)
│   └── {Model} - {Serial}/
│       └── diagnostic_report.json
├── Manufactured Vehicles/          # Vehicles that passed diagnostic (PASS)
│   └── {Model} - {Serial}/
│       ├── diagnostic_report.json
│       └── sales_record.json
├── Intervention History/           # Resolved cases for similarity search
│   └── {Serial}_history.json
├── Technical Notes/                # Persistent technician notes
│   └── {title}.json
├── credentials/                    # OAuth state persistence
│   └── oauth_state.json
├── mcp_fiat_vehicles/
│   ├── __init__.py
│   ├── __main__.py                 # CLI entry point (Click + uvicorn)
│   ├── server.py                   # All MCP primitives — single file
│   └── templates/
│       ├── consent.html            # OAuth consent page
│       └── consent_expired.html    # Shown when auth key expires
├── pyproject.toml
├── .env.example
└── .mcp.json                       # Antigravity client configuration
```

### Vehicle data format

Every vehicle is a named folder (`Model - SerialNumber`) containing JSON files. Serial number format: 3 uppercase letters + 3 digits + 2 uppercase letters (e.g. `FKZ125HZ`).

**`diagnostic_report.json`**
```json
{
  "vin": "ZFA500FAIL01",
  "model": "500",
  "serial_number": "FKZ125HZ",
  "status": "FAIL",
  "collaudo_date": "2024-09-15",
  "technician": "Russo A.",
  "technical_parameters": {
    "powertrain": { "engine_compression_bar": 9.2, "idle_rpm": 920, "throttle_response_ms": 210, "exhaust_co_ppm": 780 },
    "electrical": { "battery_voltage_v": 11.8, "battery_soh_pct": 71, "alternator_output_v": 13.1, "can_bus_error_count": 3 },
    "chassis":    { "brake_pressure_bar": 87, "brake_balance_pct": 58.0, "steering_play_deg": 7.2, "suspension_drop_mm": 11.0 },
    "adas":       { "headlight_alignment_mrad": 18.0, "abs_response_ms": 95, "ecu_fault_codes": 2, "adas_calibration_score": 81 }
  },
  "diagnostic_notes": "Multiple anomalies detected.",
  "intervention_history": []
}
```

**`sales_record.json`** (only in Manufactured Vehicles)
```json
{
  "serial_number": "FKZ125HZ",
  "sold": true,
  "sale_date": "2024-10-03",
  "customer_name": "Mario Rossi",
  "customer_id": "CUST-0042",
  "sale_price_eur": 18500,
  "dealer": "Fiat Roma Nord",
  "warranty_years": 3
}
```

---

## Technical parameters and thresholds

16 parameters across 4 functional areas. Each is classified GREEN / YELLOW / RED:

| Area | Parameter | GREEN | YELLOW | RED |
|---|---|---|---|---|
| **Powertrain** | engine_compression_bar | ≥ 12.0 | 10.0 – 11.99 | < 10.0 |
| | idle_rpm | 750 – 850 | 700 – 749 / 851 – 950 | < 700 / > 950 |
| | throttle_response_ms | ≤ 150 | 151 – 200 | > 200 |
| | exhaust_co_ppm | ≤ 499 | 500 – 700 | > 700 |
| **Electrical** | battery_voltage_v | ≥ 12.4 | 12.0 – 12.39 | < 12.0 |
| | battery_soh_pct | ≥ 85 | 70 – 84 | < 70 |
| | alternator_output_v | 13.8 – 14.4 | 13.4 – 13.79 | < 13.4 |
| | can_bus_error_count | 0 | 1 – 2 | ≥ 3 |
| **Chassis** | brake_pressure_bar | ≥ 100 | 85 – 99 | < 85 |
| | brake_balance_pct | 60 – 65 | 55 – 70 | < 55 / > 70 |
| | steering_play_deg | < 5 | 5 – 8 | > 8 |
| | suspension_drop_mm | < 8 | 8 – 12 | > 12 |
| **ADAS** | headlight_alignment_mrad | < 10 | 10 – 15 | > 15 |
| | abs_response_ms | < 80 | 80 – 100 | > 100 |
| | ecu_fault_codes | 0 | 1 | ≥ 2 |
| | adas_calibration_score | ≥ 95 | 85 – 94 | < 85 |

---

## Similarity search

`find_similar_cases` compares a FAIL vehicle against all resolved cases in `Intervention History/` using **cosine similarity** on a normalised 16-dimensional parameter vector.

Steps:
1. Flatten the 16 parameters into an ordered vector
2. Min-max normalise each value to `[0, 1]` using `NORM_RANGES`
3. Compute cosine similarity against every history entry
4. Return the top-K matches with their corrective actions

A score ≥ 0.85 suggests a known failure pattern — the same actions likely apply. Lower scores indicate a novel case requiring manual analysis.

---

## Quick start

```bash
# 1. Install dependencies
uv sync

# 2. Configure environment
cp .env.example .env
# Edit .env and set MCP_AUTH_TOKEN to your chosen password

# 3. Start the server
uv run mcp-server -v

# 4. Verify
curl http://localhost:8001/health
# → {"status": "ok", "version": "5.0.0", "auth_enabled": true}
```

---

## Configuration

```bash
cp .env.example .env
```

| Variable | Default | Purpose |
|---|---|---|
| `MCP_AUTH_TOKEN` | *(unset)* | Consent-page password. Set to enable OAuth 2.0 auth. Unset = open server (local dev only). |
| `MCP_PORT` | `8001` | HTTP port |
| `MCP_OAUTH_STATE_PATH` | `credentials/oauth_state.json` | OAuth token persistence path |

**Security note:** always set `MCP_AUTH_TOKEN` before connecting external clients. Without it, the server accepts any connection without authentication.

---

## Running the server

```bash
# Default (auth enabled if MCP_AUTH_TOKEN is set)
uv run mcp-server

# Verbose logging — INFO level, shows ctx.info() output
uv run mcp-server -v

# Debug logging — full FastMCP internals
uv run mcp-server -vv

# Custom port
uv run mcp-server --port 9000

# Custom host (bind to localhost only)
uv run mcp-server --host 127.0.0.1
```

---

## Connecting with Antigravity

1. Start the server: `uv run mcp-server -v`
2. Open Antigravity → `F1` → **Manage MCP Servers** → **View raw config**
3. Paste the contents of `.mcp.json`:
```json
{
  "mcpServers": {
    "mcp-fiat-diagnostics": {
      "url": "http://localhost:8001/mcp/"
    }
  }
}
```
4. Click **Refresh** — the browser opens the OAuth consent page
5. Enter your `MCP_AUTH_TOKEN` password and click **Approve**
6. All 20 tools are now available in the Antigravity chat

---

## Tool reference

### Diagnostic tools

| Tool | Description |
|---|---|
| `list_vehicles` | List vehicles by category: `diagnostic` (FAIL) or `manufactured` (PASS) |
| `get_diagnostic_details` | Full diagnostic report with all 16 technical parameters |
| `get_area_breakdown` | Traffic-light analysis by functional area (GREEN / YELLOW / RED) |
| `get_vehicle_status` | Concise vehicle summary: model, status, date, technician |
| `get_fleet_anomalies` | All diagnostic vehicles sorted by severity (RED count desc) |
| `find_similar_cases` | Top-K similar historical cases via cosine similarity |
| `compare_vehicles` | Parameter-by-parameter delta between two vehicles |

### Intervention tools

| Tool | Description |
|---|---|
| `log_intervention` | Record a corrective action. Blocked if target area is GREEN |
| `update_diagnostic_parameters` | Update measured values after physical repair and recompute traffic light |
| `confirm_repair_and_promote` | Promote FAIL → PASS. Blocked on RED; elicitation confirmation on YELLOW; immediate on all GREEN |
| `generate_repair_report` | Structured formal report (server-side). MCP sampling alternative commented inside |
| `log_technical_note` | Save a persistent technician note to `Technical Notes/` |

### Analytics tools

| Tool | Description |
|---|---|
| `fleet_stats` | Total vehicles, PASS rate, avg days to pass, most common fail area |
| `failure_area_heatmap` | Failure distribution across the 4 functional areas |
| `sales_summary` | Total sold, unsold, revenue, average price |
| `revenue_by_model` | Revenue breakdown by vehicle model, sorted descending |
| `top_customers` | Top-K customers by purchases and total spend |
| `avg_time_to_pass` | Average days from collaudo to PASS, optionally filtered by model |
| `get_unsold_stock` | Retrieves a detailed list of vehicles that passed diagnostics but remain unsold |

### Prompts

| Prompt | Description |
|---|---|
| `complete_diagnosis(serial)` | Full diagnostic workflow: details → breakdown → similarity → recommendation |
| `report_fleet()` | Executive fleet report: stats → heatmap → sales → revenue → customers |
| `vehicle_comparison(serial_a, serial_b)` | Comparative analysis of two vehicles |

---

## MCP primitives demonstrated

### Resources and notifications
Resources expose live server data as MCP-indexed documents. When a tool modifies data (e.g. promoting a vehicle), it calls `ctx.session.send_resource_updated()` so connected clients can refresh their cache immediately.

```python
await ctx.session.send_resource_updated("fiat://vehicles/diagnostic")
await ctx.session.send_resource_updated("fiat://vehicles/manufactured")
```

### Elicitation
`confirm_repair_and_promote` uses `ctx.elicit()` to implement a human-in-the-loop gate when a vehicle has YELLOW parameters. The server pauses, shows the anomalies, and waits for explicit user confirmation before proceeding.

```python
result = await ctx.elicit(message=warning_msg, schema=_YellowConfirm)
if result.action != "accept" or not result.data.conferma:
    return "Promotion cancelled."
```

### Progress reporting
Long-running operations emit progress notifications so the client can display a progress indicator.

```python
for i, entry in enumerate(history):
    await ctx.report_progress(progress=i + 1, total=len(history))
    # ... similarity computation
```

### MCP sampling (commented — Gemini does not support it yet)
`generate_repair_report` contains a commented implementation using `ctx.sample()` that delegates report writing to the host LLM. The active implementation is server-side for full Antigravity compatibility. To switch, uncomment the sampling block and comment out the server-side section. Requires a sampling-capable client (e.g. Claude Code ≥ 2.1.76).

### OAuth 2.0
When `MCP_AUTH_TOKEN` is set, the server runs full MCP spec OAuth 2.0 via `ConsentOAuthProvider` + `PersistentOAuthProvider`. Clients discover auth endpoints automatically via `GET /.well-known/oauth-authorization-server`. The browser consent page at `/oauth/consent` accepts the password and issues tokens that persist across sessions in `credentials/oauth_state.json`.

---

## Custom HTTP routes

| Route | Method | Description |
|---|---|---|
| `/health` | GET | Server status, version, auth enabled flag |
| `/auth-status` | GET | Whether OAuth is enabled |
| `/oauth/consent` | GET | HTML consent page (shown on first client connection) |
| `/oauth/consent` | POST | Password verification and token issuance |

---

## Synthetic dataset

The project ships with pre-generated synthetic data:

- **20 PASS vehicles** in `Manufactured Vehicles/` — 80% sold, diverse models and customers
- **8 FAIL vehicles** in `Diagnostic/` — each with 1–2 degraded functional areas
- **2 special test vehicles** in `Diagnostic/`:
  - `GRN001AA` (500) — all areas GREEN, ready for immediate promotion
  - `YLW002BB` (600) — chassis YELLOW only, triggers elicitation on promotion
- **12 intervention history entries** in `Intervention History/` — pre-computed similarity vectors for immediate use

---

## Development notes

The entire server is a single file (`server.py`). All MCP primitives are registered inside `build_app()` — a factory function that returns a configured `FastMCP` instance. This pattern allows multiple server instances (e.g. for testing) and keeps all registrations co-located.

All utility functions are module-level and prefixed with `_` (private by convention). Pydantic models are defined at module level and reused across tools and resources.

---

## Testing guide

Step-by-step guide to verify the full functionality of the server. Follow the phases in order — each phase builds on the previous one. All commands are written in natural language as you would type them in Antigravity.

> **Before you start:** start the server with `uv run mcp-server -v`, connect Antigravity, complete the OAuth consent page with your password. You should see **20 tools** loaded.

---

### Phase 0 — Authentication

- Connect Antigravity and click **Refresh** → the browser opens the OAuth consent page
- Enter a **wrong password** and click Approve → the page must show "Incorrect password. Try again." without redirecting
- Enter the **correct password** (value of `MCP_AUTH_TOKEN` in your `.env`) and click Approve → Antigravity shows 20/20 tools loaded. Check the server console log to verify that the lifespan context manager initialized the data directories.

---

### Phase 1 — Static and Dynamic Resources

- `Show me the diagnostic reference values`-> Calls `fiat://config/thresholds`.
- `What are the acceptance thresholds for all parameters?`-> Calls `fiat://config/benchmarks`.
- `How many vehicles are currently in diagnostic?`-> Calls `fiat://vehicles/diagnostic`.
- `Show me the vehicles that have already passed diagnostic`-> Calls `fiat://vehicles/manufactured`.
- `Do you have any saved technical notes?` -> Calls `fiat://notes/`

---

### Phase 2 — Vehicle listing and priority

- `List all the vehicles currently being worked on`-> Invokes `list_vehicles(category="diagnostic")`.
- `Which vehicles in diagnostic have the most severe problems?`-> Invokes `get_fleet_anomalies()`, returning data sorted by RED count descending.

---

### Phase 3 — Vehicle detail and analysis

- `Give me all information about vehicle NVP036RB`-> Invokes `get_diagnostic_details(serial_number="NVP036RB")`.
- `Where does vehicle NVP036RB have issues?`-> Invokes `get_area_breakdown(serial_number="NVP036RB")`.
- `In short, what is the status of vehicle NVP036RB?`-> Invokes `get_vehicle_status(serial_number="NVP036RB")`.

---

### Phase 4 — Similarity search

- `Are there similar cases to vehicle NVP036RB in history?`-> Invokes `find_similar_cases(serial_number="NVP036RB")`.
Look at the Antigravity UI or console logs during execution; you should briefly see a progress status bar matching the incremental updates of `ctx.report_progress()`.
---

### Phase 5 — Vehicle comparison

- `Compare vehicles NVP036RB and BYZ746SX`-> Invokes `compare_vehicles(serial_a="NVP036RB", serial_b="BYZ746SX")`. Verify that the tool displays parameter-by-parameter variance.

---

### Phase 6 — Intervention blocked on GREEN area

- `Analyze the areas of vehicle NVP036RB`-> Note down an area that evaluates to GREEN.
- `Log an intervention on the [GREEN area name] area of vehicle NVP036RB` -> Invokes `log_intervention`. It must return a `ToolError` stating that the area is already GREEN and no corrective action is allowed. Check the terminal console; a `ctx.warning()` log entry should be generated.
---

### Phase 7 — Intervention on anomalous area

Use the RED or YELLOW area identified in Phase 3.

- `Record that I worked on the electrical area of vehicle NVP036RB and replaced the battery` -> Invokes `log_intervention(serial_number="NVP036RB", area="electrical", description="battery replaced")`. Check that `NVP036RB_history.json` is created in `Intervention History/`. The client should receive a resource update event for related dynamic endpoints.

---

### Phase 8 — Update parameters after repair

- `After replacing the battery on vehicle NVP036RB, the voltage is now 12.6V and SOH is 92%, update the data`-> Invokes `update_diagnostic_parameters(serial_number="NVP036RB", subsystem="electrical", updates={"battery_voltage_v": 12.6, "battery_soh_pct": 92})`.
- `Where does vehicle NVP036RB have issues now?` -> Execute again `get_area_breakdown` to check that the electrical area has turned GREEN.

---

### Phase 9 — Technical note

- `Save a note on NVP036RB: battery replaced` -> Invokes `log_technical_note(title="NVP036RB_battery", content="Battery swapped during QC inspection")`. Verify a file appears in `Technical Notes/`.
- `Do you have any saved technical notes?` > Queries `fiat://notes/`, must list `NVP036RB_battery`.
- `Show me the contents of the note NVP036RB_battery`-> Resolves the template resource `fiat://notes/NVP036RB_battery`.
---

### Phase 10 — Promotion blocked by RED

Take a vehicle that still has at least one RED area after the interventions.

- `Promote vehicle DWJ093DO to PASS` > Invokes `confirm_repair_and_promote`. It must return a BLOCKED error notification listing the explicit out-of-range RED properties and suggesting further `log_intervention`. No files must be moved.
---

### Phase 11 — Promotion with YELLOW — elicitation (vehicle YLW002BB)

`YLW002BB` has chassis YELLOW and all other areas GREEN — designed specifically for this test.

- `Analyze the areas of vehicle YLW002BB`
- `Promote vehicle YLW002BB` Triggers `confirm_repair_and_promote`. An elicitation modal/popup form must overlay in Antigravity showcasing the specific chassis anomalies and prompting for boolean confirmation.
- Click **No / false** → "Promotion cancelled". Verify the folder is still in `Diagnostic/`
- `Promote vehicle YLW002BB` again → popup again
- Click **Yes / true** → promoted with message. Verify the folder has moved into `Manufactured Vehicles/`.

---

### Phase 12 — Immediate promotion on all GREEN (vehicle GRN001AA)

`GRN001AA` has all 4 areas GREEN — designed specifically for this test.

- `Analyze the areas of vehicle GRN001AA` 
- `Promote vehicle GRN001AA`-> Invokes `confirm_repair_and_promote`. It must bypass all elicitation or blocking flows, returning immediate validation and moving the folder to `Manufactured Vehicles/`.

---

### Phase 13 — Register a sale

- `How many vehicles are still unsold?`
- `Register the sale of vehicle GRN001AA to Marco Ferrari, customer CUST-005, price 21000 euros, dealer Fiat Milano Centro`-> Invokes `register_sale(serial_number="GRN001AA", customer_name="Marco Ferrari", customer_id="CUST-005", sale_price_eur=21000, dealer="Fiat Milano Centro")`. Verify `sales_record.json` is safely stored in its directory.
- `Try to sell vehicle GRN001AA again` -> Re-running must return an explicit tracking error confirming the unit was already sold to Marco Ferrari on the current date.
---

### Phase 14 — Unsold stock report

- `Which vehicles have been sitting unsold for more than 30 days?`-> Invokes `get_unsold_stock(min_days_unsold=30)`.
- `Show me the unsold vehicles older than 365 days`-> Invokes `get_unsold_stock(min_days_unsold=365)`.
---

### Phase 15 — Statistics

- `How is production performing?` → `fleet_stats()`
- `Which functional area causes the most issues?` → `failure_area_heatmap()`
- `What is our total revenue?` → `sales_summary()`
- `How much revenue does each model generate?` → `revenue_by_model()`
- `Who are our top customers?` → `top_customers()`
- `What is the average time required for a vehicle to clear diagnostics??` → `avg_time_to_pass()`

---

### Phase 16 — Repair report

- `Generate the repair report for vehicle NVP036RB`-> Invokes `generate_repair_report(serial_number="NVP036RB")`. 
---

### Phase 17 — HTTP routes

Open the browser directly (no Antigravity needed):

- `http://localhost:8001/health` → `{"status": "ok", "version": "5.0.0", "auth_enabled": true}`
- `http://localhost:8001/auth-status` → `{"mcp_auth_enabled": true}`

---

### Phase 18 — Prompts

Verifies: `complete_diagnosis`, `report_fleet`, `vehicle_comparison` (MCP Prompts).

- `Execute a complete diagnosis of vehicle AYU186LD`> Loads prompt `complete_diagnosis(serial="AYU186LD")`, chaining details, traffic-light breakdown, and similarity inquiries automatically.
- `Give me a complete report on the fleet and sales`> Loads prompt `report_fleet()`, instructing the LLM to aggregate all telemetry stats.
- `Compare vehicles SVC573IC and UKE416LQ and tell me which one is in worse condition`-> Loads prompt `vehicle_comparison(serial_a="SVC573IC", serial_b="UKE416LQ")`.
