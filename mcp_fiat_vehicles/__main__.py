"""
Entry point — FIAT Vehicle Diagnostics MCP Server v5
"""
from __future__ import annotations

import logging
import os
import click

@click.command()
@click.option("--port", "-p", type=int, default=None)
@click.option("--host", "-H", type=str, default="0.0.0.0")
@click.option("-v", "--verbose", count=True)
def main(port: int | None, host: str, verbose: int) -> None:
    """Start the FIAT Vehicle Diagnostics MCP server."""
    level = {0: logging.WARNING, 1: logging.INFO}.get(verbose, logging.DEBUG)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")

    from dotenv import load_dotenv
    load_dotenv()

    import uvicorn
    from mcp_fiat_vehicles.server import _MCP_AUTH_ENABLED, _RegistrationCompatMiddleware, build_app
    from starlette.middleware.cors import CORSMiddleware

    effective_port = port or int(os.getenv("MCP_PORT", "8001"))

    mcp = build_app()
    app = mcp.http_app(path="/mcp", stateless_http=False)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://antigravity.google"],
        allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "mcp-session-id"],
        expose_headers=["mcp-session-id"],
    )
    if _MCP_AUTH_ENABLED:
        app = _RegistrationCompatMiddleware(app)
        click.echo("OAuth 2.0 enabled — first connection opens /oauth/consent")
    else:
        click.echo("WARNING: MCP_AUTH_TOKEN not set — server is open")

    click.echo(f"FIAT Diagnostics Server → http://{host}:{effective_port}/mcp")
    uvicorn.run(app, host=host, port=effective_port, log_level=None)

if __name__ == "__main__":
    main()