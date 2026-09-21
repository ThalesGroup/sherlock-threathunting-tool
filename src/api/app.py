"""FastAPI application factory.

The API is the only surface exposed to the browser. It transmits no credential, no
internal technical identifier, and returns only data already minimized by the
middleware.
"""

from __future__ import annotations

import logging
import secrets as pysecrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.accounts import AccountRepository, SessionManager
from api.auth import DevTokenValidator, SessionTokenValidator, TokenValidator
from api.routes import router
from api.runtime import HuntRuntime, SiemClients, build_clients, build_threat_intel
from middleware.clients.base import configure_outbound_ca
from middleware.config import Settings, get_settings
from middleware.secrets import build_secret_provider
from orchestrator.gateway import GatewayClient
from storage.repository import Database, HuntRepository, SqlAuditSink


def create_app(
    *,
    settings: Settings | None = None,
    runtime: HuntRuntime | None = None,
    repository: HuntRepository | None = None,
    token_validator: TokenValidator | None = None,
    database: Database | None = None,
    allowed_origins: tuple[str, ...] = ("http://localhost:5173",),
) -> FastAPI:
    resolved = settings or get_settings()
    logging.basicConfig(
        level=resolved.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    configure_outbound_ca(resolved.ca_bundle)
    signing_key: str | None = None

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if app.state.database is not None:
            await app.state.database.create_all()
        if app.state.repository is not None:
            await app.state.repository.mark_running_as_interrupted(
                "server restarted during the investigation"
            )
        yield
        if app.state.database is not None:
            await app.state.database.dispose()

    app = FastAPI(
        title="Threat hunting platform",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Dev-User", "X-Dev-Roles"],
    )

    if runtime is None or repository is None:
        database = database or Database(resolved.database_url)
        repository = repository or HuntRepository(database)
        secrets = build_secret_provider(resolved)
        store = secrets.store

        signing_key = store.get("SESSION_SIGNING_KEY")
        if not signing_key:
            signing_key = pysecrets.token_urlsafe(48)
            store.set("SESSION_SIGNING_KEY", signing_key, actor="system")
        clients: SiemClients = build_clients(resolved, secrets)
        gateway = GatewayClient(
            base_url=resolved.gateway_base_url,
            api_key=secrets.get_optional("GATEWAY_API_KEY") or "",
            prompt_caching=resolved.gateway_prompt_caching,
        )
        runtime = HuntRuntime(
            settings=resolved,
            repository=repository,
            audit_sink=SqlAuditSink(database),
            gateway=gateway,
            clients=clients,
            threat_intel=build_threat_intel(resolved, secrets, gateway),
            secrets=secrets,
        )

    sessions = SessionManager(signing_key or pysecrets.token_urlsafe(48))
    accounts = AccountRepository(database) if database is not None else None

    if token_validator is None:
        fallback = (
            DevTokenValidator(resolved.environment) if resolved.environment == "dev" else None
        )
        token_validator = SessionTokenValidator(sessions, fallback=fallback)

    app.state.settings = resolved
    app.state.database = database
    app.state.repository = repository
    app.state.runtime = runtime
    app.state.accounts = accounts
    app.state.sessions = sessions
    app.state.token_validator = token_validator

    app.include_router(router)

    @app.get("/health")
    async def health() -> JSONResponse:
        """Readiness for monitoring: state of the database and connectors, without any
        infrastructure detail. An unreachable database returns 503, which an orchestrator
        can read."""

        database_ok = True
        if app.state.repository is not None:
            try:
                await app.state.repository.list_hunts(limit=1)
            except Exception:
                database_ok = False
        body = {
            "status": "ok" if database_ok else "degraded",
            "database": "ok" if database_ok else "error",
            "siem_sources": len(app.state.runtime.available_sources),
            "threat_intel": app.state.runtime.threat_intel_enabled,
        }
        return JSONResponse(body, status_code=200 if database_ok else 503)

    return app
