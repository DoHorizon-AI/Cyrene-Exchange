"""
┌─────────────────────────────────────────────────────────────────────┐
│  📄 audit_api.py                                                     │
│  Module: cyrene_exchange_product.audit_api                          │
│  Role: Read-only Product request usage and audit adapter.             │
│                                                                     │
│  模块职责：通过受控 Exchange credential 读取无内容审计记录。             │
└─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from cyrene_exchange.gateway import RequestPrincipal
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi import Path as ApiPath
from pydantic import BaseModel

from cyrene_exchange_product.domain import RequestAuditRecord
from cyrene_exchange_product.store import ExchangeStore


class RequestAuditList(BaseModel):
    """Bounded list response for the read-only audit surface."""

    items: list[RequestAuditRecord]


def create_audit_app(*, database_path: Path) -> FastAPI:
    """Build a separate read-only audit API without changing control OpenAPI."""

    store = ExchangeStore(database_path)
    app = FastAPI(title="Cyrene Exchange Usage Audit API", version="1.0.0")
    app.state.exchange_store = store

    def principal_for(authorization: str | None) -> RequestPrincipal:
        """Resolve identity only from the persisted controlled credential."""

        if authorization is None or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Authorization must use a Bearer token")
        token = authorization[7:].strip()
        principal = store.resolve_credential(token)
        if principal is None:
            raise HTTPException(status_code=401, detail="invalid credentials")
        return principal

    @app.get("/api/v1/usage-audit/requests", response_model=RequestAuditList)
    def list_audits(
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> RequestAuditList:
        """List only the caller's own workspace and actor records."""

        principal = principal_for(authorization)
        return RequestAuditList(
            items=store.list_request_audits(
                workspace_id=principal.workspace_id,
                actor_id=principal.actor_id,
                limit=limit,
            )
        )

    @app.get(
        "/api/v1/usage-audit/requests/{requestId}",
        response_model=RequestAuditRecord,
    )
    def get_audit(
        request_id: Annotated[str, ApiPath(alias="requestId", min_length=1, max_length=200)],
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    ) -> RequestAuditRecord:
        """Read one audit row when workspace and actor both match."""

        principal = principal_for(authorization)
        record = store.get_request_audit(request_id)
        if (
            record is None
            or record.workspace_id != principal.workspace_id
            or record.actor_id != principal.actor_id
        ):
            raise HTTPException(status_code=404, detail="request audit not found")
        return record

    return app
