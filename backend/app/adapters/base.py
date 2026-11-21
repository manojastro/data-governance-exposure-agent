"""Warehouse/platform adapter interfaces.

The platform is vendor-neutral: any catalog or lakehouse provider is reached
through :class:`WarehouseAdapter`. The concrete vendors (Snowflake, Databricks
Unity Catalog, AWS Lake Formation, Microsoft Purview) are documented stubs --
this POC ships only the ``local`` adapter backed by the simulated estate in the
platform database. See LIMITATIONS.md ("adapter interfaces only").
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class WarehouseAdapter(Protocol):
    """Uniform read/write surface over a data estate's governance metadata."""

    name: str

    def list_datasets(self) -> list[dict[str, Any]]:
        """Return catalog entries: fqn, schema, type (table/view/mart/file),
        store, intended sensitivity level."""
        ...

    def list_columns(self, fqn: str) -> list[dict[str, Any]]:
        """Column names, types, masked flags and sample-value pools."""
        ...

    def list_principals(self) -> list[dict[str, Any]]:
        """Users, groups, roles, service accounts, AI agents."""
        ...

    def list_grants(self) -> list[dict[str, Any]]:
        """Grant rows: principal, asset_kind, asset_ref, privilege,
        granted_on, last_used_at."""
        ...

    def list_shares(self) -> list[dict[str, Any]]:
        """Outbound data shares incl. external/public recipients."""
        ...

    def list_lineage(self) -> list[dict[str, Any]]:
        """DERIVES_FROM edges between assets."""
        ...

    def list_baseline_rules(self) -> list[dict[str, Any]]:
        """Declarative baseline policy (intended grants)."""
        ...

    # -- write path (remediation) ------------------------------------------
    def revoke_grant(self, principal: str, asset_kind: str, asset_ref: str, privilege: str) -> bool: ...
    def add_grant(self, principal: str, asset_kind: str, asset_ref: str, privilege: str) -> bool: ...
    def mask_column(self, fqn: str, column: str) -> bool: ...
    def restrict_share(self, share_name: str, *, recipient: str | None = None,
                       revoke: bool = False) -> bool: ...
    def upsert_classifications(self, fqn: str, tags: list[dict[str, Any]]) -> int: ...
