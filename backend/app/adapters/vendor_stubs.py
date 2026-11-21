"""Vendor adapter stubs -- INTERFACE DOCUMENTATION ONLY.

These classes document how the platform would integrate with commercial
platforms without requiring (or touching) any proprietary service. Every
method raises :class:`UnsupportedAdapterError`; they exist so that the mapping
between our governance model and each vendor's primitives is explicit:

* Snowflake          -- GRANT/REVOKE on database.schema.object; SHOW GRANTS;
                        MASKING POLICY objects; SNOWFLAKE.DATA_SHARING listings.
* Databricks Unity   -- catalog.schema.table securables; GRANT SELECT ON TABLE;
                        row filters / column masks; Delta Sharing recipients.
* AWS Lake Formation -- LF grants (principal -> resource -> permissions);
                        LF-Tags for classification; cross-account resource links.
* Microsoft Purview  -- scans produce assets + classifications; data-map
                        relationships supply lineage; Purview policy for access.

All are simulated in this POC by :class:`app.adapters.local_adapter.LocalAdapter`.
"""
from __future__ import annotations

from typing import Any


class UnsupportedAdapterError(NotImplementedError):
    pass


def _stub(name: str):  # noqa: ANN001 - factory for documentation stubs
    def _raise(*_a: Any, **_k: Any):
        raise UnsupportedAdapterError(
            f"{name} is an interface-only adapter; run with ADAPTER=local "
            "(the simulated estate). See LIMITATIONS.md.")
    return _raise


class _BaseStub:
    methods = ("list_datasets", "list_columns", "list_principals", "list_grants",
               "list_shares", "list_lineage", "list_baseline_rules",
               "revoke_grant", "add_grant", "mask_column", "restrict_share",
               "upsert_classifications")

    def __init__(self) -> None:
        for mth in self.methods:
            setattr(self, mth, _stub(f"{type(self).__name__}.{mth}"))


class SnowflakeAdapter(_BaseStub):
    """Snowflake account-usage + GRANT model. See module docstring."""


class UnityCatalogAdapter(_BaseStub):
    """Databricks Unity Catalog securables + Delta Sharing. See module docstring."""


class LakeFormationAdapter(_BaseStub):
    """AWS Lake Formation LF-grants + LF-Tags. See module docstring."""


class PurviewAdapter(_BaseStub):
    """Microsoft Purview scans/data map/policies. See module docstring."""


VENDOR_ADAPTERS: dict[str, type[_BaseStub]] = {
    "snowflake": SnowflakeAdapter,
    "unity": UnityCatalogAdapter,
    "lakeformation": LakeFormationAdapter,
    "purview": PurviewAdapter,
}
