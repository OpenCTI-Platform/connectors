from __future__ import annotations

from typing import Any

from ciaops.adapters.opencti_adapter import TIAdapter


def build_ti_adapter(
    *,
    ti_creds_dict: dict[str, Any],
    proxies: dict[str, Any],
    config_obj: Any,
    api_url: Any,
    enabled_collections: list[str],
    collection_mapping_config: Any,
    collections_last_sequence_updates: Any,
) -> TIAdapter:
    """Construct the ciaops ``TIAdapter`` used to pull Group-IB TI collections.

    Credentials, proxy settings, the per-collection mapping and the stored
    incremental ``seqUpdate`` cursors are all handed to ciaops here; pagination,
    auth and retries are the library's responsibility.
    """
    return TIAdapter(
        ti_creds_dict=ti_creds_dict,
        proxies=proxies,
        config_obj=config_obj,
        api_url=api_url,
        enabled_collections=enabled_collections,
        collection_mapping_config=collection_mapping_config,
        collections_last_sequence_updates=collections_last_sequence_updates,
    )
