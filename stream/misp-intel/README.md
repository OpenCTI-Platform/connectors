#### Known limitations

When a container's marking or `report_types` changes (e.g. TLP RED → GREEN) and OpenCTI sends a corresponding `update` event, the connector reconciles the now-stale MISP event tag: it adds the new tag and actively removes the old one via the MISP API.

**Removal is driven by persisted connector state, not by guessing from a tag-name prefix.** Every time the connector creates or updates a MISP event, it records — via `helper.get_state()`/`helper.set_state()`, keyed by MISP event UUID — exactly which event-level tags it itself just added. On the next `update` for that same event, only tags previously recorded in that state are eligible for automatic removal; any tag not recorded there (most commonly one added manually by a MISP analyst, or one added by another tool) is always left untouched, no matter how similar its name looks to a connector-managed tag.

This means:

- **Any allow-listed marking type is correctly reconciled**, not just `TLP`/`PAP`. Even a custom `definition_type` added to `MISP_MARKING_TYPES_TO_CONVERT` (e.g. `CLASSIFICATION`) whose resulting tag does not follow a predictable `{definition_type.lower()}:` prefix is cleaned up correctly once stale, because the connector tracks the actual tag name it added — not an assumed prefix.
- **A manually-added tag is never deleted**, even if it happens to share a namespace with connector-managed tags (e.g. an analyst manually tagging an event `tlp:red`). Since that tag was never recorded as connector-added in state, it is never a candidate for removal.
- **One transitional edge case**: for a MISP event that was synced by a connector version older than this state-tracking feature, there is no recorded state yet for that event. The *first* `update` after upgrading will not clean up any pre-existing stale tag on that event (it simply has nothing to compare against), but will start recording state from that point on — so reconciliation behaves correctly from the second sync onward. This is intentional: it is strictly safer to under-clean once on upgrade than to guess and risk deleting a manually-added tag.

In short: **every event-level tag the connector adds is tracked per-event in connector state, and reconciliation on update only ever removes a tag the connector itself previously added — regardless of its name/prefix, and never a tag it didn't.**
