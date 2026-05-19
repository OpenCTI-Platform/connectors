"""OpenCTI Mattermost external-import connector.

Pulls messages, attachments, authors and thread relationships from one or
more Mattermost channels and renders them as STIX 2.1 objects. Each message
becomes a ``media-content`` observable linked to a ``channel`` SDO; thread
replies become ``related-to`` relationships toward the root post.
"""

import base64
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import stix2
from lib.external_import import ExternalImportConnector
from mattermostdriver import Driver
from pycti import Channel as PyctiChannel
from pycti import (
    CustomObjectChannel,
    CustomObservableMediaContent,
)
from pycti import Identity as PyctiIdentity
from pycti import MarkingDefinition as PyctiMarkingDefinition
from pycti import StixCoreRelationship as PyctiSCR
from pycti import (
    get_config_variable,
)


def _make_tlp_marking(definition: str) -> stix2.MarkingDefinition:
    """Return a ``stix2.MarkingDefinition`` for an OpenCTI TLP value.

    Used for ``TLP:CLEAR`` (which OpenCTI represents with a dedicated
    ``x_opencti_definition`` value even though the canonical
    marking-definition id is shared with ``TLP:WHITE``) and for
    ``TLP:AMBER+STRICT`` (an OpenCTI-specific marking that ``stix2`` does
    not expose as a built-in constant). Building a real
    ``stix2.MarkingDefinition`` lets us include the marking object in
    every bundle, which is what the rest of the OpenCTI connector
    ecosystem does for these two values.
    """
    return stix2.MarkingDefinition(
        id=PyctiMarkingDefinition.generate_id("TLP", definition),
        definition_type="statement",
        definition={"statement": "custom"},
        allow_custom=True,
        x_opencti_definition_type="TLP",
        x_opencti_definition=definition,
    )


# ``stix2`` exposes built-in constants for TLP_WHITE / GREEN / AMBER / RED.
# ``TLP:CLEAR`` (the modern alias of ``TLP:WHITE`` in OpenCTI) and
# ``TLP:AMBER+STRICT`` are not built-in stix2 constants — we materialise
# them as proper ``stix2.MarkingDefinition`` objects so they can be added
# to every bundle and the platform can register them by name.
_TLP_MAP: Dict[str, stix2.MarkingDefinition] = {
    "CLEAR": _make_tlp_marking("TLP:CLEAR"),
    "WHITE": stix2.TLP_WHITE,
    "GREEN": stix2.TLP_GREEN,
    "AMBER": stix2.TLP_AMBER,
    "AMBER_STRICT": _make_tlp_marking("TLP:AMBER+STRICT"),
    "AMBER+STRICT": _make_tlp_marking("TLP:AMBER+STRICT"),
    "RED": stix2.TLP_RED,
}


class MattermostConnector(ExternalImportConnector):
    """Mattermost-specific external-import connector."""

    def __init__(self) -> None:
        super().__init__()

        config = self._load_config()
        self.mattermost_domain: str = self._require_string(
            config, "MATTERMOST_DOMAIN", ["mattermost", "domain"]
        )
        self.mattermost_token: str = self._require_string(
            config, "MATTERMOST_TOKEN", ["mattermost", "token"]
        )
        raw_channel_ids = self._require_string(
            config, "MATTERMOST_CHANNEL_IDS", ["mattermost", "channel_ids"]
        )
        self.mattermost_channel_ids: List[str] = [
            channel_id.strip()
            for channel_id in raw_channel_ids.split(",")
            if channel_id.strip()
        ]
        if not self.mattermost_channel_ids:
            raise ValueError(
                "MATTERMOST_CHANNEL_IDS must contain at least one channel id."
            )

        self.mattermost_port: int = int(
            get_config_variable(
                "MATTERMOST_PORT",
                ["mattermost", "port"],
                config,
                isNumber=True,
                default=8065,
            )
        )
        self.mattermost_protocol: str = (
            get_config_variable(
                "MATTERMOST_PROTOCOL",
                ["mattermost", "protocol"],
                config,
                default="https",
            )
            or "https"
        )
        self.mattermost_basepath: str = (
            get_config_variable(
                "MATTERMOST_BASEPATH",
                ["mattermost", "basepath"],
                config,
                default="/api/v4",
            )
            or "/api/v4"
        )
        self.mattermost_start_timestamp: int = int(
            get_config_variable(
                "MATTERMOST_START_TIMESTAMP",
                ["mattermost", "start_timestamp"],
                config,
                isNumber=True,
                default=0,
            )
        )
        tlp_name = (
            get_config_variable(
                "MATTERMOST_TLP",
                ["mattermost", "tlp"],
                config,
                default="AMBER",
            )
            or "AMBER"
        )
        self.mattermost_marking: stix2.MarkingDefinition = self._resolve_tlp(tlp_name)
        self.mattermost_marking_id: str = self.mattermost_marking.id
        self.mattermost_verify: bool = self._coerce_bool(
            get_config_variable(
                "MATTERMOST_VERIFY",
                ["mattermost", "verify"],
                config,
                default=True,
            ),
            default=True,
        )
        self.mattermost_timeout: int = int(
            get_config_variable(
                "MATTERMOST_TIMEOUT",
                ["mattermost", "timeout"],
                config,
                isNumber=True,
                default=30,
            )
        )
        raw_request_timeout = get_config_variable(
            "MATTERMOST_REQUEST_TIMEOUT",
            ["mattermost", "request_timeout"],
            config,
            default=None,
        )
        self.mattermost_request_timeout: Optional[int] = (
            int(raw_request_timeout)
            if raw_request_timeout not in (None, "", "None")
            else None
        )
        self.mattermost_keepalive: bool = self._coerce_bool(
            get_config_variable(
                "MATTERMOST_KEEPALIVE",
                ["mattermost", "keepalive"],
                config,
                default=False,
            ),
            default=False,
        )
        self.mattermost_keepalive_delay: int = int(
            get_config_variable(
                "MATTERMOST_KEEPALIVE_DELAY",
                ["mattermost", "keepalive_delay"],
                config,
                isNumber=True,
                default=5,
            )
        )
        self.mattermost_debug: bool = self._coerce_bool(
            get_config_variable(
                "MATTERMOST_DEBUG",
                ["mattermost", "debug"],
                config,
                default=False,
            ),
            default=False,
        )

        self.driver = Driver(
            {
                "url": self.mattermost_domain,
                "token": self.mattermost_token,
                "scheme": self.mattermost_protocol,
                "port": self.mattermost_port,
                "basepath": self.mattermost_basepath,
                "verify": self.mattermost_verify,
                "timeout": self.mattermost_timeout,
                "request_timeout": self.mattermost_request_timeout,
                "keepalive": self.mattermost_keepalive,
                "keepalive_delay": self.mattermost_keepalive_delay,
                "websocket_kw_args": None,
                "debug": self.mattermost_debug,
            }
        )
        self.driver.login()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _require_string(config: Dict[str, Any], env_name: str, path: List[str]) -> str:
        value = get_config_variable(env_name, path, config, default=None)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{env_name} is required and must be a non-empty string.")
        return value.strip()

    @staticmethod
    def _resolve_tlp(name: str) -> stix2.MarkingDefinition:
        """Return the ``stix2.MarkingDefinition`` matching ``name``.

        ``AMBER+STRICT`` is accepted both with the canonical ``+`` and
        with a ``_`` for environment-variable friendliness; both resolve
        to the same OpenCTI marking-definition id.
        """
        normalised = (name or "").strip().upper().replace(" ", "_")
        try:
            return _TLP_MAP[normalised]
        except KeyError as exc:
            # Derive the valid-value list from ``_TLP_MAP`` so the
            # error message stays in sync with the code if aliases
            # are added later (e.g. ``WHITE``, ``AMBER+STRICT``).
            valid = ", ".join(sorted(_TLP_MAP))
            raise ValueError(
                f"Unsupported MATTERMOST_TLP value '{name}'. "
                f"Expected one of {valid}."
            ) from exc

    @staticmethod
    def _list_filter(field: str, value: str) -> Dict[str, Any]:
        """Build a filter compatible with the modern OpenCTI API."""
        return {
            "mode": "and",
            "filters": [
                {
                    "key": field,
                    "values": [value],
                    "operator": "eq",
                    "mode": "and",
                }
            ],
            "filterGroups": [],
        }

    # ------------------------------------------------------------------
    # Per-run caches & deterministic ids
    # ------------------------------------------------------------------
    def _reset_run_caches(self) -> None:
        """Drop the per-run caches before starting a new collection cycle."""
        # ``user_id -> email`` so we hit Mattermost's ``users.get_user``
        # at most once per author per run, even on busy channels.
        self._user_email_cache: Dict[str, str] = {}
        # ``email -> author standard_id`` so we hit OpenCTI's
        # ``identity.list`` / append a newly-built ``stix2.Identity`` to
        # the bundle at most once per author per run, even when many
        # posts share the same author. The cached id is the
        # ``standard_id`` returned by ``identity.list`` for existing
        # authors and the ``stix2.Identity.id`` for newly-created ones,
        # which is what ``CustomObservableMediaContent.created_by_ref``
        # expects.
        self._author_id_cache: Dict[str, str] = {}
        # ``post_url -> set(filename)`` so we hit OpenCTI's
        # ``stix_cyber_observable.list`` / ``.read`` at most once
        # per post-URL per run, regardless of how many attachments
        # the post carries.
        self._existing_files_cache: Dict[str, set] = {}

    def _author_email(self, user_id: str) -> str:
        """Return the email of ``user_id``, caching the answer for this run."""
        cached = self._user_email_cache.get(user_id)
        if cached is not None:
            return cached
        email = self.driver.users.get_user(user_id)["email"]
        self._user_email_cache[user_id] = email
        return email

    def _ensure_author(self, email: str, bundle: List[Any]) -> str:
        """Return the author id for ``email``, caching the answer for this run.

        Hits OpenCTI's ``identity.list`` at most once per distinct author
        per cycle: on the first occurrence the existing identity is
        re-used (its ``standard_id`` is cached) or a new
        ``stix2.Identity`` is created and appended to ``bundle`` (its
        ``id`` is cached). Subsequent posts by the same author skip both
        the API lookup and the bundle append, so a channel with N posts
        from K distinct authors triggers exactly K identity lookups
        instead of N.
        """
        cached = self._author_id_cache.get(email)
        if cached is not None:
            return cached
        identities = self.helper.api.identity.list(
            filters=self._list_filter("name", email)
        )
        if identities:
            author_id = identities[0]["standard_id"]
        else:
            author = stix2.Identity(
                id=PyctiIdentity.generate_id(email, "individual"),
                name=email,
                identity_class="individual",
                description="Mattermost author",
                object_marking_refs=[self.mattermost_marking_id],
            )
            bundle.append(author)
            author_id = author["id"]
        self._author_id_cache[email] = author_id
        return author_id

    @staticmethod
    def _namespaced_channel_name(team_name: str, channel_name: str) -> str:
        """Return the OpenCTI Channel name used to deduplicate ``channel_name``.

        Mattermost channel names are unique within a team, not across the
        whole instance, so we prefix every channel with its team name to
        guarantee that two distinct Mattermost channels never collapse
        into the same OpenCTI Channel SDO (e.g. ``team-a/town-square`` vs
        ``team-b/town-square``).
        """
        return f"{team_name}/{channel_name}"

    @staticmethod
    def _media_content_id(post_url: str) -> str:
        """Return the deterministic STIX id of the media-content for ``post_url``.

        ``CustomObservableMediaContent`` auto-generates the id from
        ``url`` so a stub instance is enough to compute it without
        hitting the platform.
        """
        stub = CustomObservableMediaContent(url=post_url, allow_custom=True)
        return stub["id"]

    # ------------------------------------------------------------------
    # Collection
    # ------------------------------------------------------------------
    def _collect_channel_posts(self, channel_id: str, start_time: int) -> List[Any]:
        """Return STIX objects extracted from a Mattermost channel."""
        self.helper.log_debug(
            f"Collect channel posts starting from epoch: {start_time}"
        )
        bundle: List[Any] = []

        channel = self.driver.channels.get_channel(channel_id)
        channel_name = channel["name"]
        team = self.driver.teams.get_team(channel["team_id"])
        team_name = team["name"]
        # Mattermost channel names are unique within a team, not across
        # the whole instance — multiple teams can each have their own
        # ``town-square``. We namespace the OpenCTI Channel SDO by
        # ``<team_name>/<channel_name>`` so distinct Mattermost channels
        # never collide on the same OpenCTI Channel.
        namespaced_channel_name = self._namespaced_channel_name(team_name, channel_name)
        self.helper.log_debug(f"Channel {channel_id} ({namespaced_channel_name})")

        posts = self.driver.posts.get_posts_for_channel(
            channel_id, params={"since": str(start_time * 1000)}
        )
        self.helper.log_debug(f"Fetched {len(posts['order'])} posts")

        description = (
            "Purpose: "
            + (channel.get("purpose") or "")
            + "\n\nHeader: "
            + (channel.get("header") or "")
        )

        channel_target_ref = self._ensure_channel(
            namespaced_channel_name, description, bundle
        )
        base_url = (
            f"{self.mattermost_protocol}://{self.mattermost_domain}"
            f":{self.mattermost_port}/"
        )

        link: Dict[str, List[str]] = {}
        included_posts: List[str] = []
        for post_id in posts["order"]:
            post = posts["posts"][post_id]
            if post.get("delete_at", 0) > 0:
                continue
            included_posts.append(post_id)
            link[post_id] = self._process_post(
                post=post,
                post_id=post_id,
                team_name=team_name,
                base_url=base_url,
                channel_target_ref=channel_target_ref,
                bundle=bundle,
            )

        # Thread (sub-post) relationships. The target media-content id
        # is deterministic on ``url`` (pycti's
        # ``CustomObservableMediaContent`` auto-generates the id from
        # the URL), so we can link a reply to its root even when the
        # root was ingested in a previous run and is not part of the
        # current batch.
        for post_id in included_posts:
            root_mattermost_id = posts["posts"][post_id].get("root_id")
            if not root_mattermost_id:
                continue
            root_link = link.get(root_mattermost_id)
            if root_link:
                target = root_link[0]
            else:
                root_post_url = base_url + team_name + "/pl/" + root_mattermost_id
                target = self._media_content_id(root_post_url)
                self.helper.log_debug(
                    f"Root of subpost {post_id} not in this batch; "
                    f"linking to deterministic media-content id {target} "
                    f"derived from {root_post_url}."
                )
            source = link[post_id][0]
            bundle.append(
                stix2.Relationship(
                    id=PyctiSCR.generate_id("related-to", source, target, None, None),
                    relationship_type="related-to",
                    source_ref=source,
                    target_ref=target,
                    object_marking_refs=[self.mattermost_marking_id],
                )
            )
        return bundle

    def _ensure_channel(
        self,
        channel_name: str,
        description: str,
        bundle: List[Any],
    ) -> str:
        """Return the STIX id of the channel, creating it if necessary."""
        existing = self.helper.api.channel.list(
            filters=self._list_filter("name", channel_name)
        )
        if existing:
            return existing[0]["standard_id"]

        new_channel = CustomObjectChannel(
            id=PyctiChannel.generate_id(channel_name),
            name=channel_name,
            description=description,
            object_marking_refs=[self.mattermost_marking_id],
            channel_types=["Mattermost"],
            allow_custom=True,
        )
        bundle.append(new_channel)
        self.helper.log_debug(f"Channel object created: {new_channel['id']}")
        return new_channel["id"]

    def _process_post(
        self,
        *,
        post: Dict[str, Any],
        post_id: str,
        team_name: str,
        base_url: str,
        channel_target_ref: str,
        bundle: List[Any],
    ) -> List[str]:
        post_url = base_url + team_name + "/pl/" + post_id
        content = post.get("message") or "(empty)"
        publication_date = datetime.fromtimestamp(
            post["create_at"] / 1000, tz=timezone.utc
        )

        # Author -----------------------------------------------------------
        # Both the Mattermost user lookup (``_author_email``) and the
        # OpenCTI identity lookup (``_ensure_author``) are cached for the
        # duration of the run so a busy channel with many posts from a
        # handful of distinct authors triggers a small constant number
        # of API calls instead of one pair per post.
        email = self._author_email(post["user_id"])
        author_id = self._ensure_author(email, bundle)

        # Attachments ------------------------------------------------------
        attachments: List[Dict[str, Any]] = []
        files_meta = (post.get("metadata") or {}).get("files") or []
        for attachment in files_meta:
            try:
                filename = f"{attachment['id']}_{attachment['name']}"
                if self._file_exists(post_url, filename):
                    continue
                response = self.driver.files.get_file(attachment["id"])
                attachments.append(
                    {
                        "name": filename,
                        "data": base64.b64encode(response.content).decode("ascii"),
                        "mime_type": attachment.get("mime_type", ""),
                    }
                )
            except Exception as exc:  # noqa: BLE001 - keep going on attachment errors
                self.helper.log_warning(
                    f"Could not download attachment from post {post_id}: {exc}"
                )

        # Media content + relationship ------------------------------------
        # ``CustomObservableMediaContent`` (from pycti) auto-generates a
        # deterministic id from the ``url`` value, so passing it explicitly
        # is not necessary. The post body is carried in ``content`` (its
        # semantic home on a ``media-content`` SCO); ``x_opencti_description``
        # mirrors it so the observable shows a user-facing description in
        # the OpenCTI UI. ``created_by_ref`` and ``x_opencti_files`` are
        # OpenCTI extensions and are emitted through ``custom_properties``.
        # ``x_opencti_files`` is only added when there is at least one
        # attachment, matching the convention used by other
        # external-import connectors and avoiding spurious updates when
        # ``CONNECTOR_UPDATE_EXISTING_DATA`` is enabled.
        custom_properties: Dict[str, Any] = {
            "x_opencti_description": content,
            "created_by_ref": author_id,
        }
        if attachments:
            custom_properties["x_opencti_files"] = attachments
        media_content = CustomObservableMediaContent(
            url=post_url,
            content=content,
            publication_date=publication_date,
            media_category="mattermost",
            object_marking_refs=[self.mattermost_marking_id],
            allow_custom=True,
            custom_properties=custom_properties,
        )
        bundle.append(media_content)
        bundle.append(
            stix2.Relationship(
                id=PyctiSCR.generate_id(
                    "related-to",
                    media_content["id"],
                    channel_target_ref,
                    None,
                    None,
                ),
                relationship_type="related-to",
                source_ref=media_content["id"],
                target_ref=channel_target_ref,
                object_marking_refs=[self.mattermost_marking_id],
            )
        )
        return [media_content["id"], post_url]

    def _file_exists(self, url: str, filename: str) -> bool:
        """Return whether ``filename`` is already attached to the observable for ``url``.

        The set of existing filenames is cached per ``url`` for the
        duration of the run, so a post with N attachments triggers a
        single ``stix_cyber_observable.list`` / ``.read`` round-trip
        instead of N.
        """
        cached = self._existing_files_cache.get(url)
        if cached is None:
            cached = self._load_existing_filenames(url)
            self._existing_files_cache[url] = cached
        return filename in cached

    def _load_existing_filenames(self, url: str) -> set:
        observables = self.helper.api.stix_cyber_observable.list(
            filters=self._list_filter("url", url)
        )
        if len(observables) != 1:
            return set()
        observable = self.helper.api.stix_cyber_observable.read(
            id=observables[0]["id"], withFiles=True
        )
        return {
            f.get("name")
            for f in (observable.get("importFiles") or [])
            if f.get("name")
        }

    def _collect_intelligence(self, since: Optional[datetime] = None) -> List[Any]:
        """Return the STIX objects produced for this scheduling cycle."""
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting collection..."
        )
        # Drop any cached author email / attachment-existence lookups
        # from the previous cycle so a long-running connector cannot
        # leak memory and so updates on the Mattermost / OpenCTI side
        # eventually become visible.
        self._reset_run_caches()
        if since is not None:
            start_time = int(since.timestamp())
        else:
            start_time = self.mattermost_start_timestamp

        # Include the configured TLP marking-definition object in the
        # bundle. Built-in stix2 markings (TLP_WHITE / GREEN / AMBER /
        # RED) are already known to the platform but emitting them
        # explicitly is harmless; ``TLP:CLEAR`` / ``TLP:AMBER+STRICT``
        # are OpenCTI-specific and *must* be present so the platform can
        # register the marking by name instead of leaving downstream
        # objects pointing at an unresolved reference.
        stix_objects: List[Any] = [self.mattermost_marking]
        for channel_id in self.mattermost_channel_ids:
            stix_objects.extend(self._collect_channel_posts(channel_id, start_time))

        self.helper.log_info(
            f"{len(stix_objects)} STIX objects produced by "
            f"{self.helper.connect_name} connector."
        )
        return stix_objects


if __name__ == "__main__":
    try:
        MattermostConnector().run()
    except Exception as exc:  # noqa: BLE001 - last-resort safety net
        print(exc)
        time.sleep(10)
        sys.exit(1)
