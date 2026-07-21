# -*- coding: utf-8 -*-
"""
OSINT Industries mapping (spec_format) -> STIX objects.

Actual structure of a response (confirmed on a full sample):
  [
    {
      "module": "okru",
      "query": "alice@example.com",
      "status": "found",
      "spec_format": [
        {
          "registered": {"proper_key": "Registered", "value": true, "type": "bool"},
          "username":   {"proper_key": "Username", "value": "bob", "type": "str"},
          ...
          "platform_variables": [
            {"key": "uid", "proper_key": "Uid", "value": "123", "type": "int"},
          ]
        }
      ]
    },
  ]

POINTS VERIFIED on the environment (pycti 7.26 / connectors_sdk):
  - The SDK provides UserAccount, EmailAddress, URL, Note, OrganizationAuthor,
    TLPMarking (NO Location, NO PhoneNumber/Wallet).
  - account_type is voided by the platform when custom -> we leave it empty;
    the module name goes into display_name + labels.
  - Phone/Wallet: pycti CustomObservable* objects, which ARE already STIX2
    objects (they have no .to_stix2_object()).
  - RELATIONS: OpenCTI allows almost no specific relation between observables,
    but 'related-to' (the generic relation) is accepted between observables.
    So EVERYTHING (accounts, emails, urls, phones, wallets) is linked to the
    SOURCE observable with a raw 'related-to' relation (star-shaped model),
    via stix2.Relationship + StixCoreRelationship.generate_id (deterministic id).
  - No City node: no observable<->City relation exists in the schema; the
    location stays in the description + summary Notes.
  - stix2_create_bundle(items) expects a homogeneous list of STIX2 objects.
    => we call .to_stix2_object() on the SDK objects and keep the
       CustomObservable objects as-is, then bundle.
"""

from __future__ import annotations

import datetime
from typing import Any

import stix2
from connectors_sdk.models import (
    URL,
    AssociatedFile,
    EmailAddress,
    Note,
    OrganizationAuthor,
    Reference,
    TLPMarking,
    UserAccount,
)
from pycti import (
    CustomObservableCryptocurrencyWallet,
    CustomObservablePhoneNumber,
    StixCoreRelationship,
)

try:
    from report_html import build_report_html
except ImportError:  # when the folder is imported as a package
    from .report_html import build_report_html


# --------------------------------------------------------------------------
# spec_format parsing helpers
# --------------------------------------------------------------------------
def _is_placeholder(value: Any) -> bool:
    """The sample anonymises with 'XXXXXXX'; avoid creating objects from it."""
    return isinstance(value, str) and set(value) == {"X"} and len(value) >= 5


def _clean(value: Any) -> Any:
    if value in (None, "", [], {}):
        return None
    if _is_placeholder(value):
        return None
    return value


def _flatten_spec(spec: dict) -> dict:
    """Flatten a spec_format block {key:{proper_key,value,type}, platform_variables:[...]}
    into a simple dict {key: value}, merging top-level and platform_variables."""
    flat: dict = {}
    if not isinstance(spec, dict):
        return flat

    for key, field in spec.items():
        if key == "platform_variables":
            continue
        if isinstance(field, dict) and "value" in field:
            v = _clean(field.get("value"))
            if v is not None:
                flat[key] = v

    for pv in spec.get("platform_variables", []) or []:
        if not isinstance(pv, dict):
            continue
        k = pv.get("key")
        if not k:
            continue
        v = _clean(pv.get("value"))
        if v is not None:
            flat[k] = v

    return flat


def _parse_date(value: Any) -> datetime.datetime | None:
    if not value or _is_placeholder(value):
        return None
    if isinstance(value, datetime.datetime):
        return value
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            return datetime.datetime.strptime(str(value), fmt)
        except (ValueError, TypeError):
            continue
    return None


def _first(d: dict, *keys: str) -> Any:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", [], {}):
            return v
    return None


def _person_name(flat: dict) -> str | None:
    name = _first(flat, "name", "full_name", "fullname")
    if name:
        return str(name)
    fn = _first(flat, "first_name", "firstname")
    ln = _first(flat, "last_name", "lastname")
    parts = [str(p) for p in (fn, ln) if p]
    return " ".join(parts) if parts else None


class ConverterToStix:
    """Convert an OSINT Industries response into a STIX bundle."""

    def __init__(self, author: OrganizationAuthor, tlp: TLPMarking):
        self.author = author
        self.tlp = tlp
        self._source_value: str | None = None

    @staticmethod
    def make_author() -> OrganizationAuthor:
        return OrganizationAuthor(
            name="OSINT Industries",
            description="Enrichment data provided by the OSINT Industries API.",
            organization_type="vendor",
        )

    # ---- entry point: returns a homogeneous list of STIX2 objects ----------
    def process(self, source_observable, payload: Any) -> list:
        # author + marking first (converted to STIX at the end of the method)
        sdk_objects: list = [self.author, self.tlp]
        raw_stix: list = []  # already-STIX objects (pycti CustomObservable)
        self._summary = []  # per-account recap, for the summary notes

        # L'observable source arrive de pycti sous forme de dict ; son id STIX
        # est dans 'standard_id'. On relie via cet id (relation brute), car ce
        # n'est pas un objet SDK.
        source_id = None
        self._source_value = None
        if isinstance(source_observable, dict):
            source_id = source_observable.get("standard_id") or source_observable.get(
                "id"
            )
            self._source_value = source_observable.get("value")
        elif hasattr(source_observable, "id"):
            source_id = source_observable.id
            self._source_value = getattr(source_observable, "value", None)

        for mod in self._normalize_modules(payload):
            module_name = _first(mod, "module", "name") or "unknown"
            status = str(mod.get("status", "")).lower()
            if status in ("not_found", "error"):
                continue
            specs = mod.get("spec_format") or []
            if isinstance(specs, dict):
                specs = [specs]
            for spec in specs:
                flat = _flatten_spec(spec)
                if not flat:
                    continue
                self._map_flat(source_id, module_name, flat, sdk_objects, raw_stix)

        # --- summary notes (markdown Notes rendered by OpenCTI) -------------
        if self._summary:
            global_note = self._build_global_note(source_id)
            if global_note is not None:
                sdk_objects.append(global_note)
            for entry in self._summary:
                detail = self._build_account_note(entry)
                if detail is not None:
                    sdk_objects.append(detail)

        # --- HTML card report, attached to the source observable ------------
        if self._summary:
            report_obj = self._build_report_attachment(source_id)
            if report_obj is not None:
                sdk_objects.append(report_obj)

        # homogeneous conversion: SDK -> stix, + already-stix objects.
        # Dedup by id, BUT if two objects share the same id and one of them
        # porte des fichiers (x_opencti_files), on conserve la version avec
        # files (otherwise the HTML report attached to the source observable
        # would be overwritten by the same observable without file from a module).
        by_id: dict = {}
        order: list = []

        def _add(stix):
            sid = stix.id
            if sid not in by_id:
                by_id[sid] = stix
                order.append(sid)
                return
            existing = by_id[sid]
            new_has_files = bool(getattr(stix, "x_opencti_files", None))
            old_has_files = bool(getattr(existing, "x_opencti_files", None))
            if new_has_files and not old_has_files:
                by_id[sid] = stix  # la version avec fichiers gagne

        for obj in sdk_objects:
            _add(obj.to_stix2_object())
        for stix in raw_stix:
            _add(stix)

        stix_items = [by_id[sid] for sid in order]
        return stix_items

    @staticmethod
    def _normalize_modules(payload: Any) -> list[dict]:
        if payload is None:
            return []
        if isinstance(payload, list):
            return [m for m in payload if isinstance(m, dict)]
        if isinstance(payload, dict):
            for key in ("data", "results", "modules"):
                if isinstance(payload.get(key), list):
                    return [m for m in payload[key] if isinstance(m, dict)]
            return [payload]
        return []

    # ---- mapping d'un bloc aplati -----------------------------------------
    def _map_flat(
        self,
        source_id: str | None,
        module_name: str,
        flat: dict,
        sdk_objects: list,
        raw_stix: list,
    ) -> None:
        login = _first(flat, "username", "handle", "screen_name")
        user_id = _first(flat, "id", "uid", "user_id")
        person = _person_name(flat)
        email = _first(flat, "email", "email_address")

        # --- displayed handle: real handle, else person name, else email ---
        if login:
            shown = str(login)
        elif person:
            shown = person
        elif email and "@" in str(email):
            shown = str(email)
        else:
            shown = None

        # --- display_name uniforme : "<pseudo|email> [Plateforme]" -------------
        if shown:
            display_name = "%s [%s]" % (shown, module_name)
        else:
            display_name = "[%s]" % module_name

        # --- account_login = STIX uniqueness key -------------------------------
        # Uniform format "<identity> [platform]": the platform is ALWAYS
        # included, so the same handle on two sites yields two accounts
        # distincts (HugoH35 [github] != HugoH35 [twitter]), et email1/email2 sur
        # the same site stay distinct. The STIX id derives from account_login,
        # so this key guarantees uniqueness by (identity, platform).
        src_email = None
        if isinstance(self._source_value, str) and "@" in self._source_value:
            src_email = self._source_value
        key_email = src_email or (str(email) if email and "@" in str(email) else None)

        if login:
            identity = str(login)
        elif key_email:
            identity = key_email
        elif user_id:
            identity = str(user_id)
        else:
            identity = None

        if identity:
            account_login = "%s [%s]" % (identity, module_name)
        else:
            account_login = module_name

        account = UserAccount(
            account_login=account_login,
            # account_type left empty: the platform voids custom values.
            user_id=str(user_id) if user_id else None,
            display_name=display_name,
            account_created=_parse_date(
                _first(flat, "creation_date", "created", "registered_date")
            ),
            description=self._describe(module_name, flat),
            labels=["osint-industries", module_name],
            author=self.author,
            markings=[self.tlp],
        )
        sdk_objects.append(account)
        # relation account -> observable source (par id STIX, relation brute)
        if source_id:
            raw_stix.append(self._raw_rel_ids(account.id, source_id))

        # collect for the summary note + per-account detail note.
        # On exclut les modules de type 'breach' (hibp...) : ce ne sont pas des
        # accounts, they already have their own dedicated breach Note.
        is_breach = flat.get("breach") is True or module_name == "hibp"
        if not is_breach:
            self._summary.append(
                {
                    "module": module_name,
                    "display": display_name,
                    "shown": shown,
                    "flat": flat,
                    "account": account,
                }
            )

        # email -> relie a l'observable SOURCE (modele en etoile)
        email = _first(flat, "email", "email_address")
        if email and "@" in str(email):
            email_obs = EmailAddress(
                value=str(email),
                labels=["osint-industries", module_name],
                author=self.author,
                markings=[self.tlp],
            )
            sdk_objects.append(email_obs)
            if source_id and email_obs.id != source_id:
                raw_stix.append(self._raw_rel_ids(email_obs.id, source_id))

        # url de profil -> relie a la SOURCE
        url = _first(flat, "profile_url", "url", "link", "member_url")
        if url and str(url).startswith("http"):
            url_obs = URL(
                value=str(url),
                labels=["osint-industries", module_name],
                author=self.author,
                markings=[self.tlp],
            )
            sdk_objects.append(url_obs)
            if source_id:
                raw_stix.append(self._raw_rel_ids(url_obs.id, source_id))

        # localisation : OpenCTI n'autorise AUCUNE relation entre un observable
        # (User-Account/Email-Addr) et une City. On ne cree donc PAS de noeud
        # City : la localisation reste dans la description du compte et dans les
        # fiches de synthese (Notes).

        # telephone : CustomObservable pycti (deja STIX) -> relie a la SOURCE
        phone = _first(flat, "phone", "phone_number", "number")
        if phone:
            phone_obs = CustomObservablePhoneNumber(
                value=str(phone),
                object_marking_refs=[self._tlp_id()],
                custom_properties={
                    "x_opencti_created_by_ref": self._author_id(),
                    "x_opencti_labels": ["osint-industries", module_name],
                },
            )
            raw_stix.append(phone_obs)
            if source_id:
                raw_stix.append(self._raw_rel_ids(phone_obs.id, source_id))

        # wallet crypto : CustomObservable pycti (deja STIX) -> relie a la SOURCE
        wallet = _first(flat, "wallet", "crypto_wallet", "wallet_address")
        if wallet:
            wallet_obs = CustomObservableCryptocurrencyWallet(
                value=str(wallet),
                object_marking_refs=[self._tlp_id()],
                custom_properties={
                    "x_opencti_created_by_ref": self._author_id(),
                    "x_opencti_labels": ["osint-industries", module_name],
                },
            )
            raw_stix.append(wallet_obs)
            if source_id:
                raw_stix.append(self._raw_rel_ids(wallet_obs.id, source_id))

        # breach / HIBP -> Note sur le compte
        if flat.get("breach") is True or module_name == "hibp":
            note = self._breach_note(module_name, flat, [account])
            if note:
                sdk_objects.append(note)

    # ---- attached HTML report ---------------------------------------------
    def _build_report_attachment(self, source_id: str | None):
        """Recreate the source observable as an SDK object (same value -> same
        deterministic id -> OpenCTI merges) and attach the HTML report via
        associated_files. The file appears under the Data/Files tab of
        l'observable enrichi.

        Phone/wallet (pycti CustomObservable) have no associated_files:
        dans ce cas on attache le rapport au compte le plus riche (repli)."""
        if not source_id:
            return None

        selector = self._source_value or "the queried selector"
        html_bytes = build_report_html(selector, self._summary).encode("utf-8")
        report_file = AssociatedFile(
            name="osint-industries-report.html",
            description="OSINT Industries digital-footprint report (cards).",
            content=html_bytes,
            mime_type="text/html",
            markings=[self.tlp],
        )

        prefix = source_id.split("--", 1)[0]
        value = self._source_value

        # types SDK qui supportent associated_files
        if prefix == "email-addr" and value:
            return EmailAddress(
                value=str(value),
                associated_files=[report_file],
                author=self.author,
                markings=[self.tlp],
            )
        if prefix == "url" and value:
            return URL(
                value=str(value),
                associated_files=[report_file],
                author=self.author,
                markings=[self.tlp],
            )
        if prefix == "user-account" and value:
            return UserAccount(
                account_login=str(value),
                associated_files=[report_file],
                author=self.author,
                markings=[self.tlp],
            )

        # repli (phone-number, cryptocurrency-wallet, ou value absente) :
        # attacher au compte le plus riche pour ne pas perdre le rapport.
        richest = max(
            self._summary,
            key=lambda e: len(e["flat"]),
            default=None,
        )
        if richest is not None:
            acc = richest["account"]
            return UserAccount(
                account_login=acc.account_login,
                user_id=acc.user_id,
                display_name=acc.display_name,
                associated_files=[report_file],
                labels=["osint-industries", richest["module"]],
                author=self.author,
                markings=[self.tlp],
            )
        return None

    # "Noise" fields not shown in the notes (already structured elsewhere
    # or not useful to the investigator).
    _SKIP_KEYS = {"registered", "breach"}

    def _build_global_note(self, source_id: str | None):
        """Global summary note: a table of all discovered accounts, attached
        to the source observable. This is the 'card view' the investigator
        lit en premier."""
        target = self._summary[0]["account"] if self._summary else None
        if source_id is None and target is None:
            return None

        found = len(self._summary)
        src = self._source_value or "the queried selector"
        lines = [
            "## OSINT Industries — enrichment summary",
            "",
            "**Selector:** `%s`  " % src,
            "**Accounts found:** %d" % found,
            "",
            "| Platform | Identity | Key facts |",
            "| --- | --- | --- |",
        ]
        for e in sorted(self._summary, key=lambda x: x["module"]):
            ident = e["shown"] or "—"
            facts = self._key_facts(e["flat"])
            lines.append(
                "| %s | %s | %s |"
                % (
                    self._md_cell(e["module"]),
                    self._md_cell(ident),
                    self._md_cell(facts) or "—",
                )
            )
        lines += [
            "",
            "_Generated by the OSINT Industries connector. Data is provided "
            "as-is by the vendor; verify before action._",
        ]

        # Attach the note to the source observable first (that is where the
        # analyst looks for it), then to every discovered account. The source
        # observable is not an SDK object, so we reference it by its STIX id
        # through Reference, alongside the SDK accounts.
        objects = [e["account"] for e in self._summary]
        if source_id:
            objects.insert(0, Reference(id=source_id))
        return Note(
            abstract="OSINT Industries — %d account(s) found" % found,
            content="\n".join(lines),
            objects=objects,
            note_types=["analysis"],
            labels=["osint-industries", "summary"],
            author=self.author,
            markings=[self.tlp],
        )

    def _build_account_note(self, entry: dict):
        """Per-account detail note: all readable fields, including
        ceux qu'on ne mettait pas dans des champs STIX (ssh_keys, services...)."""
        flat = entry["flat"]
        rows = []
        for k, v in flat.items():
            if k in self._SKIP_KEYS:
                continue
            if isinstance(v, (dict, list)):
                v = self._stringify(v)
            v = str(v).strip()
            if not v:
                continue
            rows.append((k, v))
        if not rows:
            return None  # 'registered only' account: no detail note

        lines = [
            "### %s" % entry["display"],
            "",
            "| Field | Value |",
            "| --- | --- |",
        ]
        for k, v in rows:
            lines.append("| %s | %s |" % (self._md_cell(k), self._md_cell(v)))

        return Note(
            abstract="OSINT Industries — %s" % entry["display"],
            content="\n".join(lines),
            objects=[entry["account"]],
            note_types=["analysis"],
            labels=["osint-industries", "detail", entry["module"]],
            author=self.author,
            markings=[self.tlp],
        )

    @staticmethod
    def _key_facts(flat: dict, limit: int = 4) -> str:
        """Quelques champs saillants pour la colonne 'Key facts' du tableau."""
        priority = (
            "name",
            "full_name",
            "creation_date",
            "created",
            "last_seen",
            "location",
            "phone",
            "verified",
            "followers",
            "id",
        )
        parts = []
        for k in priority:
            v = flat.get(k)
            if v in (None, "", [], {}):
                continue
            if isinstance(v, (dict, list)):
                continue
            parts.append("%s: %s" % (k, v))
            if len(parts) >= limit:
                break
        return "; ".join(parts)

    @staticmethod
    def _stringify(value: Any) -> str:
        """Aplati listes/dicts pour affichage markdown (ssh_keys, services...)."""
        if isinstance(value, list):
            flat_items = []
            for item in value:
                if isinstance(item, dict):
                    flat_items.append(
                        ", ".join("%s=%s" % (k, v) for k, v in item.items())
                    )
                else:
                    flat_items.append(str(item))
            return " | ".join(flat_items)
        if isinstance(value, dict):
            return ", ".join("%s=%s" % (k, v) for k, v in value.items())
        return str(value)

    @staticmethod
    def _md_cell(value: Any) -> str:
        """Escape table markdown (pipes / line breaks)."""
        s = str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
        return s.strip()

    def _breach_note(self, module_name: str, flat: dict, objects: list):
        title = _first(flat, "title", "name")
        data_classes = flat.get("data_classes")
        added = flat.get("added_date")
        lines = [
            "Data breach exposure reported by OSINT Industries (%s)." % module_name
        ]
        if title:
            lines.append("Breach: %s" % title)
        if data_classes:
            lines.append("Exposed data: %s" % data_classes)
        if added:
            lines.append("Added: %s" % added)
        return Note(
            abstract="OSINT Industries breach exposure (%s)" % module_name,
            content="\n".join(lines),
            objects=objects,
            labels=["osint-industries", "breach", module_name],
            author=self.author,
            markings=[self.tlp],
        )

    @staticmethod
    def _describe(module_name: str, flat: dict) -> str:
        lines = ["Account discovered on %s by OSINT Industries.\n" % module_name]
        for k, v in flat.items():
            if isinstance(v, (dict, list)):
                continue
            if k == "registered":
                continue
            lines.append("- %s: %s" % (k, v))
        return "\n".join(lines)

    # ---- relationships ----------------------------------------------------
    def _raw_rel_ids(
        self, source_id: str, target_id: str, rel_type: str = "related-to"
    ):
        """Raw STIX 2.1 relation between two STIX ids (deterministic).
        All connector relations go through here: every discovered object is
        linked to the source observable (star-shaped model)."""
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(rel_type, source_id, target_id),
            relationship_type=rel_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self._author_id(),
            object_marking_refs=[self._tlp_id()],
            allow_custom=True,
        )

    def _author_id(self) -> str:
        return self.author.id

    def _tlp_id(self) -> str:
        return self.tlp.to_stix2_object().id
