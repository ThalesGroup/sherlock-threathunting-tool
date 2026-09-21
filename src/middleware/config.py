"""Middleware configuration: caps, budgets, allowlists, masking policy.

All numeric guardrails live here, never in a prompt. A value absent from this module is not
configurable by the model.
"""

from __future__ import annotations

import functools
import json
from typing import Annotated

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class SiemCaps(BaseModel):
    """Caps applied to a SIEM. The model cannot exceed them."""

    rows_default: int = 500
    rows_max: int = 500
    window_days_default: int = 7
    window_days_max: int = 30

    def clamp_rows(self, requested: int | None) -> int:
        if requested is None:
            return self.rows_default
        return max(1, min(requested, self.rows_max))


class Budgets(BaseModel):
    """Per-hunt budgets. Overrun = clean stop and partial report."""

    max_iterations: int = 20
    max_siem_queries: int = 15
    max_tokens: int = 400_000
    max_duration_seconds: int = 900
    token_alert_ratio: float = 0.8
    cache_read_cost_ratio: float = 0.1
    cache_write_cost_ratio: float = 1.25


class MaskingPolicy(BaseModel):
    """Fields neutralized before any return to the model."""

    drop_fields: tuple[str, ...] = (
        "password",
        "passwd",
        "secret",
        "client_secret",
        "api_key",
        "apikey",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "authorization",
        "cookie",
        "set-cookie",
        "private_key",
        "credential",
        "credentials",
        "sas_token",
        "connectionstring",
    )
    hash_fields: tuple[str, ...] = (
        "useremail",
        "user_email",
        "mail",
        "emailaddress",
        "email",
        "upn",
        "userprincipalname",
        "phone",
        "phonenumber",
        "mobile",
        "employeeid",
        "employee_id",
        "nationalid",
        "iban",
        "givenname",
        "surname",
        "firstname",
        "lastname",
        "fullname",
        "displayname",
        # Non-English log schemas seen in the wild; extend with your own field names.
        "prenom",
        "nom",
    )
    hash_salt: str = "change-me-in-vault"


class TokenizationPolicy(BaseModel):
    """Reversible pseudonymization of internal entities before any send to the model.

    Unlike the hashing in `MaskingPolicy`, the mapping is kept within the scope of the
    hunt: the model correlates on stable pseudonyms, the analyst reads the real values.
    Internal identifiers do not leave the platform.
    """

    enabled: bool = True
    host_fields: tuple[str, ...] = (
        "computer",
        "computername",
        "hostname",
        "host",
        "devicename",
        "device_name",
        "dvchostname",
        "remotedevicename",
        "sourcehostname",
        "destinationhostname",
    )
    user_fields: tuple[str, ...] = (
        "account",
        "accountname",
        "account_name",
        "user",
        "username",
        "user_name",
        "accountupn",
        "userprincipalname",
        "upn",
        "subjectusername",
        "targetusername",
        "initiatinguser",
        "requesteraccount",
    )


class RateLimits(BaseModel):
    """Outbound call quotas, aligned with the real API limits."""

    defender_per_minute: int = 45
    defender_per_hour: int = 1_500
    sentinel_per_minute: int = 60
    secops_per_minute: int = 60
    ti_per_minute: int = 30


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SHL_",
        env_file=".env",
        env_nested_delimiter="__",
        extra="ignore",
    )

    environment: str = "dev"
    report_organisation: str = "SOC"
    """Issuing entity shown on the report cover page (e.g. "SOC EU-01")."""

    demo_siem: bool = False
    """Plugs in simulated SIEM clients in place of the real ones, for demonstration.
    Explicit and confined to development: `build_clients` refuses to enable it outside
    `dev`. Each simulated row carries a `simulation` marker and the front shows a banner."""

    sentinel: SiemCaps = SiemCaps()
    defender: SiemCaps = SiemCaps(window_days_max=30)
    secops: SiemCaps = SiemCaps(window_days_max=90)

    budgets: Budgets = Budgets()
    masking: MaskingPolicy = MaskingPolicy()
    tokenization: TokenizationPolicy = TokenizationPolicy()
    rate_limits: RateLimits = RateLimits()

    max_result_tokens: int = 50_000
    """Token cap per result transmitted to the model. Sized so that a complete result of
    500 projected rows passes in full: below the row cap, the agent analyzes everything;
    beyond it, it has only the aggregates and refines."""

    workspace_aliases: Annotated[dict[str, str], NoDecode] = Field(default_factory=dict)
    """Logical alias -> real workspace identifier. The real name never leaves here."""

    ti_allowed_domains: Annotated[tuple[str, ...], NoDecode] = ()
    """Allowlist of threat intelligence sources. Empty = no outbound flow possible."""

    ti_publisher_domains: Annotated[tuple[str, ...], NoDecode] = ()
    """Approved publishers for the public report search (CISA, CERT-FR, vendors).
    Empty = the "vendor reports" source does not exist (except in open search)."""

    ti_open_search: bool = False
    """Report search open to the whole web: any HTTPS page returned by the search engine
    can be read to extract IOCs from it. Deliberate relaxation of the egress allowlist,
    limited to the upstream phase: only the campaign name leaves the perimeter, each IOC
    cites its source page and goes through analyst validation. The other locks (untrusted
    content encapsulated, revalidation by pattern) stay active. Server decision, never
    modifiable from the Configuration screen."""

    internal_hostname_suffixes: Annotated[tuple[str, ...], NoDecode] = ()
    """Internal DNS suffixes, used by the egress anti-leak filter."""

    ca_bundle: str = ""
    """Certificate authority bundle for outbound calls inspected by an enterprise TLS
    proxy. Must contain both the public roots and the internal root
    (e.g. `cat $(python -m certifi) internal-root.pem > bundle.pem`). Empty = public store
    only. Without it, a domain whose certificate is re-signed by the proxy is rejected."""

    log_level: str = "INFO"
    """Server log level (DEBUG, INFO, WARNING...). Outbound call failures (gateway, threat
    intel sources) are logged at WARNING with their real cause, secrets excluded. Standard
    output: the terminal in development, journalctl behind systemd."""

    secops_base_url: str = ""
    """Chronicle API endpoint. Empty (default) = derived from the region present in the
    instance path. To be set only for a special case."""

    secops_instance_path: str = ""
    """Chronicle instance path: `projects/<id>/locations/<region>/instances/<uuid>`.
    Normally entered in the Configuration screen (SECOPS_INSTANCE_PATH); this variable
    remains a server fallback. Empty on both sides = SecOps inactive."""

    gateway_base_url: str = ""
    gateway_model_analysis: str = ""
    """Identifier of the analysis and decision model on the gateway (the most capable in
    the catalog). To be set per installation: the list is obtained via GET /v1/models."""

    gateway_model_query: str = ""
    """Identifier of the query-generation model (fast and cheap)."""

    anonymizer_base_url: str = ""
    """Endpoint of the anonymization model (local model, OpenAI-compatible). If unset,
    reuses `gateway_base_url`. Serves the semantic anonymization layer, not the investigation."""

    anonymizer_model: str = "local-anonymizer-model"
    """Default anonymization model. Identifier to be confirmed via GET /v1/models."""

    semantic_anonymization: bool = True
    """Semantic anonymization pass after the deterministic layer. Enabled when an endpoint
    and an anonymization key are configured. Fail-closed: if the model is unreachable, the
    free-text fields are masked rather than sent in the clear."""

    semantic_anonymization_fail_closed: bool = True
    """If true (default), a failure of the anonymization model masks the free-text fields.
    If false, the results pass through as the deterministic layer left them."""
    gateway_prompt_caching: bool = True
    """Marks the stable prefix of the prompt as cacheable. Depending on the interface
    exposed by the AI gateway, caching is automatic (nothing to send) or requires these
    markers. Can be disabled with `SHL_GATEWAY_PROMPT_CACHING=false` if the gateway
    rejects them."""

    budget_pause_timeout_seconds: int = 600
    """Budget checkpoint: when a budget is exhausted, the hunt waits for the analyst's
    decision (continue with an extension, or stop) for this delay. Without a response,
    clean stop with a partial report, as before. 0 = checkpoint disabled."""

    database_url: str = "sqlite+aiosqlite:///./hunts.db"

    knowledge_dir: str = "knowledge"
    """Directory of versioned reference sheets (SIEM schemas, environment)."""

    key_vault_url: str = ""
    """Azure Key Vault URL (e.g. https://example-vault.vault.azure.net). Empty =
    development mode: local encrypted store and `.env`. Set = secrets are read and written
    in the vault via the managed identity, with no other change."""

    secret_store_path: str = ".secrets.enc"  # noqa: S105 - store path, not a secret
    """Encrypted store of the keys entered in the Configuration screen. Its master key is
    in `SHL_SECRET_STORE_KEY` or in the `.secrets.enc.key` file (created on the fly, mode
    600). Neither file must be committed to version control."""

    @field_validator(
        "ti_allowed_domains", "ti_publisher_domains", "internal_hostname_suffixes", mode="before"
    )
    @classmethod
    def _split_csv(cls, value: object) -> object:
        if isinstance(value, str):
            return tuple(item.strip().lower() for item in value.split(",") if item.strip())
        return value

    @field_validator("workspace_aliases", mode="before")
    @classmethod
    def _parse_aliases(cls, value: object) -> object:
        """Accepts JSON from the .env, and an empty value rather than a crash at startup."""

        if isinstance(value, str):
            if not value.strip():
                return {}
            return json.loads(value)
        return value

    def caps_for(self, siem: str) -> SiemCaps:
        match siem:
            case "sentinel":
                return self.sentinel
            case "defender":
                return self.defender
            case "secops":
                return self.secops
            case _:
                raise ValueError(f"Unknown SIEM: {siem}")


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
