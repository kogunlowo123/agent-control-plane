"""Runtime settings, read from ACP_* environment variables."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Literal

from pydantic import Field, HttpUrl, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ACP_", env_nested_delimiter="__")

    environment: str = "production"
    public_url: HttpUrl = Field(description="Public URL of this control plane (agent card, pods)")
    instance_id: str = Field(
        default_factory=socket.gethostname,
        min_length=1,
        max_length=128,
        description="Replica identity: audit chain id and reconciler lease holder",
    )
    database_url: str = Field(description="SQLAlchemy async URL, e.g. postgresql+asyncpg://...")

    # Operator authentication (enterprise IdP)
    operator_issuer: str
    operator_audience: str
    operator_jwks_url: str
    operator_roles_claim: str = "roles"

    policy_file: Path = Path("policies/control-plane.yaml")

    # Signing keys (Ed25519 PEM). Ephemeral keys only outside production.
    audit_key_file: Path | None = None
    bundle_key_file: Path | None = None
    dev_ephemeral_keys: bool = Field(
        default=False,
        description="In-memory signing keys generated at start-up; refused in production.",
    )

    # Kubernetes
    kube_mode: Literal["in-cluster", "kubeconfig"] = "in-cluster"
    kubeconfig_path: str | None = None
    managed_namespaces: frozenset[str] = Field(
        description="Namespaces this control plane may deploy agents into"
    )
    platform_namespace: str = Field(
        default="agent-platform", description="Namespace of the control plane and identity fabric"
    )
    reconcile_interval_s: float = Field(default=30.0, ge=1.0, le=3600.0)
    lease_ttl_s: float = Field(default=45.0, ge=5.0, le=600.0)

    # Identity fabric (optional; without it agents are authorized by local policy)
    fabric_url: HttpUrl | None = None
    fabric_trust_domain: str | None = None
    fabric_workload_audience: str = "identity-fabric"
    cluster_oidc_issuer: str | None = Field(
        default=None, description="Workload token issuer of the managed cluster"
    )
    fabric_admin_token_url: str | None = None
    fabric_admin_client_id: str | None = None
    fabric_admin_client_secret: SecretStr | None = None
    fabric_admin_scope: str = "identity-fabric-admin/.default"

    log_level: str = "INFO"
    otlp_endpoint: str | None = None

    @model_validator(mode="after")
    def _validate(self) -> Settings:
        if self.dev_ephemeral_keys:
            if self.environment == "production":
                raise ValueError("dev_ephemeral_keys cannot be used in production")
        else:
            missing = [
                name
                for name, value in (
                    ("ACP_AUDIT_KEY_FILE", self.audit_key_file),
                    ("ACP_BUNDLE_KEY_FILE", self.bundle_key_file),
                )
                if value is None
            ]
            if missing:
                raise ValueError(f"signing configuration incomplete: {missing}")
        if not self.managed_namespaces:
            raise ValueError("at least one managed namespace is required")
        if self.fabric_url is not None:
            required = {
                "ACP_FABRIC_TRUST_DOMAIN": self.fabric_trust_domain,
                "ACP_CLUSTER_OIDC_ISSUER": self.cluster_oidc_issuer,
                "ACP_FABRIC_ADMIN_TOKEN_URL": self.fabric_admin_token_url,
                "ACP_FABRIC_ADMIN_CLIENT_ID": self.fabric_admin_client_id,
                "ACP_FABRIC_ADMIN_CLIENT_SECRET": self.fabric_admin_client_secret,
            }
            absent = sorted(k for k, v in required.items() if v is None)
            if absent:
                raise ValueError(f"identity fabric integration incomplete: {absent}")
        if self.kube_mode == "kubeconfig" and not self.kubeconfig_path:
            raise ValueError("ACP_KUBECONFIG_PATH is required when ACP_KUBE_MODE=kubeconfig")
        return self

    @property
    def public_url_str(self) -> str:
        return str(self.public_url).rstrip("/")

    @property
    def fabric_url_str(self) -> str | None:
        return str(self.fabric_url).rstrip("/") if self.fabric_url else None
