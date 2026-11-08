"""Version 2 reporting wire contract. Only registered product metadata is accepted."""
from __future__ import annotations

from datetime import date, timezone
from typing import Annotated, Literal

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

Identifier = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
Version = Annotated[str, Field(max_length=32, pattern=r"^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:(?:a|b|rc)[0-9]{1,4})?$")]
Timestamp = Annotated[AwareDatetime, AfterValidator(lambda v: v.astimezone(timezone.utc))]
Agent = Literal["claude-code", "cursor", "codex", "gemini-cli", "vscode", "antigravity", "qwen-code",
                "factory-droid", "kiro", "mcp", "http", "custom", "other"]
Integration = Literal["builtin", "github", "gitlab", "postgres", "supabase", "stripe", "gmail", "slack",
                      "atlassian", "kubernetes", "notion", "linear", "custom", "other"]
Mode = Literal["observe", "enforce"]
ErrorCode = Literal["none", "unknown", "network", "permission", "unsupported", "configuration", "timeout"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    @field_validator("schema_version", "catalogue_version", mode="before", check_fields=False)
    @classmethod
    def integer_version(cls, value):
        if type(value) is not int:
            raise ValueError("version must be an integer")
        return value


class SetupProperties(StrictModel):
    installer: Literal["pip", "pipx", "uv", "docker", "native", "source", "other"]
    os_family: Literal["macos", "linux", "windows", "other"]
    error_code: ErrorCode = "none"


class ConnectionProperties(StrictModel):
    agent_family: Agent
    method: Literal["hook", "mcp", "http"]
    error_code: ErrorCode = "none"


class ActivityProperties(StrictModel):
    agent_family: Agent
    mode: Mode


class FeatureProperties(StrictModel):
    feature: Literal["approval", "rejection", "escalation", "undo", "sequences", "stop", "resume", "steering",
                     "evidence", "report", "rule_edit", "budgets", "notifications"]
    outcome: Literal["success", "failure"]
    channel: Literal["cli", "dashboard", "phone", "slack", "teams", "email", "telegram", "http"]


class ModeProperties(StrictModel):
    previous: Mode
    current: Mode


class VersionProperties(StrictModel):
    previous: Version
    current: Version


class EventBase(StrictModel):
    event_id: Identifier
    occurred_at: Timestamp
    recorded_at: Timestamp
    catalogue_version: Literal[1] = 1
    emitter_version: Version


class SetupEvent(EventBase):
    event_name: Literal["setup_started", "setup_completed", "setup_failed"]
    properties: SetupProperties


class ConnectionEvent(EventBase):
    event_name: Literal["agent_connected", "agent_connection_failed", "agent_disconnected"]
    properties: ConnectionProperties


class ActivityEvent(EventBase):
    event_name: Literal["first_action_checked", "installation_active_day"]
    properties: ActivityProperties


class FeatureEvent(EventBase):
    event_name: Literal["feature_used"]
    properties: FeatureProperties


class ModeEvent(EventBase):
    event_name: Literal["mode_changed"]
    properties: ModeProperties


class VersionEvent(EventBase):
    event_name: Literal["product_version_changed"]
    properties: VersionProperties


Event = Annotated[SetupEvent | ConnectionEvent | ActivityEvent | FeatureEvent | ModeEvent | VersionEvent,
                  Field(discriminator="event_name")]


class Rollup(StrictModel):
    day: date
    agent_family: Agent
    integration_family: Integration
    tool_category: Literal["shell", "read", "edit", "database", "deploy", "payment", "communication", "other"]
    mode: Mode
    kind: Literal["initial_decision", "review_outcome", "execution_outcome"]
    outcome: Literal["allow", "review", "deny", "approved", "rejected", "timed_out", "completed", "failed"]
    would_decision: Literal["none", "allow", "review", "deny"] = "none"
    revision: Annotated[int, Field(ge=1, le=2**63 - 1)]
    count: Annotated[int, Field(ge=0, le=10**12)]

    @model_validator(mode="after")
    def coherent_dimensions(self):
        outcomes = {"initial_decision": {"allow", "review", "deny"},
                    "review_outcome": {"approved", "rejected", "timed_out"},
                    "execution_outcome": {"completed", "failed"}}
        if self.outcome not in outcomes[self.kind]:
            raise ValueError("outcome does not belong to this rollup kind")
        if self.would_decision != "none" and (self.mode != "observe" or self.kind != "initial_decision"):
            raise ValueError("would-decision requires an observed initial decision")
        return self


class Batch(StrictModel):
    schema_version: Literal[2]
    batch_id: Identifier
    installation_id: Identifier
    dataset_epoch: Identifier
    sent_at: Timestamp
    product_version: Version
    events: Annotated[list[Event], Field(max_length=100)] = Field(default_factory=list)
    rollups: Annotated[list[Rollup], Field(max_length=200)] = Field(default_factory=list)


class Alias(StrictModel):
    kind: Literal["cli", "pilot"]
    alias: Annotated[str, Field(max_length=36, pattern=r"^(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$")]


class Invitation(StrictModel):
    installation_id: Identifier
    pilot_code: Annotated[str, Field(pattern=r"^[a-z0-9-]{3,40}$")]
    aliases: Annotated[list[Alias], Field(max_length=2)] = Field(default_factory=list)


class Enrollment(StrictModel):
    schema_version: Literal[2]
    installation_id: Identifier
    community_code: Annotated[str, Field(max_length=40)] | None = None
    invitation_token: Annotated[str, Field(pattern=r"^sbi_[A-Za-z0-9_-]{43}$")] | None = None

    @model_validator(mode="after")
    def one_enrollment_method(self):
        if (self.community_code is None) == (self.invitation_token is None):
            raise ValueError("choose one enrollment method")
        return self
