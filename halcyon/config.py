from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from halcyon.session_state import SessionState

_TRUE = {"1", "true", "on", "yes"}


def _flag(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUE


@dataclass(frozen=True)
class Settings:
    mode: str
    sec_system_prompt_hardening: bool
    sec_input_filter: bool
    sec_output_encoding: bool
    sec_rag_provenance: bool
    sec_artifact_verification: bool
    sec_tool_scope_enforcement: bool
    sec_mcp_desc_pinning: bool
    sec_mcp_token_scoping: bool
    sec_inter_agent_auth: bool
    sec_guardrails: bool
    sec_secret_scanning: bool
    ollama_url: str
    ollama_model: str
    database_url: str
    default_provider: str
    expose_openapi: bool


def load_settings(env: Mapping[str, str]) -> Settings:
    mode = env.get("HALCYON_MODE", "vulnerable").strip().lower()
    if mode not in ("vulnerable", "secure"):
        raise ValueError(
            f"HALCYON_MODE must be 'vulnerable' or 'secure', got {mode!r}"
        )
    secure = mode == "secure"
    return Settings(
        mode=mode,
        sec_system_prompt_hardening=_flag(env, "SEC_SYSTEM_PROMPT_HARDENING", secure),
        sec_input_filter=_flag(env, "SEC_INPUT_FILTER", secure),
        sec_output_encoding=_flag(env, "SEC_OUTPUT_ENCODING", secure),
        sec_rag_provenance=_flag(env, "SEC_RAG_PROVENANCE", secure),
        sec_artifact_verification=_flag(env, "SEC_ARTIFACT_VERIFICATION", secure),
        sec_tool_scope_enforcement=_flag(env, "SEC_TOOL_SCOPE_ENFORCEMENT", secure),
        sec_mcp_desc_pinning=_flag(env, "SEC_MCP_DESC_PINNING", secure),
        sec_mcp_token_scoping=_flag(env, "SEC_MCP_TOKEN_SCOPING", secure),
        sec_inter_agent_auth=_flag(env, "SEC_INTER_AGENT_AUTH", secure),
        sec_guardrails=_flag(env, "SEC_GUARDRAILS", secure),
        sec_secret_scanning=_flag(env, "SEC_SECRET_SCANNING", secure),
        ollama_url=env.get("OLLAMA_URL", "http://localhost:11434"),
        ollama_model=env.get("OLLAMA_MODEL", "llama3.1:8b"),
        database_url=env.get("DATABASE_URL", ""),
        default_provider=env.get("DEFAULT_PROVIDER", "local"),
        expose_openapi=_flag(env, "EIGER_EXPOSE_OPENAPI", False),
    )


MODULE_FLAGS: dict[str, tuple[str, ...]] = {
    "m1": ("sec_system_prompt_hardening", "sec_input_filter"),
    "m2": ("sec_output_encoding", "sec_system_prompt_hardening"),
    "m3": ("sec_rag_provenance",),
    "m5": ("sec_tool_scope_enforcement",),
    "m6": ("sec_mcp_desc_pinning", "sec_mcp_token_scoping"),
    "m7": ("sec_inter_agent_auth",),
    "m8": ("sec_guardrails",),
}


def effective_settings(
    base: Settings, session_state: "SessionState", session_id: str, module: str
) -> Settings:
    """Overlay a session's per-module L1/L2 level onto the base Settings.

    Returns base unchanged when the session has no override for `module` (or the
    module has no runtime guard). L2 forces that module's flags on; L1 forces them off.
    """
    level = session_state.get_level(session_id, module)
    flags = MODULE_FLAGS.get(module)
    if level is None or not flags:
        return base
    value = level == "L2"
    changes: dict[str, Any] = {name: value for name in flags}
    return replace(base, **changes)
