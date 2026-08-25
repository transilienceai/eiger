import os
import secrets
import time
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel

from halcyon import (
    agent, audit, bank_fixtures, capstone, dispute_pipeline, guards, halo, kb_fixtures,
    learn_content, m4_answers, rag, source_browser,
)
from halcyon.bank import Bank
from halcyon.config import MODULE_FLAGS, Settings, effective_settings
from halcyon.kb import KnowledgeBase
from halcyon.session_state import InMemorySessionState, SessionState
from halcyon.llm import LLM, OllamaProvider, ToolLLM
from halcyon.store import Store
from halcyon.validators import m1, m2, m3, m4, m5, m6, m7, m8

if TYPE_CHECKING:
    from halcyon.mcp_host import MCPHost

LLMFactory = Callable[[str | None, str | None, str | None], LLM]
ToolLLMFactory = Callable[[str | None, str | None, str | None], ToolLLM]
MCPHostFactory = Callable[[str, Settings], AbstractAsyncContextManager["MCPHost"]]


class ChatIn(BaseModel):
    session_id: str
    message: str
    provider: str | None = None
    model: str | None = None
    api_key: str | None = None


class ResetIn(BaseModel):
    session_id: str


class ProfileIn(BaseModel):
    session_id: str
    display_name: str


class KbIn(BaseModel):
    session_id: str
    text: str


class AskIn(BaseModel):
    session_id: str
    query: str


class SubmitIn(BaseModel):
    session_id: str
    finding_type: str
    value: str


class AgentIn(BaseModel):
    session_id: str
    message: str
    provider: str | None = None
    model: str | None = None
    api_key: str | None = None


class DisputeIn(BaseModel):
    session_id: str
    dispute_text: str
    account: str
    amount: int
    provider: str | None = None
    model: str | None = None
    api_key: str | None = None


class LevelIn(BaseModel):
    session_id: str
    module: str
    level: str


class ConfigIn(BaseModel):
    session_id: str
    provider: str
    model: str | None = None
    api_key: str | None = None


_VALIDATORS = {
    "m1": m1.validate,
    "m2": m2.validate,
    "m3": m3.validate,
    "m4": m4.validate,
    "m5": m5.validate,
    "m6": m6.validate,
    "m7": m7.validate,
    "m8": m8.validate,
}


def create_app(
    store: Store,
    settings: Settings,
    llm_factory: LLMFactory,
    kb_for: Callable[[str], KnowledgeBase],
    bank_for: Callable[[str], Bank],
    tool_llm_factory: ToolLLMFactory,
    mcp_host_factory: MCPHostFactory,
    session_state: SessionState | None = None,
) -> FastAPI:
    if settings.expose_openapi:
        app = FastAPI(title="Eiger")
    else:
        app = FastAPI(title="Eiger", openapi_url=None, docs_url=None, redoc_url=None)

    import psycopg
    import psycopg_pool
    from fastapi.responses import JSONResponse

    @app.exception_handler(psycopg.OperationalError)
    @app.exception_handler(psycopg_pool.PoolTimeout)
    async def _db_busy(_request, _exc):  # type: ignore[no-untyped-def]
        return JSONResponse(
            status_code=503,
            content={"error": "database busy, please retry"},
            headers={"Retry-After": "1"},
        )

    sess: SessionState = session_state or InMemorySessionState()

    def _mcfg(
        session_id: str, p: str | None = None, m: str | None = None, k: str | None = None
    ) -> tuple[str | None, str | None, str | None]:
        """Resolve model config: explicit request values win, else the session's saved config."""
        cfg = sess.get_model_cfg(session_id)
        return (
            p or cfg.get("provider") or None,
            m or cfg.get("model") or None,
            k or cfg.get("api_key") or None,
        )

    from starlette.requests import Request

    @app.middleware("http")
    async def _csp(request: Request, call_next):
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce
        resp = await call_next(request)
        if settings.sec_output_encoding:
            resp.headers["Content-Security-Policy"] = (
                f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; img-src 'self' data:"
            )
        return resp

    templates = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(),
    )

    _ollama_probe: dict[str, float | bool] = {"ts": 0.0, "up": False}

    def _ollama_up() -> bool:
        now = time.monotonic()
        if now - _ollama_probe["ts"] > 5.0:
            _ollama_probe["up"] = OllamaProvider(
                settings.ollama_url, settings.ollama_model
            ).ping()
            _ollama_probe["ts"] = now
        return bool(_ollama_probe["up"])

    _mcp_core_url = os.environ.get("MCP_CORE_URL")
    _mcp_crm_url = os.environ.get("MCP_CRM_URL")
    _mcp_probe: dict[str, float | bool] = {"ts": 0.0, "up": False}

    def _mcp_up(core_url: str, crm_url: str) -> bool:
        now = time.monotonic()
        if now - _mcp_probe["ts"] > 5.0:
            up = True
            for url in (core_url, crm_url):
                try:
                    httpx.get(url, timeout=2.0)
                except Exception:
                    # Any probe failure (unreachable, timeout, or a malformed
                    # MCP_*_URL) degrades to "down" — /health must never 500.
                    up = False
                    break
            _mcp_probe["up"] = up
            _mcp_probe["ts"] = now
        return bool(_mcp_probe["up"])

    def _mcp_status() -> str:
        if not (_mcp_core_url and _mcp_crm_url):
            return "in-process"
        return "up" if _mcp_up(_mcp_core_url, _mcp_crm_url) else "down"

    @app.get("/health")
    def health() -> dict:
        ollama = _ollama_up()
        return {
            "status": "ok",
            "mode": settings.mode,
            "ollama": "up" if ollama else "down",
            "db": "up" if store.ping() else "down",
            "mcp": _mcp_status(),
        }

    @app.post("/api/chat")
    def chat(body: ChatIn) -> dict:
        llm = llm_factory(*_mcfg(body.session_id, body.provider, body.model, body.api_key))
        eff = effective_settings(settings, sess, body.session_id, "m1")
        history = sess.get_history(body.session_id, "chat")
        reply = halo.handle_turn(
            store, llm, eff, body.session_id, body.message, history=history
        )
        sess.append_turn(body.session_id, "chat", body.message, reply)
        return {"reply": reply}

    @app.get("/validate/{module}")
    def validate(module: str, session: str) -> dict:
        # placeholder between S10's removal and S11's wiring (Task 9)
        if module == "chain":
            return {"core": "fail", "stages": {}}
        validator = _VALIDATORS.get(module)
        if validator is None:
            return {"error": f"unknown module {module}"}
        return validator(store, session)

    @app.post("/reset/{module}")
    def reset(module: str, body: ResetIn) -> dict:
        store.write_reset_marker(body.session_id, module)
        if module == "chain":
            store.write_reset_marker(body.session_id, "chain")
            return {"status": "reset", "module": "chain"}
        if module in ("m1", "m2"):
            sess.clear_history(body.session_id, "chat")
        if module == "m3":
            kb = kb_for(body.session_id)
            kb.clear()
            kb.seed(kb_fixtures.SEED)
        if module in ("m5", "m6", "m7"):
            bank = bank_for(body.session_id)
            bank.clear()
            bank.seed(bank_fixtures.seed_for(body.session_id))
        return {"status": "reset", "module": module}

    @app.post("/api/kb")
    def add_kb(body: KbIn) -> dict:
        kb = kb_for(body.session_id)
        kb.add(body.text, "user", owner_session=body.session_id)
        return {"status": "ok"}

    @app.post("/api/ask")
    def ask(body: AskIn) -> dict:
        eff = effective_settings(settings, sess, body.session_id, "m3")
        kb = kb_for(body.session_id)
        reply, _ = rag.answer(
            kb, llm_factory(*_mcfg(body.session_id)), store, eff, body.session_id, body.query
        )
        return {"reply": reply}

    @app.get("/", response_class=HTMLResponse)
    def root() -> str:
        ollama = _ollama_up()
        return templates.get_template("reach.html").render(
            ollama=ollama, db=store.ping(), mode=settings.mode
        )

    @app.get("/chat", response_class=HTMLResponse)
    def chat_page(request: Request, session: str = "dev") -> str:
        name = store.get_profile(session)
        eff = effective_settings(settings, sess, session, "m2")
        return templates.get_template("chat.html").render(
            output_encoding="on" if eff.sec_output_encoding else "off",
            display_name_html=guards.encode_output(name, eff),
            nonce=request.state.csp_nonce,
            mode=settings.mode,
            learn=learn_content.LEARN,
        )

    from fastapi.responses import Response

    _GIF = bytes.fromhex(
        "47494638396101000100800000ffffff00000021f90401000000002c00000000010001000002024401003b"
    )

    @app.post("/api/profile")
    def set_profile(body: ProfileIn) -> dict:
        store.set_profile(body.session_id, body.display_name)
        return {"status": "ok"}

    @app.get("/beacon/xss")
    def beacon(session: str) -> Response:
        audit.record(store, session, "m2", audit.XSS_BEACON, session)
        return Response(content=_GIF, media_type="image/gif")

    @app.post("/api/agent")
    def agent_endpoint(body: AgentIn) -> dict:
        tool_llm = tool_llm_factory(*_mcfg(body.session_id, body.provider, body.model, body.api_key))
        eff = effective_settings(settings, sess, body.session_id, "m5")
        bank = bank_for(body.session_id)
        reply, calls = agent.run(tool_llm, body.session_id, body.message, bank, store, eff)
        return {"reply": reply, "tool_calls": [{"name": n, "args": a} for n, a, _ in calls]}

    @app.post("/api/mcp-agent")
    async def mcp_agent(body: AgentIn) -> dict:
        tool_llm = tool_llm_factory(*_mcfg(body.session_id, body.provider, body.model, body.api_key))
        # M6 guards read their flags from the MCPHost's settings. The host is built per
        # request, so passing this session's effective settings makes the L1/L2 flip
        # per-session and restart-free, like every other module.
        eff = effective_settings(settings, sess, body.session_id, "m6")
        async with mcp_host_factory(body.session_id, eff) as host:
            reply, calls = await agent.run_mcp(
                tool_llm, body.session_id, body.message, host, store, eff
            )
        return {"reply": reply, "tool_calls": [{"name": n, "args": a} for n, a, _ in calls]}

    @app.post("/api/dispute")
    def dispute_endpoint(body: DisputeIn) -> dict:
        tool_llm = tool_llm_factory(*_mcfg(body.session_id, body.provider, body.model, body.api_key))
        eff = effective_settings(settings, sess, body.session_id, "m7")
        bank = bank_for(body.session_id)
        decision, transcript = dispute_pipeline.run_dispute(
            tool_llm, body.session_id,
            {"account": body.account, "amount": body.amount, "dispute_text": body.dispute_text},
            bank, store, eff)
        return {
            "decision": decision,
            "transcript": [{"from": m["signer"], "content": m["content"]} for m in transcript],
        }

    @app.post("/api/guarded-chat")
    def guarded_chat(body: ChatIn) -> dict:
        llm = llm_factory(*_mcfg(body.session_id, body.provider, body.model, body.api_key))
        eff = effective_settings(settings, sess, body.session_id, "m8")
        reply = halo.guarded_turn(store, llm, eff, body.session_id, body.message)
        return {"reply": reply}

    @app.get("/capstone")
    def capstone_view(session: str) -> dict:
        return capstone.residual_risk(store, session)

    @app.get("/board")
    def board_view() -> dict:
        return capstone.board(store)

    @app.post("/api/level")
    def set_level(body: LevelIn) -> dict:
        if body.level not in ("L1", "L2"):
            return {"error": "level must be L1 or L2"}
        if body.module not in MODULE_FLAGS:
            return {"error": f"unknown module {body.module}"}
        sess.set_level(body.session_id, body.module, body.level)
        return {"status": "ok", "module": body.module, "level": body.level}

    @app.get("/api/level")
    def get_levels(session: str) -> dict:
        return sess.get_levels(session)

    @app.post("/api/config")
    def set_config(body: ConfigIn) -> dict:
        sess.set_model_cfg(
            body.session_id, body.provider, body.model or "", body.api_key or ""
        )
        return {"status": "ok", "provider": body.provider, "model": body.model or ""}

    @app.get("/api/config")
    def get_config(session: str) -> dict:
        cfg = sess.get_model_cfg(session)
        # never return the api_key
        return {"provider": cfg.get("provider", ""), "model": cfg.get("model", "")}

    import io
    import zipfile

    _LABS_M4 = Path(__file__).parent.parent / "labs" / "m4"

    # This is plain text shown to the participant, not code that loads pickle data —
    # it warns them NOT to unpickle the bundled artifact and to scan/hash it instead.
    _M4_README = (
        "# M4 supply-chain audit bundle\n\n"
        "1. SCAN the artifact — do NOT run/unpickle it:\n"
        "   python scan_artifact.py artifacts/<file>\n"
        "   (no Python? hash it: shasum -a 256 artifacts/<file>)\n"
        "   Submit the poisoned artifact's sha256 as the malicious artifact.\n\n"
        "2. AUDIT the dependencies against a CVE database:\n"
        "   pip-audit -r requirements-vulnerable.txt\n"
        "   (or look each pin up on osv.dev / NVD). Submit the flagged pin\n"
        "   (name==version) as the vulnerable dependency.\n\n"
        "WARNING: the artifact is a real malicious pickle. Scan or hash it only; "
        "loading it with pickle.load executes attacker code on your machine.\n"
    )

    @app.get("/api/m4/bundle")
    def m4_bundle() -> Response:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for art in sorted((_LABS_M4 / "artifacts").glob("*")):
                if art.is_file():
                    z.write(art, f"artifacts/{art.name}")
            req = _LABS_M4 / "requirements-vulnerable.txt"
            if req.exists():
                z.write(req, "requirements-vulnerable.txt")
            z.write(Path(__file__).parent / "scan_artifact.py", "scan_artifact.py")
            z.writestr("README.md", _M4_README)
        return Response(content=buf.getvalue(), media_type="application/zip",
                        headers={"Content-Disposition": "attachment; filename=eiger-m4-audit.zip"})

    @app.post("/submit/m4")
    def submit_m4(body: SubmitIn) -> dict:
        correct = False
        if body.finding_type == "malicious_artifact":
            correct = m4_answers.normalize_hash(body.value) == m4_answers.POISONED_ARTIFACT_SHA256
            if correct:
                audit.record(store, body.session_id, "m4",
                             audit.MALICIOUS_ARTIFACT_IDENTIFIED, body.session_id)
        elif body.finding_type == "vulnerable_dependency":
            correct = m4_answers.normalize_package(body.value) == m4_answers.VULNERABLE_PACKAGE
            if correct:
                audit.record(store, body.session_id, "m4",
                             audit.VULNERABLE_DEPENDENCY_IDENTIFIED, body.session_id)
        return {"correct": correct}

    @app.get("/source/tree")
    def source_tree(session: str) -> dict:
        return {"tree": source_browser.tree()}

    @app.get("/source/blob")
    def source_blob(session: str, path: str) -> dict:
        # placeholder ci_token between S10's removal and S11's wiring (Task 9)
        ci_token = ""
        content = guards.scrub_secrets(source_browser.blob(path, ci_token),
                                       ci_token, settings)
        if path == source_browser.LEAK_PATH and ci_token and ci_token in content:
            audit.record(store, session, "chain", audit.INGEST_KEY_ACCEPTED,
                         session, {"path": path})
        return {"path": path, "content": content}

    return app
