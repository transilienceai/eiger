from collections.abc import Callable

from fastapi import FastAPI
from pydantic import BaseModel

from halcyon import halo
from halcyon.config import Settings
from halcyon.llm import LLM
from halcyon.store import Store
from halcyon.validators import m1

LLMFactory = Callable[[str | None, str | None, str | None], LLM]


class ChatIn(BaseModel):
    session_id: str
    message: str
    provider: str | None = None
    model: str | None = None
    api_key: str | None = None


class ResetIn(BaseModel):
    session_id: str


_VALIDATORS = {"m1": m1.validate}


def create_app(store: Store, settings: Settings, llm_factory: LLMFactory) -> FastAPI:
    app = FastAPI(title="Halcyon")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "mode": settings.mode}

    @app.post("/api/chat")
    def chat(body: ChatIn) -> dict:
        llm = llm_factory(body.provider, body.model, body.api_key)
        reply = halo.handle_turn(store, llm, settings, body.session_id, body.message)
        return {"reply": reply}

    @app.get("/validate/{module}")
    def validate(module: str, session: str) -> dict:
        validator = _VALIDATORS.get(module)
        if validator is None:
            return {"error": f"unknown module {module}"}
        return validator(store, session)

    @app.post("/reset/{module}")
    def reset(module: str, body: ResetIn) -> dict:
        store.write_reset_marker(body.session_id, module)
        return {"status": "reset", "module": module}

    return app
