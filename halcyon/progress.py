from halcyon.store import Store


def read(store: Store, session_id: str, module: str) -> tuple[bool, bool]:
    return store.get_progress(session_id, module)


def mark(store: Store, session_id: str, module: str, core: bool, stretch: bool) -> None:
    store.upsert_progress(session_id, module, core, stretch)
