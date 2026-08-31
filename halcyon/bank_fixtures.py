def seed_for(session_id: str) -> list[dict]:
    return [
        {"id": "acct-me", "owner_session": session_id, "balance": 1000, "email": "me@eiger.test"},
        {"id": "acct-victim", "owner_session": "victim", "balance": 5000, "email": "victim@eiger.test"},
        {"id": "acct-attacker", "owner_session": "attacker", "balance": 0, "email": "attacker@evil.test"},
    ]
