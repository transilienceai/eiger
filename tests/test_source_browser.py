from halcyon import guards, source_browser
from halcyon.config import load_settings


def test_tree_has_enough_files_to_require_reading():
    t = source_browser.tree()
    assert len(t) >= 8
    assert source_browser.LEAK_PATH in t
    assert source_browser.INGEST_PATH in t


def test_key_and_route_live_in_different_files():
    key = "KEY-XYZ"
    env = source_browser.blob(source_browser.LEAK_PATH, key)
    ci = source_browser.blob(source_browser.INGEST_PATH, key)
    assert key in env
    assert source_browser.INGEST_ROUTE not in env, "reading one file must not be enough"
    assert source_browser.INGEST_ROUTE in ci
    assert key not in ci


def test_decoys_look_like_credentials_but_are_not_the_key():
    key = "KEY-XYZ"
    decoys = [p for p in source_browser.tree()
              if p not in (source_browser.LEAK_PATH, source_browser.INGEST_PATH)]
    blobs = [source_browser.blob(p, key) for p in decoys]
    assert any("TOKEN" in b or "SECRET" in b or "KEY" in b for b in blobs)
    assert all(key not in b for b in blobs)


def test_unknown_path_returns_empty():
    assert source_browser.blob("does/not/exist", "K") == ""


def test_scrub_secrets_only_in_secure_mode():
    tok = "KEY-XYZ"
    text = f"INGEST_KEY={tok}\n"
    vuln = load_settings({"HALCYON_MODE": "vulnerable"})
    sec = load_settings({"HALCYON_MODE": "secure"})
    assert guards.scrub_secrets(text, tok, vuln) == text
    scrubbed = guards.scrub_secrets(text, tok, sec)
    assert tok not in scrubbed and "REDACTED" in scrubbed
    assert guards.scrub_secrets(text, "", sec) == text
