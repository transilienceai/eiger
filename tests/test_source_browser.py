from halcyon import guards, source_browser
from halcyon.config import load_settings


def test_tree_is_deterministic_and_contains_leak_path():
    t1 = source_browser.tree()
    t2 = source_browser.tree()
    assert t1 == t2
    assert source_browser.LEAK_PATH in t1


def test_log_points_at_the_reverted_leak():
    log = source_browser.log()
    assert any(source_browser.LEAK_COMMIT == c["id"] for c in log)
    joined = " ".join(c["message"].lower() for c in log)
    assert "revert" in joined  # the story that lures the participant to git history


def test_leak_blob_embeds_session_token_others_do_not():
    tok = "SECRET-TOKEN-XYZ"
    leak = source_browser.blob(source_browser.LEAK_PATH, tok)
    assert tok in leak
    readme = source_browser.blob("README.md", tok)
    assert tok not in readme
    assert source_browser.blob("does/not/exist", tok) == ""


def test_scrub_secrets_only_in_secure_mode():
    tok = "SECRET-TOKEN-XYZ"
    text = f"CI_TOKEN={tok}\n"
    vuln = load_settings({"HALCYON_MODE": "vulnerable"})
    sec = load_settings({"HALCYON_MODE": "secure"})
    assert guards.scrub_secrets(text, tok, vuln) == text          # untouched
    scrubbed = guards.scrub_secrets(text, tok, sec)
    assert tok not in scrubbed and "REDACTED" in scrubbed
    # empty secret is a no-op even in secure mode
    assert guards.scrub_secrets(text, "", sec) == text
