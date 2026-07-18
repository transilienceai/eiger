from halcyon import guards


def test_sign_verify_roundtrip():
    key = "k1"
    content = {"decision": "approved", "amount": 5000}
    sig = guards.sign_message(content, key)
    assert guards.verify_message(content, sig, key) is True


def test_verify_rejects_tampered_content():
    key = "k1"
    sig = guards.sign_message({"decision": "denied"}, key)
    assert guards.verify_message({"decision": "approved"}, sig, key) is False


def test_verify_rejects_wrong_key():
    sig = guards.sign_message({"decision": "approved"}, "k1")
    assert guards.verify_message({"decision": "approved"}, sig, "k2") is False


def test_sign_is_key_order_independent():
    key = "k1"
    assert guards.sign_message({"a": 1, "b": 2}, key) == guards.sign_message({"b": 2, "a": 1}, key)
