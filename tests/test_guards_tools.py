from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.guards import authorize_tool_call


def _seed_bank() -> Bank:
    b = Bank()
    b.seed(
        [
            {
                "id": "acct-me",
                "owner_session": "me",
                "balance": 1000,
                "email": "me@x",
            },
            {
                "id": "acct-victim",
                "owner_session": "victim",
                "balance": 5000,
                "email": "v@x",
            },
        ]
    )
    return b


def test_enforce_off_always_returns_true():
    b = _seed_bank()
    settings = load_settings({"HALCYON_MODE": "vulnerable"})
    # Money tool to unowned account
    assert (
        authorize_tool_call("me", "transfer_funds", {"to_account": "acct-victim", "amount": 500}, b, settings)
        is True
    )
    # Update email on unowned account
    assert (
        authorize_tool_call("me", "update_email", {"account": "acct-victim", "email": "new@x"}, b, settings)
        is True
    )
    # Read-only tool
    assert authorize_tool_call("me", "get_balance", {"account": "acct-victim"}, b, settings) is True


def test_enforce_on_money_tool_to_owned_account_allowed():
    b = _seed_bank()
    settings = load_settings({"HALCYON_MODE": "secure"})
    assert (
        authorize_tool_call("me", "transfer_funds", {"to_account": "acct-me", "amount": 500}, b, settings)
        is True
    )
    assert (
        authorize_tool_call("me", "issue_refund", {"to_account": "acct-me", "amount": 250}, b, settings)
        is True
    )


def test_enforce_on_money_tool_to_unowned_account_denied():
    b = _seed_bank()
    settings = load_settings({"HALCYON_MODE": "secure"})
    assert (
        authorize_tool_call("me", "transfer_funds", {"to_account": "acct-victim", "amount": 500}, b, settings)
        is False
    )
    assert (
        authorize_tool_call("me", "issue_refund", {"to_account": "acct-victim", "amount": 250}, b, settings)
        is False
    )


def test_enforce_on_update_email_owned_account_allowed():
    b = _seed_bank()
    settings = load_settings({"HALCYON_MODE": "secure"})
    assert (
        authorize_tool_call("me", "update_email", {"account": "acct-me", "email": "new@x"}, b, settings)
        is True
    )


def test_enforce_on_update_email_unowned_account_denied():
    b = _seed_bank()
    settings = load_settings({"HALCYON_MODE": "secure"})
    assert (
        authorize_tool_call("me", "update_email", {"account": "acct-victim", "email": "new@x"}, b, settings)
        is False
    )


def test_enforce_on_readonly_tool_always_allowed():
    b = _seed_bank()
    settings = load_settings({"HALCYON_MODE": "secure"})
    assert authorize_tool_call("me", "get_balance", {"account": "acct-victim"}, b, settings) is True
    assert (
        authorize_tool_call("me", "get_account_details", {"account": "acct-victim"}, b, settings)
        is True
    )
