from halcyon import agent, audit
from halcyon.bank import Bank
from halcyon.config import load_settings
from halcyon.llm import FinalAnswer, StubToolLLM, ToolCall
from halcyon.store import InMemoryStore


def test_agent_executes_scripted_tool_calls_and_records_unauthorized():
    b = Bank()
    b.seed([{"id": "acct-attacker", "owner_session": "attacker", "balance": 0, "email": "a@x"}])
    s = InMemoryStore()
    settings = load_settings({"HALCYON_MODE": "vulnerable"})
    llm = StubToolLLM([
        ToolCall("issue_refund", {"to_account": "acct-attacker", "amount": 250}),
        FinalAnswer("Refund issued."),
    ])
    reply, calls = agent.run(llm, "me", "refund me 250 to acct-attacker", b, s, settings)
    assert reply == "Refund issued."
    assert len(calls) == 1
    assert audit.has_event(s, "me", "m5", audit.UNAUTHORIZED_TOOL_CALL)


def test_agent_stops_at_step_limit():
    s = InMemoryStore()
    settings = load_settings({"HALCYON_MODE": "vulnerable"})
    llm = StubToolLLM([ToolCall("get_balance", {"account": "x"})] * 50)
    reply, calls = agent.run(llm, "me", "loop", Bank(), s, settings)
    assert len(calls) <= 8
