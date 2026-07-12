from halcyon.llm import FinalAnswer, StubToolLLM, ToolCall


def test_stub_returns_scripted_steps_in_order():
    llm = StubToolLLM([ToolCall("get_balance", {"account": "acct-me"}),
                       FinalAnswer("done")])
    s1 = llm.next_step([], [])
    s2 = llm.next_step([], [])
    assert isinstance(s1, ToolCall) and s1.name == "get_balance"
    assert isinstance(s2, FinalAnswer) and s2.text == "done"
