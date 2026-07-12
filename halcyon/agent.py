from halcyon import tools as tools_mod
from halcyon.bank import Bank
from halcyon.config import Settings
from halcyon.llm import FinalAnswer, ToolCall, ToolLLM
from halcyon.store import Store

MAX_STEPS = 8


def run(llm: ToolLLM, session_id: str, message: str, bank: Bank,
        store: Store, settings: Settings, module: str = "m5") -> tuple[str, list]:
    messages: list[dict] = [{"role": "user", "content": message}]
    calls: list = []
    for _ in range(MAX_STEPS):
        step = llm.next_step(messages, tools_mod.SCHEMAS)
        if isinstance(step, FinalAnswer):
            return step.text, calls
        assert isinstance(step, ToolCall)
        result = tools_mod.execute(step.name, session_id, step.args, bank, store, settings)
        calls.append((step.name, step.args, result))
        messages.append({"role": "assistant",
                         "content": f"call {step.name}({step.args})"})
        messages.append({"role": "tool", "content": result})
    return "step limit reached", calls
