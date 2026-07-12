import hashlib
import pickletools
import sys
from pathlib import Path

_DANGEROUS_MODULES = {"os", "subprocess", "sys", "builtins", "posix", "nt", "shutil",
                      "socket", "pty", "commands", "importlib"}


def scan(path: str | Path) -> dict:
    data = Path(path).read_bytes()
    dangerous: list[str] = []
    recent: list[str] = []  # recent string operands, for STACK_GLOBAL resolution
    note: str | None = None
    try:
        for opcode, arg, _pos in pickletools.genops(data):
            name = opcode.name
            if name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "SHORT_BINSTRING",
                        "BINSTRING", "STRING") and isinstance(arg, str):
                recent.append(arg)
                recent[:] = recent[-2:]
            elif name == "GLOBAL" and isinstance(arg, str):
                mod = arg.split(" ")[0].split(".")[0]
                if mod in _DANGEROUS_MODULES:
                    dangerous.append(f"GLOBAL -> {arg}")
            elif name == "STACK_GLOBAL":
                mod = (recent[0] if recent else "").split(".")[0]
                if mod in _DANGEROUS_MODULES:
                    dangerous.append(f"STACK_GLOBAL -> {' '.join(recent)}")
            elif name == "REDUCE":
                dangerous.append("REDUCE (callable invocation)")
    except Exception as exc:  # noqa: BLE001 - the bytes are not a valid pickle stream
        # Not a parseable pickle (e.g. a genuine .safetensors) — that is NOT a malicious
        # pickle. Record it as a note; only real dangerous opcodes mark a file malicious.
        note = f"not a valid pickle stream: {exc}"
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "dangerous": dangerous,
        "malicious": bool(dangerous),
        "note": note,
    }


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: python -m halcyon.scan_artifact <file>...")
        return 2
    for path in argv:
        r = scan(path)
        verdict = "MALICIOUS" if r["malicious"] else "clean"
        print(f"{path}  sha256={r['sha256']}  {verdict}")
        for d in r["dangerous"]:
            print(f"    ! {d}")
        if r["note"]:
            print(f"    ({r['note']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
