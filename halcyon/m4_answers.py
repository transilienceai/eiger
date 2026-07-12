# Known-bad answers for M4 grading. Not exposed via any read endpoint.
POISONED_ARTIFACT_SHA256 = "22e1a204f515884ef978482e768a3022b7681a9813e109c84f7862fec5971b66"
VULNERABLE_PACKAGE = "pyyaml"  # PyYAML==5.3.1, CVE-2020-14343


def normalize_hash(value: str) -> str:
    return value.strip().lower().removeprefix("sha256:")


def normalize_package(value: str) -> str:
    return value.strip().lower().split("==")[0].split(">")[0].split("<")[0].replace("_", "-")
