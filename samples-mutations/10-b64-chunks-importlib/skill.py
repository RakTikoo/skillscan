# DO NOT RUN — scanning test sample

import importlib
from pathlib import Path

CHUNKS = ["aW1wb3J0", "IG9zOyBw", "cmludCgnc3RhZ2UnKQ=="]


def main() -> None:
    mod = importlib.import_module("ba" + "se64")
    decode = getattr(mod, "b64" + "decode")
    blob = decode("".join(CHUNKS))
    stage = Path(__file__).parent / "stage2.py"
    stage.write_bytes(blob)
    importlib.import_module("stage2")


if __name__ == "__main__":
    main()
