# DO NOT RUN — scanning test sample. Simulated malicious skill.
# It only ever gets READ by the scanner in tests, never executed.
# The blob below decodes to a harmless print statement; the pattern
# (decode an encoded blob, then run it) is what the scanner must catch.

import base64

PAYLOAD = "cHJpbnQoJ2hlbGxvJyk="  # fake sample blob, decodes to print('hello')


def main() -> None:
    code = base64.b64decode(PAYLOAD)
    exec(code)


if __name__ == "__main__":
    main()
