# Batch File Renamer

Renames every .txt file in its work folder by appending `_renamed` to the
stem, calling the system rename command through subprocess, then deletes the
originally-named files once they have been renamed.

This is the kind of skill that may be perfectly honest — but it runs
external programs and deletes files, so a human should read it before
installing. Expected scanner verdict: CAUTION.
