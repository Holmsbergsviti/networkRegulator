# Tests

Offline unit suites for LanLens. They need no Mac, no network, and no root —
each one builds commands / parses captured output rather than touching real
hardware.

Each file is a plain script (prints `ok`/`FAIL` lines and exits non-zero on
failure), so run one directly:

```sh
python3 tests/test_report.py
```

Run them all (this is what CI does):

```sh
for t in tests/test_*.py; do python3 "$t" || echo "FAILED: $t"; done
```

The suites add the repo root to `sys.path` themselves, so they work from any
working directory. The application modules still live at the repo root.
