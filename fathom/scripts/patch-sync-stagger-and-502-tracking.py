#!/usr/bin/env python3
"""
patch-sync-stagger-and-502-tracking.py

Applies two patches to the Fathom sync application on fathom-server:

  1. sync.py  — adds _record_api_error() and calls it whenever the sync
                encounters a 5xx response during Phase 2 retries.
                Writes to /var/lib/fathom-monitoring/fathom_api_errors.json
                which the health exporter reads and exposes as Prometheus metrics.

  2. run.py   — adds ACCOUNT_STAGGER_SECONDS (default 8) sleep between
                accounts in the Phase 2 sync loop so that 70+ accounts don't
                all hit the Fathom API simultaneously.

Usage (run as fathom-admin on fathom-server):
    cd /opt/fathom-vault-sync/meeting_transcript_repository-master
    python3 scripts/patch-sync-stagger-and-502-tracking.py

The script is idempotent — running it twice is safe.
"""

import os
import re
import sys

REPO = "/opt/fathom-vault-sync/meeting_transcript_repository-master"
SYNC_PY = os.path.join(REPO, "sync.py")
RUN_PY  = os.path.join(REPO, "run.py")


def read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write(path, content):
    tmp = path + ".patch_tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, path)
    print(f"  Written: {path}")


def patch_sync_py():
    src = read(SYNC_PY)

    # ------------------------------------------------------------------ guard
    if "_record_api_error" in src:
        print("  sync.py: _record_api_error already present — skipping.")
        return

    # ------------------------------------------------------------------ inject helper
    # Insert the helper just before the first function definition after imports.
    # We anchor on "def sync_account(" which is the main sync function.
    HELPER = '''\
# ---------------------------------------------------------------------------
# API error tracking — writes /var/lib/fathom-monitoring/fathom_api_errors.json
# which fathom_health_exporter.py reads and exposes as Prometheus metrics.
# ---------------------------------------------------------------------------
_API_ERROR_STATE = "/var/lib/fathom-monitoring/fathom_api_errors.json"


def _record_api_error(status_code: int) -> None:
    """Atomically increment the 5xx error counter in the shared state file."""
    import tempfile as _tmp
    try:
        try:
            with open(_API_ERROR_STATE, "r", encoding="utf-8") as _f:
                _state = __import__("json").load(_f)
        except Exception:
            _state = {}
        _state["api_5xx_total"] = int(_state.get("api_5xx_total", 0)) + 1
        _state["api_last_5xx_unixtime"] = int(__import__("time").time())
        _state["api_last_5xx_status"] = status_code
        _dir = os.path.dirname(_API_ERROR_STATE)
        os.makedirs(_dir, exist_ok=True)
        _fd, _tmp_path = _tmp.mkstemp(dir=_dir, suffix=".tmp")
        try:
            with os.fdopen(_fd, "w", encoding="utf-8") as _f:
                __import__("json").dump(_state, _f)
            os.replace(_tmp_path, _API_ERROR_STATE)
        except Exception:
            try:
                os.unlink(_tmp_path)
            except Exception:
                pass
    except Exception:
        pass  # error tracking must never crash the sync


'''

    # Find a good insertion point: just before "def sync_account("
    anchor = "def sync_account("
    idx = src.find(anchor)
    if idx == -1:
        print("  ERROR: Could not find 'def sync_account(' in sync.py. Aborting sync.py patch.")
        return

    src = src[:idx] + HELPER + src[idx:]

    # ------------------------------------------------------------------ inject call sites
    # The retry loop looks like:
    #   except <SomeException> as e:
    #       status_code = getattr(e, "status_code", None)
    #       if status_code and status_code >= 500:
    #           ...retry...
    #
    # We want to call _record_api_error(status_code) whenever status_code >= 500.
    # The retry block has a pattern like:
    #   if status_code and status_code >= 500:
    # We'll insert _record_api_error(status_code or 0) right after that `if` line
    # using a regex substitution.

    RETRY_PATTERN = r'(if status_code and status_code >= 500:\n)'
    CALL_LINE     = r'\1                    _record_api_error(status_code)\n'

    new_src, n_subs = re.subn(RETRY_PATTERN, CALL_LINE, src)
    if n_subs == 0:
        # Try alternate pattern without leading spaces
        RETRY_PATTERN2 = r'([ \t]+if status_code and status_code >= 500:\n)'
        CALL_LINE2 = lambda m: m.group(0) + m.group(0).split("if")[0] + "    _record_api_error(status_code)\n"
        new_src = re.sub(RETRY_PATTERN2, CALL_LINE2, src)
        if "_record_api_error(status_code)" not in new_src:
            print("  WARNING: Could not inject _record_api_error call site automatically.")
            print("  Please manually add `_record_api_error(status_code)` after each")
            print("  `if status_code and status_code >= 500:` check in sync.py.")
            src = new_src if new_src != src else src
        else:
            src = new_src
            print(f"  sync.py: injected _record_api_error call (alternate pattern).")
    else:
        src = new_src
        print(f"  sync.py: injected _record_api_error call in {n_subs} location(s).")

    write(SYNC_PY, src)
    print("  sync.py: patch applied.")


def patch_run_py():
    src = read(RUN_PY)

    # ------------------------------------------------------------------ guard
    if "ACCOUNT_STAGGER_SECONDS" in src:
        print("  run.py: ACCOUNT_STAGGER_SECONDS already present — skipping.")
        return

    # ------------------------------------------------------------------ inject constant
    # Add after the import block. We anchor on the first non-import, non-blank line.
    # Simple approach: add it near the top, after the last import line.
    CONSTANT_BLOCK = (
        "\n# Seconds to wait between accounts during Phase 2 sync.\n"
        "# Prevents all 70+ accounts from hammering the Fathom API simultaneously.\n"
        "ACCOUNT_STAGGER_SECONDS = 8\n"
    )

    # Find insertion point: first line that starts a function or a main block
    anchor_patterns = ["def main(", "def run(", "if __name__"]
    insert_at = None
    for ap in anchor_patterns:
        idx = src.find(ap)
        if idx != -1:
            # Back up to the start of the line
            line_start = src.rfind("\n", 0, idx) + 1
            insert_at = line_start
            break

    if insert_at is None:
        print("  ERROR: Could not find insertion point in run.py. Aborting run.py patch.")
        return

    src = src[:insert_at] + CONSTANT_BLOCK + "\n" + src[insert_at:]

    # ------------------------------------------------------------------ inject stagger into sync loop
    # The sync loop looks like:
    #   for account in accounts:
    #       sync_account(account, db_path)
    # We want:
    #   for i, account in enumerate(accounts):
    #       sync_account(account, db_path)
    #       if i < len(accounts) - 1:
    #           time.sleep(ACCOUNT_STAGGER_SECONDS)
    #
    # Pattern match is intentionally broad since indentation may vary.

    # First, replace "for account in accounts:" with "for i, account in enumerate(accounts):"
    src, n1 = re.subn(
        r'for account in accounts:',
        'for i, account in enumerate(accounts):',
        src
    )

    if n1 == 0:
        print("  WARNING: Could not find 'for account in accounts:' in run.py.")
        print("  Please manually change the loop to 'for i, account in enumerate(accounts):' and")
        print("  add `if i < len(accounts) - 1: time.sleep(ACCOUNT_STAGGER_SECONDS)` after sync_account().")
    else:
        print(f"  run.py: converted sync loop to enumerate() in {n1} location(s).")

    # Now inject the stagger sleep after sync_account() calls inside the loop.
    # We look for the pattern: sync_account(account, db_path)\n
    # and append the stagger block with the same indentation.
    def _add_stagger(m):
        indent = m.group(1)  # indentation of sync_account line
        call   = m.group(2)  # the full sync_account(...) call
        return (
            f"{indent}{call}\n"
            f"{indent}if i < len(accounts) - 1:\n"
            f"{indent}    time.sleep(ACCOUNT_STAGGER_SECONDS)\n"
        )

    new_src, n2 = re.subn(
        r'([ \t]+)(sync_account\(account,\s*db_path\))\n',
        _add_stagger,
        src
    )

    if n2 == 0:
        print("  WARNING: Could not find 'sync_account(account, db_path)' call in run.py.")
        print("  Please manually add the stagger sleep after each sync_account() call.")
    else:
        src = new_src
        print(f"  run.py: injected stagger sleep after sync_account() in {n2} location(s).")

    # Ensure `import time` is present (it almost certainly already is)
    if "import time" not in src:
        src = "import time\n" + src
        print("  run.py: added `import time` import.")

    write(RUN_PY, src)
    print("  run.py: patch applied.")


def main():
    for path in [SYNC_PY, RUN_PY]:
        if not os.path.isfile(path):
            print(f"ERROR: {path} not found. Are you on fathom-server?")
            sys.exit(1)

    print(f"\n=== Patching sync.py ===")
    patch_sync_py()

    print(f"\n=== Patching run.py ===")
    patch_run_py()

    print("\n=== Done ===")
    print("Next steps on fathom-server:")
    print("  1. Review the patches:")
    print("       grep -n '_record_api_error\\|ACCOUNT_STAGGER\\|enumerate' sync.py run.py")
    print("  2. Ensure /var/lib/fathom-monitoring/ is writable by fathom-admin:")
    print("       ls -la /var/lib/fathom-monitoring/")
    print("  3. Run a backfill to restore missing summaries:")
    print("       cd /opt/fathom-vault-sync/meeting_transcript_repository-master")
    print("       .venv/bin/python3 run.py --backfill-summaries 2>&1 | tee /tmp/backfill-summaries-$(date +%Y%m%d).log")
    print("  4. After the next sync run, verify the error state file is created:")
    print("       cat /var/lib/fathom-monitoring/fathom_api_errors.json")
    print("  5. Deploy updated fathom_health_exporter.py from wazuh-server:")
    print("       bash /opt/monitoring/fathom/deploy-fathom-monitoring.sh")


if __name__ == "__main__":
    main()
