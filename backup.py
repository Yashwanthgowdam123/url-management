"""Daily SQLite backup loop (runs as its own container). Keeps the newest BACKUP_KEEP files."""
import glob, os, sqlite3, time
from datetime import datetime, timezone

DB = os.environ.get("DB_PATH", "/data/urls.db")
OUT = os.environ.get("BACKUP_DIR", "/backups")
KEEP = int(os.environ.get("BACKUP_KEEP", "14"))
EVERY = int(os.environ.get("BACKUP_INTERVAL_HOURS", "24")) * 3600


def run():
    if not os.path.exists(DB):
        print("database not found yet, skipping", flush=True)
        return
    os.makedirs(OUT, exist_ok=True)
    dst = os.path.join(OUT, f"urls-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.db")
    src, out = sqlite3.connect(DB, timeout=30), sqlite3.connect(dst)
    try:
        src.backup(out)
    finally:
        out.close(); src.close()
    for old in sorted(glob.glob(os.path.join(OUT, "urls-*.db")))[:-KEEP]:
        os.remove(old)
    print(f"backup written: {dst}", flush=True)


while True:
    try:
        run()
    except Exception as e:  # keep the loop alive
        print(f"backup failed: {e}", flush=True)
    time.sleep(EVERY)
