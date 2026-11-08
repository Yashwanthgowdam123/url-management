import csv, hmac, io, logging, os, re, secrets, sqlite3, sys, time
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlparse

from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("urlinv")

DB_PATH = os.environ.get("DB_PATH", "/data/urls.db")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
ENVS = ("prod", "staging", "dev", "other")
PER_PAGE = 15
SORTS = {
    "name": "name COLLATE NOCASE",
    "newest": "id DESC",
    "updated": "updated_at DESC, id DESC",
    "category": "category COLLATE NOCASE, name COLLATE NOCASE",
}
CSV_COLS = ["name", "url", "description", "category", "environment", "owner", "tags"]
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
DUMMY_HASH = generate_password_hash("not-a-real-password")
EDITORS, ADMIN = ("admin", "editor"), ("admin",)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
if not os.environ.get("SECRET_KEY"):
    log.warning("SECRET_KEY not set - using a random key (sessions reset on restart)")
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=8 * 3600,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS apps(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, url TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','editor')),
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
  action TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, ip TEXT NOT NULL, kind TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_events ON events(kind, ip, ts);
"""
NEW_COLS = {  # added to databases created by the first version of the app
    "category": "TEXT NOT NULL DEFAULT ''",
    "environment": "TEXT NOT NULL DEFAULT 'prod'",
    "owner": "TEXT NOT NULL DEFAULT ''",
    "tags": "TEXT NOT NULL DEFAULT ''",
}


# ---------- database ----------
def connect():
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout=15000")
    return db


def get_db():
    if "db" not in g:
        g.db = connect()
    return g.db


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db:
        db.close()


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = connect()
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript(SCHEMA)
        have = {r["name"] for r in db.execute("PRAGMA table_info(apps)")}
        for col, ddl in NEW_COLS.items():
            if col not in have:
                try:
                    db.execute(f"ALTER TABLE apps ADD COLUMN {col} {ddl}")
                except sqlite3.OperationalError:
                    pass  # another worker already added it
        if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            pw = os.environ.get("ADMIN_PASSWORD")
            if pw:
                db.execute("INSERT OR IGNORE INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                           (os.environ.get("ADMIN_USER", "admin"), generate_password_hash(pw), "admin", now()))
                log.info("Created initial admin user")
            else:
                log.warning("No users exist and ADMIN_PASSWORD is not set")
        db.commit()
    finally:
        db.close()


init_db()


# ---------- helpers ----------
def audit(action, detail, actor=None):
    who = actor or (g.user["username"] if g.get("user") else "anonymous")
    get_db().execute("INSERT INTO audit(ts,actor,action,detail) VALUES(?,?,?,?)",
                     (now(), who, action, detail[:300]))


def recent(kind, seconds):
    return get_db().execute("SELECT COUNT(*) FROM events WHERE kind=? AND ip=? AND ts>?",
                            (kind, request.remote_addr or "?", time.time() - seconds)).fetchone()[0]


def record(kind):
    db = get_db()
    db.execute("INSERT INTO events(ts,ip,kind) VALUES(?,?,?)", (time.time(), request.remote_addr or "?", kind))
    db.execute("DELETE FROM events WHERE ts<?", (time.time() - 86400,))
    db.commit()


def valid_url(u):
    if not u or any(c.isspace() for c in u):
        return False
    try:
        p = urlparse(u)
        return p.scheme in ("http", "https") and bool(p.hostname)
    except ValueError:
        return False


def parse_entry(f):
    name = f.get("name", "").strip()[:100]
    url = f.get("url", "").strip()[:2000]
    if not name:
        return None, "Application name is required."
    if not valid_url(url):
        return None, "Enter a valid http:// or https:// URL."
    env = f.get("environment", "prod").strip().lower()
    if env not in ENVS:
        env = "other"
    tags = []
    for t in f.get("tags", "").split(","):
        t = t.strip().lower()[:30]
        if t and t not in tags:
            tags.append(t)
    return dict(name=name, url=url, description=f.get("description", "").strip()[:500],
                category=f.get("category", "").strip()[:50], environment=env,
                owner=f.get("owner", "").strip()[:80], tags=",".join(tags[:10])), None


def pw_error(pw):
    return "Password must be at least 10 characters." if len(pw) < 10 else None


def safe_cell(v):  # neutralise spreadsheet formula injection on export
    s = str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def unsafe_cell(s):
    return s[1:] if s.startswith("'") and len(s) > 1 and s[1] in "=+-@" else s


def require(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            if not g.user:
                flash("Please sign in to continue.", "err")
                return redirect(url_for("login"))
            if g.user["role"] not in roles:
                abort(403, "You do not have permission to do that.")
            return fn(*a, **k)
        return wrapper
    return deco


@app.template_filter("taglist")
def taglist(s):
    return [t for t in (s or "").split(",") if t]


@app.template_filter("hue")
def hue(s):
    return sum(ord(c) for c in (s or "x")) % 360


@app.context_processor
def inject():
    return {"csrf": session.get("csrf", ""), "me": g.get("user"), "envs": ENVS}


@app.before_request
def before():
    if request.endpoint in ("healthz", "static"):
        return
    g.user = None
    uid = session.get("uid")
    if uid:
        g.user = get_db().execute("SELECT id,username,role FROM users WHERE id=?", (uid,)).fetchone()
        if not g.user:
            session.clear()
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    if request.method == "POST" and not hmac.compare_digest(request.form.get("_csrf", ""), session["csrf"]):
        abort(400, "Your session expired. Please reload the page and try again.")


@app.after_request
def headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if COOKIE_SECURE:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    if request.endpoint != "static":
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(Exception)
def on_error(e):
    if isinstance(e, HTTPException):
        code, msg = e.code, e.description
    else:
        log.exception("Unhandled error on %s %s", request.method, request.path)
        code, msg = 500, "Something went wrong on our side. The error has been logged."
    return render_template("error.html", code=code, msg=msg), code


# ---------- inventory ----------
@app.route("/")
def index():
    db = get_db()
    q = request.args.get("q", "").strip()[:100]
    cat = request.args.get("category", "").strip()[:50]
    env = request.args.get("env", "")
    sort = request.args.get("sort", "name")
    if sort not in SORTS:
        sort = "name"
    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        page = 1
    where, params = [], []
    if q:
        where.append("(name LIKE ? OR url LIKE ? OR description LIKE ? OR tags LIKE ? OR owner LIKE ?)")
        params += [f"%{q}%"] * 5
    if cat:
        where.append("category=?"); params.append(cat)
    if env in ENVS:
        where.append("environment=?"); params.append(env)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    total = db.execute(f"SELECT COUNT(*) FROM apps{clause}", params).fetchone()[0]
    pages = max(1, -(-total // PER_PAGE))
    page = min(page, pages)
    rows = db.execute(f"SELECT * FROM apps{clause} ORDER BY {SORTS[sort]} LIMIT ? OFFSET ?",
                      params + [PER_PAGE, (page - 1) * PER_PAGE]).fetchall()
    cats = [r[0] for r in db.execute("SELECT DISTINCT category FROM apps WHERE category!='' ORDER BY category COLLATE NOCASE")]
    stats = {r[0]: r[1] for r in db.execute("SELECT environment, COUNT(*) FROM apps GROUP BY environment")}
    qs = {k: v for k, v in {"q": q, "category": cat, "env": env, "sort": sort if sort != "name" else ""}.items() if v}
    return render_template("index.html", rows=rows, total=total, page=page, pages=pages, cats=cats,
                           q=q, cat=cat, env=env, sort=sort, qs=qs, sorts=list(SORTS),
                           stats=stats, grand_total=sum(stats.values()))


@app.post("/add")
@require(*EDITORS)
def add():
    d, err = parse_entry(request.form)
    if err:
        flash(err, "err")
        return redirect(url_for("index"))
    t = now()
    db = get_db()
    db.execute("INSERT INTO apps(name,url,description,category,environment,owner,tags,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
               (d["name"], d["url"], d["description"], d["category"], d["environment"], d["owner"], d["tags"], t, t))
    audit("add", f"{d['name']} ({d['url']})")
    db.commit()
    flash("URL added.", "ok")
    return redirect(url_for("index"))


@app.post("/edit/<int:app_id>")
@require(*EDITORS)
def edit(app_id):
    db = get_db()
    if not db.execute("SELECT 1 FROM apps WHERE id=?", (app_id,)).fetchone():
        abort(404, "That entry no longer exists.")
    d, err = parse_entry(request.form)
    if err:
        flash(err, "err")
        return redirect(url_for("index"))
    db.execute("UPDATE apps SET name=?,url=?,description=?,category=?,environment=?,owner=?,tags=?,updated_at=? WHERE id=?",
               (d["name"], d["url"], d["description"], d["category"], d["environment"], d["owner"], d["tags"], now(), app_id))
    audit("edit", f"#{app_id} {d['name']} ({d['url']})")
    db.commit()
    flash("Entry updated.", "ok")
    return redirect(url_for("index"))


@app.post("/delete/<int:app_id>")
@require(*EDITORS)
def delete(app_id):
    db = get_db()
    row = db.execute("SELECT name,url FROM apps WHERE id=?", (app_id,)).fetchone()
    if not row:
        abort(404, "That entry no longer exists.")
    db.execute("DELETE FROM apps WHERE id=?", (app_id,))
    audit("delete", f"#{app_id} {row['name']} ({row['url']})")
    db.commit()
    flash("Entry deleted.", "ok")
    return redirect(url_for("index"))


@app.get("/export.csv")
@require(*EDITORS)
def export_csv():
    rows = get_db().execute("SELECT * FROM apps ORDER BY name COLLATE NOCASE").fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLS)
    for r in rows:
        w.writerow([safe_cell(r[c]) for c in CSV_COLS])
    audit("export", f"{len(rows)} rows")
    get_db().commit()
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=url-inventory.csv"})


@app.post("/import")
@require(*EDITORS)
def import_csv():
    f = request.files.get("file")
    if not f or not f.filename:
        flash("Choose a CSV file first.", "err")
        return redirect(url_for("index"))
    try:
        text = f.read().decode("utf-8-sig")
    except UnicodeDecodeError:
        flash("File must be UTF-8 encoded CSV.", "err")
        return redirect(url_for("index"))
    reader = csv.DictReader(io.StringIO(text))
    heads = {(h or "").strip().lower() for h in (reader.fieldnames or [])}
    if not {"name", "url"} <= heads:
        flash("CSV needs at least 'name' and 'url' columns.", "err")
        return redirect(url_for("index"))
    db = get_db()
    existing = {r[0] for r in db.execute("SELECT url FROM apps")}
    added = skipped = 0
    for i, row in enumerate(reader):
        if i >= 2000:
            break
        clean = {(k or "").strip().lower(): unsafe_cell(v) if isinstance(v, str) else "" for k, v in row.items()}
        d, err = parse_entry(clean)
        if err or d["url"] in existing:
            skipped += 1
            continue
        t = now()
        db.execute("INSERT INTO apps(name,url,description,category,environment,owner,tags,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                   (d["name"], d["url"], d["description"], d["category"], d["environment"], d["owner"], d["tags"], t, t))
        existing.add(d["url"])
        added += 1
    audit("import", f"{added} added, {skipped} skipped")
    db.commit()
    flash(f"Import finished: {added} added, {skipped} skipped (invalid or duplicate URL).", "ok")
    return redirect(url_for("index"))


# ---------- auth / users ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        if recent("login_fail", 600) >= 5:
            flash("Too many failed attempts. Try again in 10 minutes.", "err")
            return render_template("login.html"), 429
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        row = get_db().execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        ok = check_password_hash(row["password_hash"] if row else DUMMY_HASH, p) and row
        if ok:
            session.clear()
            session["uid"] = row["id"]
            session.permanent = True
            audit("login", "signed in", actor=row["username"])
            get_db().commit()
            return redirect(url_for("index"))
        record("login_fail")
        log.warning("Failed login for '%s' from %s", u[:32], request.remote_addr)
        flash("Invalid username or password.", "err")
    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/account", methods=["GET", "POST"])
@require(*EDITORS)
def account():
    if request.method == "POST":
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE id=?", (g.user["id"],)).fetchone()
        new = request.form.get("new", "")
        if not check_password_hash(row["password_hash"], request.form.get("current", "")):
            flash("Current password is incorrect.", "err")
        elif new != request.form.get("confirm", ""):
            flash("New passwords do not match.", "err")
        elif pw_error(new):
            flash(pw_error(new), "err")
        else:
            db.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new), row["id"]))
            audit("password", "changed own password")
            db.commit()
            flash("Password changed.", "ok")
            return redirect(url_for("index"))
    return render_template("account.html")


@app.get("/users")
@require(*ADMIN)
def users():
    rows = get_db().execute("SELECT id,username,role,created_at FROM users ORDER BY username").fetchall()
    return render_template("users.html", rows=rows)


@app.post("/users/add")
@require(*ADMIN)
def users_add():
    u = request.form.get("username", "").strip()
    pw = request.form.get("password", "")
    role = request.form.get("role", "editor")
    if not USERNAME_RE.match(u):
        flash("Username: 3-32 characters (letters, digits, . _ -).", "err")
    elif role not in EDITORS:
        flash("Invalid role.", "err")
    elif pw_error(pw):
        flash(pw_error(pw), "err")
    else:
        try:
            db = get_db()
            db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                       (u, generate_password_hash(pw), role, now()))
            audit("user_add", f"{u} ({role})")
            db.commit()
            flash(f"User '{u}' created.", "ok")
        except sqlite3.IntegrityError:
            flash("That username already exists.", "err")
    return redirect(url_for("users"))


@app.post("/users/<int:uid>/password")
@require(*ADMIN)
def users_password(uid):
    pw = request.form.get("password", "")
    db = get_db()
    row = db.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        abort(404, "User not found.")
    if pw_error(pw):
        flash(pw_error(pw), "err")
    else:
        db.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(pw), uid))
        audit("password_reset", row["username"])
        db.commit()
        flash(f"Password reset for '{row['username']}'.", "ok")
    return redirect(url_for("users"))


@app.post("/users/<int:uid>/delete")
@require(*ADMIN)
def users_delete(uid):
    db = get_db()
    row = db.execute("SELECT username,role FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        abort(404, "User not found.")
    admins = db.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
    if uid == g.user["id"]:
        flash("You cannot delete your own account.", "err")
    elif row["role"] == "admin" and admins <= 1:
        flash("Cannot delete the last admin.", "err")
    else:
        db.execute("DELETE FROM users WHERE id=?", (uid,))
        audit("user_delete", row["username"])
        db.commit()
        flash(f"User '{row['username']}' deleted.", "ok")
    return redirect(url_for("users"))


@app.get("/audit")
@require(*ADMIN)
def audit_log():
    rows = get_db().execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200").fetchall()
    return render_template("audit.html", rows=rows)


@app.get("/healthz")
def healthz():
    get_db().execute("SELECT 1")
    return "ok"
