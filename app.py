import csv
import io
import secrets
import uuid
from datetime import date, datetime, timedelta
from functools import wraps
from pathlib import Path
from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from db import get_db

app = Flask(__name__)
app.secret_key = "change-this-to-a-long-random-string"
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024
INCIDENT_UPLOAD_DIR = Path(app.instance_path) / "incident_uploads"
PROFILE_UPLOAD_DIR = Path(app.instance_path) / "profile_uploads"
INCIDENT_IMAGE_TYPES = {
    ".jpg": ("image/jpeg", lambda data: data.startswith(b"\xff\xd8\xff") and data.endswith(b"\xff\xd9")),
    ".jpeg": ("image/jpeg", lambda data: data.startswith(b"\xff\xd8\xff") and data.endswith(b"\xff\xd9")),
    ".png": ("image/png", lambda data: len(data) >= 33 and data.startswith(b"\x89PNG\r\n\x1a\n")
            and data[8:12] == b"\x00\x00\x00\r" and data[12:16] == b"IHDR"),
    ".webp": ("image/webp", lambda data: len(data) >= 20 and data.startswith(b"RIFF")
             and data[8:12] == b"WEBP" and int.from_bytes(data[4:8], "little") + 8 <= len(data)),
}

ROLES = {"admin": "Admin"}   # Admin is the only role

# ======================= SETTINGS (edit these lists) =======================
CATEGORIES = ["Theft / Missing Property", "Guest Disturbance", "Accident / Injury",
              "Property Damage", "Lost / Found Property", "Trespassing", "Suspicious Activity",
              "Fire / Alarm", "Medical", "Other"]
SEVERITIES = ["low", "medium", "high", "critical"]
STATUSES = ["open", "investigating", "resolved"]
SHIFTS = ["Day", "Mid", "Night"]
DEFAULT_AREAS = ["Main Entrance", "Lobby", "Parking Area", "Pool Area", "Stairwells",
                 "Elevators", "Back Entrance", "Basement", "Rooftop", "Perimeter / Grounds"]
ESCALATE_TO = ["Security Manager", "Hotel Manager", "General Manager",
               "Police / Authorities", "Hotel Owner"]
# Hours an unresolved incident may stay un-escalated before an alert is raised
SLA_HOURS = {"critical": 1, "high": 4, "medium": 24, "low": 72}
STAFF_TITLES = ["Security Guard", "Head Guard", "Security Supervisor", "CCTV Operator", "Security Manager"]
FIRE_ITEMS = ["Fire extinguisher", "Smoke detector", "Fire alarm panel", "Sprinkler system",
              "Emergency exit", "Exit sign", "Fire hose", "Evacuation route", "Emergency lighting"]
RESTRICTED_AREAS = ["Server Room", "Cash Office / Safe", "CCTV Control Room", "Master Key Room",
                    "Storage / Warehouse", "Rooftop / Machine Room", "Electrical Room"]
EMERGENCY_TYPES = ["Fire", "Medical Emergency", "Evacuation", "Power Outage", "Flood / Water Leak",
                   "Earthquake", "Bomb Threat", "Armed Threat", "Other"]
AGENCIES = ["Fire Department", "Police", "Ambulance / EMS", "Hotel Management",
            "Maintenance / Engineering", "Other"]

BADGES = {
    "Active": "ok", "Online": "ok", "OK": "ok", "Passed": "ok", "Completed": "ok", "Returned": "ok",
    "Closed": "ok", "Exited": "low", "Within SLA": "ok", "Found": "ok",
    "On leave": "medium", "Maintenance": "medium", "Due now": "medium", "Inside": "medium",
    "Investigating": "medium", "Contained": "medium", "Escalated": "high",
    "Upcoming": "low", "Inactive": "low", "Reported": "low",
    "Needs attention": "high", "Never patrolled": "high", "Not returned": "high",
    "Offline": "high", "Overdue": "critical", "Failed": "critical", "Missed": "critical",
    "SLA breached": "critical", "Active emergency": "critical",
}

# ============================== HELPERS ====================================
def q(sql, args=(), one=False):
    """SELECT returns rows (list of dicts); other statements return the new row id."""
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(sql, args)
            if sql.lstrip().upper().startswith("SELECT"):
                return cur.fetchone() if one else list(cur.fetchall())
            return cur.lastrowid
    finally:
        db.close()

def count(sql, args=()):
    return q(sql, args, one=True)["c"]

def safe_count(sql, args=()):
    try:
        return count(sql, args)
    except Exception:
        return 0

def safe_rows(sql, args=()):
    try:
        return q(sql, args)
    except Exception:
        return []

def can(perm):
    """Kept so older templates keep working: every logged-in account is an admin."""
    return "user_id" in session

def initials(name):
    parts = (name or "?").split()
    return ("".join(p[0] for p in parts[:2]).upper()) or "?"

def parse_dt(s):
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M")
    except (ValueError, TypeError):
        return None

def valid_date(s, default):
    try:
        datetime.strptime(s, "%Y-%m-%d")
        return s
    except (ValueError, TypeError):
        return default

def week_start(s=None):
    d = datetime.strptime(valid_date(s or "", date.today().isoformat()), "%Y-%m-%d").date()
    return d - timedelta(days=d.weekday())

def csv_safe(v):
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@") else v

def num(v):
    try:
        return round(float(v), 2) if v not in (None, "") else None
    except ValueError:
        return None

def fmt(v):
    if v is None or v == "":
        return "—"
    if isinstance(v, datetime):
        return v.strftime("%b %d, %I:%M %p")
    if isinstance(v, date):
        return v.strftime("%b %d, %Y")
    if isinstance(v, timedelta):
        mins = int(v.total_seconds() // 60)
        return datetime(2000, 1, 1, (mins // 60) % 24, mins % 60).strftime("%I:%M %p")
    return str(v)

def badge_class(v):
    return BADGES.get(str(v), "")

def age_text(hours):
    d, h = int(hours // 24), int(hours % 24)
    return f"{d}d {h}h" if d else f"{h}h {int((hours * 60) % 60)}m"

def sla_info(inc, now):
    age = (now - inc["created_at"]).total_seconds() / 3600
    limit = SLA_HOURS.get(inc["severity"], 72)
    if inc["status"] == "resolved":
        state = "Resolved"
    elif inc["escalation_level"]:
        state = "Escalated"
    elif age > limit:
        state = "SLA breached"
    else:
        state = "Within SLA"
    return age, limit, state

def account_error(name, email, emp_no, username=None, exclude_id=0):
    if not name:
        return "Full name is required."
    if email and ("@" not in email or "." not in email.split("@")[-1]):
        return "Please enter a valid email address."
    if q("SELECT id FROM users WHERE LOWER(full_name)=LOWER(%s) AND id!=%s", (name, exclude_id), one=True):
        return "An account with that full name already exists."
    if username and q("SELECT id FROM users WHERE LOWER(username)=LOWER(%s) AND id!=%s",
                      (username, exclude_id), one=True):
        return "That username is already taken."
    if email and q("SELECT id FROM users WHERE email=%s AND id!=%s", (email, exclude_id), one=True):
        return "That email is already used by another account."
    if emp_no and q("SELECT id FROM users WHERE employee_no=%s AND id!=%s", (emp_no, exclude_id), one=True):
        return "That employee number is already used by another account."
    return None

def get_areas():
    if "areas" not in g:
        g.areas = [r["name"] for r in safe_rows("SELECT name FROM checkpoints WHERE active=1 ORDER BY name")] \
                  or DEFAULT_AREAS
    return g.areas

def login_required(f):
    @wraps(f)
    def inner(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return inner

# ---------- computed states (SQL) ----------
SLA_CASE = "CASE severity " + " ".join(f"WHEN '{k}' THEN {v}" for k, v in SLA_HOURS.items()) + " ELSE 72 END"
SLA_BREACH_SQL = ("SELECT COUNT(*) c FROM incidents WHERE status!='resolved' AND escalation_level=0 "
                  f"AND TIMESTAMPDIFF(MINUTE, created_at, NOW()) > 60 * {SLA_CASE}")

PATROL_STATE = """CASE
  WHEN EXISTS (SELECT 1 FROM patrol_logs p WHERE p.area=s.area
       AND p.patrolled_at BETWEEN TIMESTAMP(CURDATE(), s.scheduled_time) - INTERVAL 30 MINUTE
                              AND TIMESTAMP(CURDATE(), s.scheduled_time) + INTERVAL 90 MINUTE) THEN 'Completed'
  WHEN NOW() > TIMESTAMP(CURDATE(), s.scheduled_time) + INTERVAL 90 MINUTE THEN 'Missed'
  WHEN NOW() >= TIMESTAMP(CURDATE(), s.scheduled_time) - INTERVAL 30 MINUTE THEN 'Due now'
  ELSE 'Upcoming' END"""

CHECKPOINT_STATE = """CASE
  WHEN NOT EXISTS (SELECT 1 FROM patrol_logs p WHERE p.area=c.name) THEN 'Never patrolled'
  WHEN TIMESTAMPDIFF(MINUTE, (SELECT MAX(p.patrolled_at) FROM patrol_logs p WHERE p.area=c.name), NOW())
       > c.interval_minutes THEN 'Overdue'
  ELSE 'OK' END"""

FIRE_LATEST = """FROM fire_inspections f WHERE NOT EXISTS (SELECT 1 FROM fire_inspections g
   WHERE g.location=f.location AND g.item=f.item
     AND (g.inspected_on > f.inspected_on OR (g.inspected_on = f.inspected_on AND g.id > f.id)))"""

# ============================ NOTIFICATIONS ================================
LEVEL_ORDER = {"critical": 0, "high": 1, "info": 2}

def get_notifications():
    if "notes" in g:
        return g.notes
    n = []
    def add(level, text, url):
        n.append((level, text, url))
    c = safe_count(SLA_BREACH_SQL)
    if c:
        add("critical", f"{c} incident(s) passed their response time and need escalation.",
            url_for("incidents", status="open"))
    c = safe_count("SELECT COUNT(*) c FROM emergencies WHERE closed_at IS NULL")
    if c:
        add("critical", f"{c} active emergency event(s).", url_for("cases", key="emergencies"))
    c = safe_count("SELECT COUNT(*) c FROM incidents WHERE status!='resolved' AND escalation_level>0")
    if c:
        add("high", f"{c} escalated incident(s) still unresolved.", url_for("incidents"))
    c = safe_count("SELECT COUNT(*) c FROM incidents WHERE severity IN ('high','critical') AND status!='resolved'")
    if c:
        add("high", f"{c} high/critical incident(s) still open.", url_for("incidents", status="open"))
    c = safe_count(f"SELECT COUNT(*) c FROM (SELECT {PATROL_STATE} AS st FROM patrol_schedule s WHERE s.active=1) t WHERE st='Missed'")
    if c:
        add("high", f"{c} scheduled patrol(s) missed today.", url_for("module", key="patrol_schedule"))
    c = safe_count(f"SELECT COUNT(*) c FROM (SELECT {CHECKPOINT_STATE} AS st FROM checkpoints c WHERE c.active=1) t WHERE st!='OK'")
    if c:
        add("high", f"{c} checkpoint(s) overdue for a patrol.", url_for("module", key="checkpoints"))
    c = safe_count("SELECT COUNT(*) c " + FIRE_LATEST + " AND f.result IN ('Failed','Needs attention')")
    if c:
        add("high", f"{c} fire safety item(s) failed or need attention.", url_for("module", key="fire"))
    c = safe_count("SELECT COUNT(*) c " + FIRE_LATEST + " AND f.result='Passed' AND f.next_due < CURDATE()")
    if c:
        add("high", f"{c} fire safety inspection(s) overdue.", url_for("module", key="fire"))
    c = safe_count("SELECT COUNT(*) c FROM key_logs WHERE returned_at IS NULL AND issued_at < NOW() - INTERVAL 24 HOUR")
    if c:
        add("high", f"{c} key(s) not returned for over 24 hours.", url_for("module", key="keys"))
    c = safe_count("SELECT COUNT(*) c FROM restricted_access WHERE time_out IS NULL AND time_in < NOW() - INTERVAL 12 HOUR")
    if c:
        add("high", f"{c} person(s) logged inside a restricted area for over 12 hours.", url_for("module", key="restricted"))
    if safe_count("SELECT COUNT(*) c FROM security_staff") and not safe_count(
            "SELECT COUNT(*) c FROM shift_schedule WHERE shift_date=CURDATE()"):
        add("info", "No guard shifts are scheduled for today.", url_for("schedule"))
    c = safe_count("SELECT COUNT(*) c FROM users WHERE is_active=0")
    if c:
        add("info", f"{c} account(s) waiting for approval.", url_for("users"))
    c = safe_count("SELECT COUNT(*) c FROM users WHERE reset_requested=1")
    if c:
        add("info", f"{c} password reset request(s).", url_for("users"))
    n.sort(key=lambda x: LEVEL_ORDER[x[0]])
    g.notes = n
    return n

@app.context_processor
def helpers():
    va = request.view_args or {}
    cur = f"{request.endpoint}:{va['key']}" if "key" in va else (request.endpoint or "")
    logged = "user_id" in session
    return dict(can=can, ROLES=ROLES, CATEGORIES=CATEGORIES, SEVERITIES=SEVERITIES,
                STATUSES=STATUSES, SHIFTS=SHIFTS, ESCALATE_TO=ESCALATE_TO,
                STAFF_TITLES=STAFF_TITLES,
                AREAS=get_areas() if logged else DEFAULT_AREAS,
                initials=initials, badge=badge_class, cur=cur,
                 notif_count=len(get_notifications()) if logged else 0,
                notif_items=get_notifications()[:6] if logged else [],
                REPORT_TYPES=[(k, d["title"]) for k, d in REPORT_DEFS.items()])

# ================================= AUTH ====================================
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("home"))
    if request.method == "POST":
        u = q("SELECT * FROM users WHERE username=%s", (request.form["username"].strip(),), one=True)
        if not u or not check_password_hash(u["password_hash"], request.form["password"]):
            flash("Invalid username or password.", "error")
        elif not u["is_active"]:
            flash("Your account is pending approval or has been deactivated.", "error")
        else:
            session.update(user_id=u["id"], name=u["full_name"], role="admin",
                           profile_photo_filename=u.get("profile_photo_filename"))
            q("UPDATE users SET last_login=NOW() WHERE id=%s", (u["id"],))
            flash(f"Welcome back, {u['full_name']}!", "success")
            return redirect(url_for("home"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = request.form
        name, user = f["full_name"].strip(), f["username"].strip()
        email = f["email"].strip().lower() or None
        emp_no = f["employee_no"].strip() or None
        err = account_error(name, email, emp_no, username=user)
        if not user:
            flash("Username is required.", "error")
        elif err:
            flash(err, "error")
        elif len(f["password"]) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif f["password"] != f["confirm"]:
            flash("Passwords do not match.", "error")
        else:
            q("""INSERT INTO users (full_name, username, password_hash, role, is_active,
                                    email, phone, job_title, employee_no)
                 VALUES (%s,%s,%s,'admin',0,%s,%s,%s,%s)""",
              (name, user, generate_password_hash(f["password"]), email,
               f["phone"].strip(), f["job_title"].strip(), emp_no))
            flash("Account created. An existing admin must approve it before you can sign in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        q("UPDATE users SET reset_requested=1 WHERE username=%s AND is_active=1",
          (request.form["username"].strip(),))
        flash("If that account exists, an admin has been notified. Ask them for your reset code.", "info")
        return redirect(url_for("reset"))
    return render_template("forgot.html")

@app.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "POST":
        f = request.form
        u = q("SELECT * FROM users WHERE username=%s", (f["username"].strip(),), one=True)
        ok = bool(u and u["reset_code_hash"] and u["reset_expires"]
                  and u["reset_expires"] > datetime.now()
                  and check_password_hash(u["reset_code_hash"], f["code"].strip()))
        if not ok:
            flash("Invalid or expired reset code.", "error")
        elif len(f["password"]) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif f["password"] != f["confirm"]:
            flash("Passwords do not match.", "error")
        else:
            q("""UPDATE users SET password_hash=%s, reset_code_hash=NULL,
                 reset_expires=NULL, reset_requested=0 WHERE id=%s""",
              (generate_password_hash(f["password"]), u["id"]))
            flash("Password updated. You can sign in now.", "success")
            return redirect(url_for("login"))
    return render_template("reset.html")

# ============================== DASHBOARD ==================================
@app.route("/home")
@login_required
def home():
    return render_template("index.html", notes=get_notifications())

# ---------- activity tracking + dashboard analytics ----------
@app.before_request
def track_activity():
    """Remember when each user was last active (written at most once a minute)."""
    if "user_id" not in session or request.endpoint in (None, "static"):
        return
    now = datetime.now()
    seen = session.get("seen_at")
    if seen:
        try:
            if (now - datetime.fromisoformat(seen)).total_seconds() < 60:
                return
        except ValueError:
            pass
    session["seen_at"] = now.isoformat()
    try:
        q("UPDATE users SET last_seen=%s WHERE id=%s", (now, session["user_id"]))
    except Exception:
        pass

def ago(dt):
    if not dt:
        return "never"
    mins = int((datetime.now() - dt).total_seconds() // 60)
    if mins < 1:
        return "just now"
    if mins < 60:
        return f"{mins} min ago"
    if mins < 1440:
        return f"{mins // 60} h ago"
    return f"{mins // 1440} d ago"

def daily_counts(table, col, days):
    """Rows per day for the last N days (missing days count as 0)."""
    rows = safe_rows(f"""SELECT DATE({col}) AS d, COUNT(*) AS n FROM {table}
                         WHERE {col} >= CURDATE() - INTERVAL {days - 1} DAY GROUP BY DATE({col})""")
    by = {r["d"]: r["n"] for r in rows}
    start = date.today() - timedelta(days=days - 1)
    out = []
    for i in range(days):
        d = start + timedelta(days=i)
        out.append(dict(label=d.strftime("%a") if days <= 7 else d.strftime("%d"),
                        title=d.strftime("%b %d"), value=by.get(d, 0)))
    top = max([o["value"] for o in out] + [1])
    for o in out:
        o["pct"] = round(100 * o["value"] / top)
    return out

def top_counts(sql):
    rows = safe_rows(sql)
    top = max([r["n"] for r in rows] + [1])
    return [dict(label=r["label"], value=r["n"], pct=round(100 * r["n"] / top), cls="") for r in rows]

def analytics(days=30):
    a = {}
    now = datetime.now()

    # --- users ---
    a["online"] = safe_count("SELECT COUNT(*) c FROM users WHERE is_active=1 AND last_seen >= NOW() - INTERVAL 5 MINUTE")
    a["active_today"] = safe_count("""SELECT COUNT(*) c FROM users WHERE is_active=1
        AND (last_seen >= NOW() - INTERVAL 24 HOUR OR last_login >= NOW() - INTERVAL 24 HOUR)""")
    a["accounts"] = safe_count("SELECT COUNT(*) c FROM users WHERE is_active=1")
    a["pending"] = safe_count("SELECT COUNT(*) c FROM users WHERE is_active=0")
    people = []
    for r in safe_rows("""SELECT full_name, job_title, last_seen, last_login, id,
                          profile_photo_filename FROM users WHERE is_active=1"""):
        last = max([t for t in (r["last_seen"], r["last_login"]) if t], default=None)
        people.append(dict(name=r["full_name"], job=r["job_title"] or "", ago=ago(last),
                           online=bool(last and (now - last).total_seconds() < 300),
                           when=last or datetime.min, id=r["id"],
                           profile_photo_filename=r["profile_photo_filename"]))
    people.sort(key=lambda p: p["when"], reverse=True)
    a["people"] = people[:6]

    # --- incidents ---
    period_start = f"CURDATE() - INTERVAL {days - 1} DAY"
    previous_start = f"CURDATE() - INTERVAL {days * 2 - 1} DAY"
    incidents = safe_count(f"SELECT COUNT(*) c FROM incidents WHERE created_at >= {period_start}")
    previous_incidents = safe_count(f"""SELECT COUNT(*) c FROM incidents WHERE created_at >= {previous_start}
                           AND created_at < {period_start}""")
    resolved = safe_count(f"""SELECT COUNT(*) c FROM incidents WHERE created_at >= {period_start}
                           AND status='resolved'""")
    a["period_days"] = days
    a["incidents"] = incidents
    a["trend"] = round(100 * (incidents - previous_incidents) / previous_incidents) if previous_incidents else None
    a["resolve_rate"] = round(100 * resolved / incidents) if incidents else None
    row = safe_rows(f"""SELECT AVG(TIMESTAMPDIFF(MINUTE, created_at, resolved_at)) / 60 AS h FROM incidents
                       WHERE resolved_at IS NOT NULL AND created_at >= {period_start}""")
    h = row[0]["h"] if row else None
    a["avg_hours"] = round(float(h), 1) if h is not None else None
    a["inc_daily"] = daily_counts("incidents", "created_at", days)
    a["visit_daily"] = daily_counts("visitors", "time_in", days)
    a["patrol_daily"] = daily_counts("patrol_logs", "patrolled_at", days)
    a["by_category"] = top_counts(f"""SELECT category AS label, COUNT(*) AS n FROM incidents
        WHERE created_at >= {period_start} GROUP BY category ORDER BY n DESC LIMIT 6""")
    a["hotspots"] = top_counts(f"""SELECT location AS label, COUNT(*) AS n FROM incidents
        WHERE created_at >= {period_start} AND location IS NOT NULL AND location != ''
        GROUP BY location ORDER BY n DESC LIMIT 5""")
    sev = {r["severity"]: r["n"] for r in safe_rows(
        "SELECT severity, COUNT(*) AS n FROM incidents WHERE status!='resolved' GROUP BY severity")}
    top = max(list(sev.values()) + [1])
    a["by_severity"] = [dict(label=s.capitalize(), value=sev.get(s, 0),
                             pct=round(100 * sev.get(s, 0) / top), cls="sev-" + s)
                        for s in ("critical", "high", "medium", "low")]

    # --- patrols today ---
    st = {r["st"]: r["n"] for r in safe_rows(
        f"SELECT st, COUNT(*) AS n FROM (SELECT {PATROL_STATE} AS st FROM patrol_schedule s WHERE s.active=1) t GROUP BY st")}
    done, missed, due, upcoming = (st.get(k, 0) for k in ("Completed", "Missed", "Due now", "Upcoming"))
    total = done + missed + due + upcoming
    a["patrol"] = dict(
        total=total,
        pct=round(100 * done / (done + missed)) if (done + missed) else None,
        segs=[dict(label=l, value=v, cls=c, w=round(100 * v / total) if total else 0)
              for l, v, c in (("Completed", done, "seg-ok"), ("Missed", missed, "seg-bad"),
                              ("Due now", due, "seg-warn"), ("Upcoming", upcoming, "seg-idle"))])

    # --- guards on duty by shift (today) ---
    gs = {r["sh"]: r["n"] for r in safe_rows("""SELECT sc.shift AS sh, COUNT(*) AS n FROM shift_schedule sc
        JOIN security_staff s2 ON s2.id=sc.staff_id
        WHERE sc.shift_date=CURDATE() AND s2.status='Active' GROUP BY sc.shift""")}
    top = max(list(gs.values()) + [1])
    a["by_shift"] = [dict(label=s, value=gs.get(s, 0), pct=round(100 * gs.get(s, 0) / top), cls="") for s in SHIFTS]
    return a
@app.route("/dashboard")
@login_required
def dashboard():
    days = request.args.get("days", "30")
    days = int(days) if days in ("7", "14", "30") else 30
    s = dict(
        open_inc=safe_count("SELECT COUNT(*) c FROM incidents WHERE status!='resolved'"),
        breached=safe_count(SLA_BREACH_SQL),
        escalated=safe_count("SELECT COUNT(*) c FROM incidents WHERE status!='resolved' AND escalation_level>0"),
        emergencies=safe_count("SELECT COUNT(*) c FROM emergencies WHERE closed_at IS NULL"),
        guards=safe_count("""SELECT COUNT(*) c FROM shift_schedule sc JOIN security_staff st ON st.id=sc.staff_id
                             WHERE sc.shift_date=CURDATE() AND st.status='Active'"""),
        visitors=safe_count("SELECT COUNT(*) c FROM visitors WHERE DATE(time_in)=CURDATE()"),
        patrols=safe_count("SELECT COUNT(*) c FROM patrol_logs WHERE DATE(patrolled_at)=CURDATE()"),
        keys_out=safe_count("SELECT COUNT(*) c FROM key_logs WHERE returned_at IS NULL"))
    notes = get_notifications()
    return render_template(
            "dashboard.html", s=s, an=analytics(days), analytics_days=days,
            alerts=notes[:6], total_alerts=len(notes),
        guards_today=safe_rows("""SELECT st.full_name, st.job_title, sc.shift, sc.post FROM shift_schedule sc
                                  JOIN security_staff st ON st.id=sc.staff_id
                                  WHERE sc.shift_date=CURDATE() AND st.status='Active'
                                  ORDER BY FIELD(sc.shift,'Day','Mid','Night'), st.full_name"""),
        emerg=safe_rows("SELECT id, kind, location, opened_at FROM emergencies WHERE closed_at IS NULL ORDER BY opened_at DESC"),
        recent_visitors=safe_rows("""SELECT visitor_name, guest_visited, room_no, time_in, time_out
                                     FROM visitors ORDER BY time_in DESC LIMIT 5"""),
        recent=safe_rows("SELECT id, title, severity, status, created_at FROM incidents ORDER BY created_at DESC LIMIT 5"))

@app.route("/notifications")
@login_required
def notifications():
    return render_template("notifications.html", notes=get_notifications())

# ================================ INCIDENTS ================================
def incident_locations():
    locations = get_areas()
    for location in ("Guest Room", "Other / not listed"):
        if location not in locations:
            locations = locations + [location]
    return locations


@app.errorhandler(413)
def incident_upload_too_large(error):
    flash("The uploaded image must be 6 MB or smaller.", "error")
    destination = "profile" if request.path.startswith(url_for("profile")) else "incidents"
    return redirect(url_for(destination))


@app.route("/incidents")
@login_required
def incidents():
    status = request.args.get("status", "")
    locations = incident_locations()
    sql = """SELECT i.*, u.full_name reporter, a.full_name assignee,
               (SELECT COUNT(*) FROM cctv_refs c WHERE c.incident_id=i.id) AS cctv_count
             FROM incidents i LEFT JOIN users u ON u.id=i.reported_by
             LEFT JOIN users a ON a.id=i.assigned_to"""
    args = ()
    if status in STATUSES:
        sql += " WHERE i.status=%s"
        args = (status,)
    sql += """ ORDER BY FIELD(i.status,'open','investigating','resolved'),
                        FIELD(i.severity,'critical','high','medium','low'), i.created_at DESC"""
    selected_location = request.args.get("loc", "")
    incident_now = datetime.now().replace(second=0, microsecond=0)
    return render_template(
        "incidents.html", incidents=q(sql, args), status=status, loc=selected_location,
        locations=locations, incident_now=incident_now.strftime("%Y-%m-%dT%H:%M"))

@app.route("/incidents/add", methods=["POST"])
@login_required
def add_incident():
    f = request.form
    category = f.get("category", "")
    severity = f.get("severity", "")
    selected_location = f.get("location", "")
    location_details = f.get("location_details", "").strip()
    location = location_details if selected_location == "Other / not listed" else selected_location
    incident_at = parse_dt(f.get("incident_at", ""))
    now = datetime.now().replace(second=0, microsecond=0)
    property_type = f.get("property_report_type", "")
    item_desc = f.get("item_desc", "").strip()
    if severity not in SEVERITIES or category not in CATEGORIES:
        flash("Invalid severity or category.", "error")
    elif selected_location not in incident_locations():
        flash("Please choose a valid incident location.", "error")
    elif selected_location == "Other / not listed" and not location_details:
        flash("Please enter the incident location.", "error")
    elif not incident_at:
        flash("Please enter when the incident happened.", "error")
    elif incident_at < now:
        flash("Past incident dates and times can't be submitted. Choose the current time or later.", "error")
    elif category == "Lost / Found Property" and property_type not in (
            "Lost item (guest reported)", "Found item (turned in)"):
        flash("Please choose whether the item was lost or found.", "error")
    elif category == "Lost / Found Property" and not item_desc:
        flash("Please describe the lost or found item.", "error")
    else:
        photo = request.files.get("photo")
        photo_data, photo_ext, photo_error = None, None, None
        if photo and photo.filename:
            photo_ext = Path(photo.filename).suffix.lower()
            image_type = INCIDENT_IMAGE_TYPES.get(photo_ext)
            if not image_type:
                photo_error = "Upload a JPG, PNG, or WebP image."
            else:
                photo_data = photo.read(6 * 1024 * 1024 + 1)
                if len(photo_data) > 6 * 1024 * 1024:
                    photo_error = "The incident photo must be 6 MB or smaller."
                elif not image_type[1](photo_data):
                    photo_error = "The uploaded file does not appear to be a valid image."
        if photo_error:
            flash(photo_error, "error")
        else:
            room_no = f.get("room_no", "").strip()[:10] or None
            if selected_location != "Guest Room":
                room_no = None
            title = f"{property_type + ' - ' if category == 'Lost / Found Property' else ''}{category} - {location}"
            description = f.get("description", "").strip()[:2000] or None
            contact = f.get("contact", "").strip()[:100] or None
            if category != "Lost / Found Property":
                contact = None
            photo_filename = f"{uuid.uuid4().hex}{photo_ext}" if photo_data else None
            photo_path = None
            if photo_filename:
                INCIDENT_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                photo_path = INCIDENT_UPLOAD_DIR / photo_filename
                photo_path.write_bytes(photo_data)
            try:
                iid = q("""INSERT INTO incidents
                           (title, description, location, category, severity, reported_by,
                            room_no, involved, item_desc, incident_at, photo_filename,
                            property_report_type, contact)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                         (title, description, location, category, severity, session["user_id"],
                          room_no, f.get("involved", "").strip()[:200] or None,
                          item_desc[:200] or None, incident_at, photo_filename,
                          property_type if category == "Lost / Found Property" else None,
                          contact))
            except Exception:
                if photo_path and photo_path.exists():
                    photo_path.unlink()
                raise
            flash(f"Incident #{iid} reported. You can now attach CCTV references.", "success")
            return redirect(url_for("incident_detail", iid=iid))
    return redirect(url_for("incidents"))

@app.route("/incidents/<int:iid>")
@login_required
def incident_detail(iid):
    inc = q("""SELECT i.*, u.full_name reporter, a.full_name assignee FROM incidents i
               LEFT JOIN users u ON u.id=i.reported_by LEFT JOIN users a ON a.id=i.assigned_to
               WHERE i.id=%s""", (iid,), one=True)
    if not inc:
        flash("Incident not found.", "error")
        return redirect(url_for("incidents"))
    age, limit, state = sla_info(inc, datetime.now())
    return render_template(
        "incident_detail.html", i=inc, age=age_text(age), limit=limit, state=state,
        updates=q("""SELECT t.*, u.full_name who FROM incident_updates t LEFT JOIN users u ON u.id=t.user_id
                     WHERE t.incident_id=%s ORDER BY t.created_at DESC, t.id DESC""", (iid,)),
        refs=q("""SELECT c.*, u.full_name who FROM cctv_refs c LEFT JOIN users u ON u.id=c.added_by
                  WHERE c.incident_id=%s ORDER BY c.footage_from""", (iid,)),
        admins=q("SELECT id, full_name FROM users WHERE is_active=1 ORDER BY full_name"),
        cams=safe_rows("SELECT name FROM cctv_cameras ORDER BY name"))

@app.route("/incidents/<int:iid>/photo")
@login_required
def incident_photo(iid):
    inc = q("SELECT photo_filename FROM incidents WHERE id=%s", (iid,), one=True)
    if not inc or not inc["photo_filename"] or Path(inc["photo_filename"]).name != inc["photo_filename"]:
        abort(404)
    extension = Path(inc["photo_filename"]).suffix.lower()
    image_type = INCIDENT_IMAGE_TYPES.get(extension)
    if not image_type:
        abort(404)
    response = send_from_directory(
        INCIDENT_UPLOAD_DIR, inc["photo_filename"], mimetype=image_type[0], max_age=0)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "private, no-store"
    return response


@app.route("/incidents/<int:iid>/update", methods=["POST"])
@login_required
def update_incident(iid):
    s = request.form["status"]
    note = request.form.get("note", "").strip()[:400]
    assigned = request.form.get("assigned_to", "")
    assigned_id = int(assigned) if assigned.isdigit() else None
    old = q("SELECT assigned_to FROM incidents WHERE id=%s", (iid,), one=True)
    if s not in STATUSES:
        flash("Invalid status.", "error")
    elif not old:
        flash("Incident not found.", "error")
        return redirect(url_for("incidents"))
    else:
        if assigned_id != old["assigned_to"]:
            who = q("SELECT full_name FROM users WHERE id=%s", (assigned_id,), one=True)
            note = (note + " " if note else "") + (f"[Assigned to {who['full_name']}]" if who else "[Unassigned]")
        q("""UPDATE incidents SET status=%s, assigned_to=%s,
             resolved_at=IF(%s='resolved', COALESCE(resolved_at, NOW()), NULL) WHERE id=%s""",
          (s, assigned_id, s, iid))
        q("INSERT INTO incident_updates (incident_id, user_id, status, note) VALUES (%s,%s,%s,%s)",
          (iid, session["user_id"], s, note))
        flash(f"Incident #{iid} updated.", "success")
    return redirect(url_for("incident_detail", iid=iid))

@app.route("/incidents/<int:iid>/escalate", methods=["POST"])
@login_required
def escalate_incident(iid):
    to = request.form.get("to", "")
    reason = request.form.get("reason", "").strip()[:300]
    inc = q("SELECT status FROM incidents WHERE id=%s", (iid,), one=True)
    if not inc:
        flash("Incident not found.", "error")
        return redirect(url_for("incidents"))
    if to not in ESCALATE_TO:
        flash("Please choose who to escalate to.", "error")
    elif inc["status"] == "resolved":
        flash("Resolved incidents can't be escalated.", "error")
    else:
        q("""UPDATE incidents SET escalation_level=escalation_level+1, escalated_at=NOW(), escalated_to=%s
             WHERE id=%s""", (to, iid))
        q("INSERT INTO incident_updates (incident_id, user_id, status, note) VALUES (%s,%s,%s,%s)",
          (iid, session["user_id"], inc["status"], f"ESCALATED to {to}. {reason}".strip()))
        flash(f"Incident #{iid} escalated to {to}.", "success")
    return redirect(url_for("incident_detail", iid=iid))

@app.route("/incidents/<int:iid>/delete", methods=["POST"])
@login_required
def delete_incident(iid):
    incident = q("SELECT photo_filename FROM incidents WHERE id=%s", (iid,), one=True)
    q("DELETE FROM incidents WHERE id=%s", (iid,))
    if incident and incident["photo_filename"]:
        photo_path = INCIDENT_UPLOAD_DIR / Path(incident["photo_filename"]).name
        if photo_path.exists():
            photo_path.unlink()
    flash(f"Incident #{iid} deleted.", "info")
    return redirect(url_for("incidents"))

# ============================ CCTV FOOTAGE REFS ============================
@app.route("/incidents/<int:iid>/cctv", methods=["POST"])
@login_required
def add_cctv(iid):
    f = request.form
    cam = f["camera_name"].strip()
    start, end = parse_dt(f.get("footage_from", "")), parse_dt(f.get("footage_to", ""))
    if not cam or not start:
        flash("Camera name and footage start time are required.", "error")
    elif end and end <= start:
        flash("Footage end time must be after the start time.", "error")
    else:
        q("""INSERT INTO cctv_refs (incident_id, camera_name, footage_from, footage_to,
                                   clip_ref, notes, added_by) VALUES (%s,%s,%s,%s,%s,%s,%s)""",
          (iid, cam, start, end, f["clip_ref"].strip()[:150], f["notes"].strip()[:500], session["user_id"]))
        flash("CCTV reference added.", "success")
    return redirect(url_for("incident_detail", iid=iid))

@app.route("/cctv/<int:rid>/delete", methods=["POST"])
@login_required
def delete_cctv(rid):
    ref = q("SELECT incident_id FROM cctv_refs WHERE id=%s", (rid,), one=True)
    q("DELETE FROM cctv_refs WHERE id=%s", (rid,))
    flash("CCTV reference removed.", "info")
    return redirect(url_for("incident_detail", iid=ref["incident_id"]) if ref else url_for("incidents"))

# ================================ VISITORS =================================
@app.route("/visitors")
@login_required
def visitors():
    return render_template("visitors.html",
                           visitors=q("SELECT * FROM visitors ORDER BY time_in DESC LIMIT 200"))

# ================================ PATROLS ==================================
PATROL_RANGES = {
    "today": "DATE(p.patrolled_at)=CURDATE()",
    "7":     "p.patrolled_at >= NOW() - INTERVAL 7 DAY",
    "30":    "p.patrolled_at >= NOW() - INTERVAL 30 DAY",
    "all":   "1=1",
}

@app.route("/patrols")
@login_required
def patrols():
    rng = request.args.get("range", "today")
    if rng not in PATROL_RANGES:
        rng = "today"
    area = request.args.get("area", "")
    sql = f"""SELECT p.*, u.full_name guard FROM patrol_logs p
              LEFT JOIN users u ON u.id=p.patrolled_by WHERE {PATROL_RANGES[rng]}"""
    args = ()
    if area in get_areas():
        sql += " AND p.area=%s"
        args = (area,)
    sql += " ORDER BY p.patrolled_at DESC LIMIT 300"
    stats = dict(
        today=count("SELECT COUNT(*) c FROM patrol_logs WHERE DATE(patrolled_at)=CURDATE()"),
        issues=count("SELECT COUNT(*) c FROM patrol_logs WHERE DATE(patrolled_at)=CURDATE() AND result='issue'"),
        last=q("SELECT MAX(patrolled_at) m FROM patrol_logs", one=True)["m"])
    patrol_now = datetime.now().replace(second=0, microsecond=0)
    return render_template("patrols.html", patrols=q(sql, args), stats=stats, rng=rng, area=area,
                           patrol_now=patrol_now.strftime("%Y-%m-%dT%H:%M"))

@app.route("/patrols/add", methods=["POST"])
@login_required
def add_patrol():
    f = request.form
    area, result = f.get("area", ""), f.get("result", "")
    notes = f.get("notes", "").strip()[:500]
    raw_when = f.get("patrolled_at", "").strip()
    when = parse_dt(raw_when) if raw_when else datetime.now().replace(second=0, microsecond=0)
    now = datetime.now().replace(second=0, microsecond=0)
    if area not in get_areas() or result not in ("clear", "issue"):
        flash("Invalid area or result.", "error")
    elif result == "issue" and not notes:
        flash("Please describe the issue you found.", "error")
    elif not when:
        flash("Please enter a valid patrol date and time.", "error")
    elif when < now:
        flash("Past patrol dates and times can't be logged. Choose the current time or later.", "error")
    else:
        q("""INSERT INTO patrol_logs (area, result, notes, patrolled_by, patrolled_at)
             VALUES (%s,%s,%s,%s,%s)""", (area, result, notes, session["user_id"], when))
        flash("Patrol logged with an issue. Use 'Report incident' on that row to file it."
              if result == "issue" else "Patrol recorded.", "info" if result == "issue" else "success")
    return redirect(url_for("patrols"))

@app.route("/patrols/<int:pid>/delete", methods=["POST"])
@login_required
def delete_patrol(pid):
    q("DELETE FROM patrol_logs WHERE id=%s", (pid,))
    flash("Patrol record deleted.", "info")
    return redirect(url_for("patrols"))

# ============================ GUARD SHIFT SCHEDULE =========================
@app.route("/schedule")
@login_required
def schedule():
    start = week_start(request.args.get("week"))
    days = [start + timedelta(days=i) for i in range(7)]
    rows = q("SELECT * FROM shift_schedule WHERE shift_date BETWEEN %s AND %s", (days[0], days[-1]))
    return render_template(
        "schedule.html", days=days, start=start, today=date.today(),
        prev=start - timedelta(days=7), nxt=start + timedelta(days=7),
        grid={(r["staff_id"], r["shift_date"]): r for r in rows},
        staff=q("SELECT id, full_name, job_title FROM security_staff WHERE status!='Inactive' ORDER BY full_name"),
        areas=get_areas())

@app.route("/schedule/add", methods=["POST"])
@login_required
def schedule_add():
    f = request.form
    d = valid_date(f.get("shift_date", ""), "")
    sid = f.get("staff_id", "")
    post = f.get("post", "").strip()
    if d and datetime.strptime(d, "%Y-%m-%d").date() < date.today():
        flash("Shifts can't be assigned to a past date. Choose today or a future date.", "error")
        return redirect(url_for("schedule"))
    if post and post not in get_areas():
        flash("Please choose a valid post.", "error")
        return redirect(url_for("schedule"))
    if not d or f.get("shift") not in SHIFTS or not sid.isdigit() or not q(
            "SELECT id FROM security_staff WHERE id=%s", (sid,), one=True):
        flash("Please choose a guard, a date and a shift.", "error")
        return redirect(url_for("schedule"))
    q("""INSERT INTO shift_schedule (staff_id, shift_date, shift, post) VALUES (%s,%s,%s,%s)
         ON DUPLICATE KEY UPDATE shift=VALUES(shift), post=VALUES(post)""",
      (sid, d, f["shift"], post[:100]))
    flash("Shift saved.", "success")
    return redirect(url_for("schedule", week=d))

@app.route("/schedule/<int:sid>/delete", methods=["POST"])
@login_required
def schedule_delete(sid):
    q("DELETE FROM shift_schedule WHERE id=%s", (sid,))
    flash("Shift removed.", "info")
    return redirect(url_for("schedule"))

@app.route("/schedule/copy", methods=["POST"])
@login_required
def schedule_copy():
    start = week_start(request.form.get("week"))
    if start + timedelta(days=6) < date.today():
        flash("Shifts can't be copied into a past week.", "error")
        return redirect(url_for("schedule"))
    prev = start - timedelta(days=7)
    q("""INSERT IGNORE INTO shift_schedule (staff_id, shift_date, shift, post)
         SELECT staff_id, shift_date + INTERVAL 7 DAY, shift, post FROM shift_schedule
         WHERE shift_date BETWEEN %s AND %s
           AND shift_date + INTERVAL 7 DAY >= CURDATE()""", (prev, prev + timedelta(days=6)))
    flash("Last week's shifts copied into this week.", "success")
    return redirect(url_for("schedule", week=start))

# ====================== SIMPLE MODULES (generic list + add) ================
def F(col, label, typ="text", opts=None, req=False, now=False, default=""):
    return dict(col=col, label=label, type=typ, opts=opts or [], req=req, now=now, default=default)

def resolve_fields(fields):
    out = []
    for f in fields:
        opts = f["opts"]() if callable(f["opts"]) else f["opts"]
        default = f["default"] or (date.today().isoformat() if f["type"] == "date" and f["now"] else "")
        out.append(dict(f, opts=opts, default=default))
    return out

def read_fields(fields, form):
    vals = {}
    for f in resolve_fields(fields):
        raw = (form.get(f["col"], "") or "").strip()
        t = f["type"]
        if not raw:
            if f["req"]:
                return None, f"{f['label']} is required."
            vals[f["col"]] = (datetime.now().replace(second=0, microsecond=0) if t == "datetime" and f["now"]
                              else date.today() if t == "date" and f["now"] else None)
            continue
        try:
            if t == "select":
                if raw not in f["opts"]:
                    return None, f"Invalid choice for {f['label']}."
            elif t == "number":
                raw = int(raw)
            elif t == "date":
                raw = datetime.strptime(raw, "%Y-%m-%d").date()
            elif t == "datetime":
                raw = parse_dt(raw)
                if not raw:
                    raise ValueError
            elif t == "time":
                datetime.strptime(raw, "%H:%M")
            elif t == "textarea":
                raw = raw[:500]
            else:
                raw = raw[:100]
        except ValueError:
            return None, f"{f['label']} is not valid."
        vals[f["col"]] = raw
    return vals, None

STATUS_STAFF = ["Active", "On leave", "Inactive"]
MODULES = {
    "staff": dict(
        title="Security Personnel", table="security_staff",
        select="SELECT * FROM security_staff ORDER BY FIELD(status,'Active','On leave','Inactive'), full_name",
        fields=[F("full_name", "Full name", req=True),
                F("job_title", "Position", "select", STAFF_TITLES, True), F("contact", "Contact number"),
                F("post", "Assigned post", "select", get_areas), F("status", "Status", "select", STATUS_STAFF, True)],
        cols=[("Staff ID", "staff_no"), ("Name", "full_name"), ("Position", "job_title"), ("Post", "post"),
              ("Contact", "contact"), ("Hired", "date_hired"), ("Status", "status", "badge")],
        setter=("status", STATUS_STAFF)),
    "cameras": dict(
        title="CCTV Cameras", table="cctv_cameras", unique=["name"],
        note="A register of your cameras. Camera names here appear as suggestions when you add footage references to an incident.",
        select="SELECT * FROM cctv_cameras ORDER BY name",
        fields=[F("name", "Camera name", req=True), F("location", "Location"), F("nvr_ref", "NVR / channel reference"),
                F("status", "Status", "select", ["Online", "Offline", "Maintenance"], True), F("notes", "Notes", "textarea")],
        cols=[("Camera", "name"), ("Location", "location"), ("NVR / channel", "nvr_ref"),
              ("Notes", "notes"), ("Status", "status", "badge")],
        setter=("status", ["Online", "Offline", "Maintenance"])),
    "checkpoints": dict(
        title="Security Checkpoints", table="checkpoints", unique=["name"],
        note="Each checkpoint shows when it was last patrolled. It turns Overdue when no patrol is logged within the required interval.",
        select=f"SELECT c.*, (SELECT MAX(p.patrolled_at) FROM patrol_logs p WHERE p.area=c.name) AS last_patrol, "
               f"{CHECKPOINT_STATE} AS state FROM checkpoints c WHERE c.active=1 ORDER BY c.name",
        fields=[F("name", "Checkpoint name", req=True), F("location", "Location / description"),
                F("interval_minutes", "Patrol required every (minutes)", "number", req=True, default="120")],
        cols=[("Checkpoint", "name"), ("Location", "location"), ("Every (min)", "interval_minutes"),
              ("Last patrol", "last_patrol"), ("Status", "state", "badge")]),
    "patrol_schedule": dict(
        title="Patrol Schedule", table="patrol_schedule",
        note="A scheduled patrol counts as completed when that area is logged on Patrol Records within 30 minutes before to 90 minutes after the scheduled time.",
        select=f"SELECT s.*, {PATROL_STATE} AS state FROM patrol_schedule s WHERE s.active=1 ORDER BY s.scheduled_time",
        fields=[F("area", "Checkpoint / area", "select", get_areas, True),
                F("scheduled_time", "Scheduled time", "time", req=True), F("assigned_to", "Assigned guard (optional)")],
        cols=[("Time", "scheduled_time"), ("Checkpoint", "area"), ("Assigned to", "assigned_to"),
              ("Today", "state", "badge")]),
    "fire": dict(
        title="Fire Safety Inspections", table="fire_inspections", by="inspected_by",
        select="""SELECT f.*, u.full_name inspector, CASE WHEN f.result='Failed' THEN 'Failed'
                    WHEN f.result='Needs attention' THEN 'Needs attention'
                    WHEN f.next_due IS NOT NULL AND f.next_due < CURDATE() THEN 'Overdue' ELSE 'Passed' END AS state
                  FROM fire_inspections f LEFT JOIN users u ON u.id=f.inspected_by
                  ORDER BY f.inspected_on DESC, f.id DESC LIMIT 300""",
        fields=[F("inspected_on", "Inspection date", "date", req=True, now=True), F("location", "Location", req=True),
                F("item", "Item inspected", "select", FIRE_ITEMS, True),
                F("result", "Result", "select", ["Passed", "Needs attention", "Failed"], True),
                F("next_due", "Next inspection due", "date"), F("notes", "Notes", "textarea")],
        cols=[("Inspected", "inspected_on"), ("Location", "location"), ("Item", "item"), ("Result", "state", "badge"),
              ("Next due", "next_due"), ("Inspector", "inspector"), ("Notes", "notes")]),
    "keys": dict(
        title="Key & Access Control Log", table="key_logs", by="issued_by",
        select="""SELECT k.*, u.full_name issuer,
                    CASE WHEN k.returned_at IS NULL THEN 'Not returned' ELSE 'Returned' END AS state
                  FROM key_logs k LEFT JOIN users u ON u.id=k.issued_by
                  ORDER BY (k.returned_at IS NULL) DESC, k.issued_at DESC LIMIT 300""",
        fields=[F("key_ref", "Key / card (e.g. Master key #2)", req=True), F("issued_to", "Issued to", req=True),
                F("purpose", "Purpose"), F("issued_at", "Issued at (blank = now)", "datetime", now=True),
                F("notes", "Notes", "textarea")],
        cols=[("Key / card", "key_ref"), ("Issued to", "issued_to"), ("Purpose", "purpose"), ("Issued", "issued_at"),
              ("Returned", "returned_at"), ("Issued by", "issuer"), ("Status", "state", "badge")],
        close=("returned_at", "Mark returned", "Mark this key as returned?")),
    "restricted": dict(
        title="Restricted-Area Access", table="restricted_access", by="logged_by",
        select="""SELECT r.*, u.full_name logger,
                    CASE WHEN r.time_out IS NULL THEN 'Inside' ELSE 'Exited' END AS state
                  FROM restricted_access r LEFT JOIN users u ON u.id=r.logged_by
                  ORDER BY (r.time_out IS NULL) DESC, r.time_in DESC LIMIT 300""",
        fields=[F("area", "Restricted area", "select", RESTRICTED_AREAS, True), F("person_name", "Person's name", req=True),
                F("company", "Company / department"), F("purpose", "Purpose of access"),
                F("authorized_by", "Authorized by"), F("time_in", "Time in (blank = now)", "datetime", now=True)],
        cols=[("Area", "area"), ("Person", "person_name"), ("Company", "company"), ("Purpose", "purpose"),
              ("Authorized by", "authorized_by"), ("In", "time_in"), ("Out", "time_out"), ("Status", "state", "badge")],
        close=("time_out", "Log exit", "Log that this person has left the restricted area?")),
}

@app.route("/m/<key>")
@login_required
def module(key):
    cfg = MODULES.get(key) or abort(404)
    table = []
    for r in q(cfg["select"]):
        cells = [(fmt(r.get(c[1])), badge_class(r.get(c[1])) if len(c) > 2 else "") for c in cfg["cols"]]
        table.append(dict(id=r["id"], cells=cells, raw=r))
    refs = q("""SELECT c.*, i.title, i.severity, u.full_name who FROM cctv_refs c
                JOIN incidents i ON i.id=c.incident_id
                LEFT JOIN users u ON u.id=c.added_by
                ORDER BY c.footage_from DESC LIMIT 200""") if key == "cameras" else []
    checkpoint_cfg = MODULES["checkpoints"] if key == "patrol_schedule" else None
    checkpoint_table = []
    if checkpoint_cfg:
        for r in q(checkpoint_cfg["select"]):
            cells = [(fmt(r.get(c[1])), badge_class(r.get(c[1])) if len(c) > 2 else "")
                     for c in checkpoint_cfg["cols"]]
            checkpoint_table.append(dict(id=r["id"], cells=cells, raw=r))
    return render_template("module.html", key=key, cfg=cfg, fields=resolve_fields(cfg["fields"]),
                           table=table, headers=[c[0] for c in cfg["cols"]], refs=refs,
                           checkpoint_cfg=checkpoint_cfg, checkpoint_table=checkpoint_table,
                           checkpoint_fields=resolve_fields(checkpoint_cfg["fields"]) if checkpoint_cfg else [],
                           checkpoint_headers=[c[0] for c in checkpoint_cfg["cols"]] if checkpoint_cfg else [])

def module_redirect(key):
    if key == "checkpoints" and request.form.get("return_to") == "patrol_schedule":
        return redirect(url_for("module", key="patrol_schedule"))
    return redirect(url_for("module", key=key))

@app.route("/m/<key>/add", methods=["POST"])
@login_required
def module_add(key):
    cfg = MODULES.get(key) or abort(404)
    vals, err = read_fields(cfg["fields"], request.form)
    if not err:
        for u in cfg.get("unique", []):
            if vals.get(u) and q(f"SELECT id FROM {cfg['table']} WHERE {u}=%s", (vals[u],), one=True):
                err = f"That {u.replace('_', ' ')} already exists."
    if err:
        flash(err, "error")
    elif key == "staff":
        db = get_db()
        locked = False
        try:
            with db.cursor() as cur:
                cur.execute("SELECT GET_LOCK(%s, 10) AS acquired", ("hotel_security_staff_id",))
                locked = cur.fetchone()["acquired"] == 1
                if locked:
                    try:
                        cur.execute("SELECT staff_no FROM security_staff")
                        existing_ids = [
                            int(row["staff_no"]) for row in cur.fetchall()
                            if str(row["staff_no"] or "").isdigit()
                        ]
                        vals["staff_no"] = f"{max(existing_ids, default=0) + 1:04d}"
                        vals["date_hired"] = datetime.now()
                        if cfg.get("by"):
                            vals[cfg["by"]] = session["user_id"]
                        cur.execute(
                            f"INSERT INTO {cfg['table']} ({', '.join(vals)}) "
                            f"VALUES ({', '.join(['%s'] * len(vals))})",
                            list(vals.values()))
                    finally:
                        cur.execute("SELECT RELEASE_LOCK(%s)", ("hotel_security_staff_id",))
        finally:
            db.close()
        if not locked:
            flash("Could not generate a Staff ID. Please try again.", "error")
        else:
            flash(f"Saved with Staff ID {vals['staff_no']}.", "success")
    else:
        if cfg.get("by"):
            vals[cfg["by"]] = session["user_id"]
        q(f"INSERT INTO {cfg['table']} ({', '.join(vals)}) VALUES ({', '.join(['%s'] * len(vals))})",
          list(vals.values()))
        flash("Saved.", "success")
    return module_redirect(key)

@app.route("/m/<key>/<int:rid>/set", methods=["POST"])
@login_required
def module_set(key, rid):
    cfg = MODULES.get(key) or abort(404)
    col, opts = cfg.get("setter") or abort(404)
    v = request.form.get("value", "")
    if v in opts:
        q(f"UPDATE {cfg['table']} SET {col}=%s WHERE id=%s", (v, rid))
        flash("Updated.", "success")
    return module_redirect(key)

@app.route("/m/<key>/<int:rid>/close", methods=["POST"])
@login_required
def module_close(key, rid):
    cfg = MODULES.get(key) or abort(404)
    col = (cfg.get("close") or abort(404))[0]
    q(f"UPDATE {cfg['table']} SET {col}=NOW() WHERE id=%s AND {col} IS NULL", (rid,))
    flash("Recorded.", "success")
    return module_redirect(key)

@app.route("/m/<key>/<int:rid>/delete", methods=["POST"])
@login_required
def module_delete(key, rid):
    cfg = MODULES.get(key) or abort(404)
    q(f"DELETE FROM {cfg['table']} WHERE id=%s", (rid,))
    flash("Record deleted.", "info")
    return module_redirect(key)

# ============================== CASES ======================================
CASES = {
    "emergencies": dict(
        title="Emergency Events", single="Emergency", table="emergencies",
        statuses=["Active", "Contained", "Closed"], closing=["Closed"], agencies=AGENCIES,
        note="Record the emergency, then log every response action and agency contacted on its page.",
        fields=[F("kind", "Type of emergency", "select", EMERGENCY_TYPES, True), F("location", "Location"),
                F("description", "What is happening?", "textarea", req=True),
                F("opened_at", "Started at (blank = now)", "datetime", now=True)]),
}

@app.route("/cases/<key>")
@login_required
def cases(key):
    cfg = CASES.get(key) or abort(404)
    status = request.args.get("status", "")
    sql = f"""SELECT t.*, u.full_name by_name FROM {cfg['table']} t
              LEFT JOIN users u ON u.id=t.reported_by"""
    args = ()
    if status in cfg["statuses"]:
        sql += " WHERE t.status=%s"
        args = (status,)
    sql += " ORDER BY (t.closed_at IS NULL) DESC, t.opened_at DESC LIMIT 300"
    return render_template("cases.html", key=key, cfg=cfg, fields=resolve_fields(cfg["fields"]),
                           rows=q(sql, args), status=status)

@app.route("/cases/<key>/add", methods=["POST"])
@login_required
def case_add(key):
    cfg = CASES.get(key) or abort(404)
    vals, err = read_fields(cfg["fields"], request.form)
    if err:
        flash(err, "error")
        return redirect(url_for("cases", key=key))
    vals.update(status=cfg["statuses"][0], reported_by=session["user_id"])
    rid = q(f"INSERT INTO {cfg['table']} ({', '.join(vals)}) VALUES ({', '.join(['%s'] * len(vals))})",
            list(vals.values()))
    flash(f"{cfg['single']} #{rid} recorded.", "success")
    return redirect(url_for("case_detail", key=key, rid=rid))

@app.route("/cases/<key>/<int:rid>")
@login_required
def case_detail(key, rid):
    cfg = CASES.get(key) or abort(404)
    r = q(f"""SELECT t.*, u.full_name by_name FROM {cfg['table']} t
              LEFT JOIN users u ON u.id=t.reported_by WHERE t.id=%s""", (rid,), one=True) or abort(404)
    notes = q("""SELECT n.*, u.full_name who FROM case_notes n LEFT JOIN users u ON u.id=n.user_id
                 WHERE n.ref_type=%s AND n.ref_id=%s ORDER BY n.created_at DESC, n.id DESC""", (key, rid))
    details = [(f["label"].split(" (")[0], fmt(r.get(f["col"]))) for f in cfg["fields"]]
    return render_template("case_detail.html", key=key, cfg=cfg, r=r, notes=notes, details=details)

@app.route("/cases/<key>/<int:rid>/note", methods=["POST"])
@login_required
def case_note(key, rid):
    cfg = CASES.get(key) or abort(404)
    s = request.form.get("status", "")
    note = request.form.get("note", "").strip()[:500]
    agency = request.form.get("agency", "")
    if s not in cfg["statuses"]:
        flash("Invalid status.", "error")
    elif not q(f"SELECT id FROM {cfg['table']} WHERE id=%s", (rid,), one=True):
        abort(404)
    else:
        closing = 1 if s in cfg["closing"] else 0
        q(f"UPDATE {cfg['table']} SET status=%s, closed_at=IF(%s=1, COALESCE(closed_at, NOW()), NULL) WHERE id=%s",
          (s, closing, rid))
        q("""INSERT INTO case_notes (ref_type, ref_id, user_id, status, agency, note)
             VALUES (%s,%s,%s,%s,%s,%s)""",
          (key, rid, session["user_id"], s, agency if agency in (cfg["agencies"] or []) else None, note))
        flash("Update logged.", "success")
    return redirect(url_for("case_detail", key=key, rid=rid))

# ================================ REPORTS ==================================
def date_range():
    today = date.today()
    return (valid_date(request.args.get("from", ""), (today - timedelta(days=30)).isoformat()),
            valid_date(request.args.get("to", ""), today.isoformat()))

def incident_filters():
    where, args, chosen = [], [], {}
    for key, col, allowed in (("severity", "i.severity", SEVERITIES), ("status", "i.status", STATUSES),
                              ("category", "i.category", CATEGORIES)):
        v = request.args.get(key, "")
        chosen[key] = v if v in allowed else ""
        if chosen[key]:
            where.append(f"{col}=%s")
            args.append(v)
    return where, args, chosen

def report_data():
    d_from, d_to = date_range()
    where, args, chosen = incident_filters()
    where.insert(0, "DATE(i.created_at) BETWEEN %s AND %s")
    rows = q(f"""SELECT i.*, u.full_name reporter FROM incidents i LEFT JOIN users u ON u.id=i.reported_by
                 WHERE {" AND ".join(where)} ORDER BY i.created_at DESC""", [d_from, d_to] + args)
    return d_from, d_to, chosen, rows

def avg_hours(rows):
    hours = [(r["resolved_at"] - r["created_at"]).total_seconds() / 3600 for r in rows if r["resolved_at"]]
    return round(sum(hours) / len(hours), 1) if hours else None

def cnt(rows, key, val):
    return sum(1 for r in rows if r.get(key) == val)

INC_SQL = ("SELECT i.*, u.full_name reporter, a.full_name assignee FROM incidents i "
           "LEFT JOIN users u ON u.id=i.reported_by LEFT JOIN users a ON a.id=i.assigned_to")
INC_BASE = dict(sql=INC_SQL, date="DATE(i.created_at)", order="i.created_at")

def unresolved_post(r):
    age, limit, state = sla_info(r, datetime.now())
    r["age"], r["sla"] = age_text(age), state

def patrol_post(r):
    r["result_txt"] = "Issue found" if r["result"] == "issue" else "All clear"

REPORT_DEFS = {
    "incidents": dict(INC_BASE, title="Incident Report",
        cols=[("#", "id"), ("Title", "title"), ("Category", "category"), ("Location", "location"),
              ("Incident time", "incident_at"),
              ("Severity", "severity"), ("Status", "status"), ("Assigned to", "assignee"),
              ("Escalated to", "escalated_to"), ("Reported by", "reporter"), ("Reported", "created_at"),
              ("Resolved", "resolved_at")],
        summary=lambda rs: {"Incidents": len(rs), "Open": cnt(rs, "status", "open"),
                            "Investigating": cnt(rs, "status", "investigating"),
                            "Resolved": cnt(rs, "status", "resolved"),
                            "Escalated": sum(1 for r in rs if r["escalation_level"])}),
    "unresolved": dict(INC_BASE, title="Unresolved Incidents Report", dated=False, where=["i.status!='resolved'"],
        cols=[("#", "id"), ("Title", "title"), ("Category", "category"), ("Severity", "severity"),
              ("Status", "status"), ("Assigned to", "assignee"), ("Reported", "created_at"),
              ("Age", "age"), ("Response time", "sla"), ("Escalated to", "escalated_to")],
        post=unresolved_post,
        summary=lambda rs: {"Unresolved": len(rs), "SLA breached": cnt(rs, "sla", "SLA breached"),
                            "Escalated": sum(1 for r in rs if r["escalation_level"])}),
    "lost": dict(INC_BASE, title="Lost Property Report",
        where=["i.category='Lost / Found Property'"],
        cols=[("#", "id"), ("Report type", "property_report_type"), ("Item", "item_desc"),
              ("Where", "location"), ("Owner / guest", "involved"), ("Contact", "contact"),
              ("Room", "room_no"), ("Status", "status"), ("Incident time", "incident_at"),
              ("Reported by", "reporter")],
        summary=lambda rs: {"Items": len(rs), "Resolved": cnt(rs, "status", "resolved"),
                            "Open": sum(1 for r in rs if r["status"] != "resolved")}),
}
for _k, _title, _cat, _cols in [
    ("theft", "Theft & Missing Property Report", "Theft / Missing Property",
     [("Owner / guest", "involved"), ("Item", "item_desc")]),
    ("disturbance", "Guest Disturbance Report", "Guest Disturbance", [("Guests involved", "involved")]),
    ("injury", "Accident & Injury Report", "Accident / Injury",
     [("Person involved", "involved"), ("Injury", "injury_details")]),
    ("damage", "Property Damage Report", "Property Damage",
     [("Responsible / guest", "involved"), ("Damaged item", "item_desc")])]:
    REPORT_DEFS[_k] = dict(
        INC_BASE, title=_title, where=[f"i.category='{_cat}'"],
        cols=[("#", "id"), ("Reported", "created_at"), ("Incident time", "incident_at"),
              ("Location", "location"), ("Room", "room_no")] + _cols +
             [("Details", "description"), ("Severity", "severity"), ("Status", "status"), ("Reported by", "reporter")],
        summary=lambda rs: {"Reports": len(rs), "Resolved": cnt(rs, "status", "resolved")})
REPORT_DEFS.update({
    "patrols": dict(title="Patrol Records Report",
        sql="SELECT p.*, u.full_name guard FROM patrol_logs p LEFT JOIN users u ON u.id=p.patrolled_by",
        date="DATE(p.patrolled_at)", order="p.patrolled_at", post=patrol_post,
        cols=[("When", "patrolled_at"), ("Area", "area"), ("Result", "result_txt"), ("Officer", "guard"), ("Notes", "notes")],
        summary=lambda rs: {"Patrols": len(rs), "Issues found": cnt(rs, "result", "issue")}),
    "visitors": dict(title="Visitor Log Report",
        sql="SELECT v.*, u.full_name logger FROM visitors v LEFT JOIN users u ON u.id=v.logged_by",
        date="DATE(v.time_in)", order="v.time_in",
        cols=[("Visitor", "visitor_name"), ("ID presented", "id_presented"), ("Visiting", "guest_visited"),
              ("Room", "room_no"), ("Time in", "time_in"), ("Time out", "time_out"), ("Logged by", "logger")],
        summary=lambda rs: {"Visitor records": len(rs)}),
    "restricted": dict(title="Restricted-Area Access Report",
        sql="SELECT r.*, u.full_name logger FROM restricted_access r LEFT JOIN users u ON u.id=r.logged_by",
        date="DATE(r.time_in)", order="r.time_in",
        cols=[("Area", "area"), ("Person", "person_name"), ("Company", "company"), ("Purpose", "purpose"),
              ("Authorized by", "authorized_by"), ("In", "time_in"), ("Out", "time_out"), ("Logged by", "logger")],
        summary=lambda rs: {"Entries": len(rs), "Still inside": sum(1 for r in rs if not r["time_out"])}),
    "keys": dict(title="Key & Access Control Report",
        sql="SELECT k.*, u.full_name issuer FROM key_logs k LEFT JOIN users u ON u.id=k.issued_by",
        date="DATE(k.issued_at)", order="k.issued_at",
        cols=[("Key / card", "key_ref"), ("Issued to", "issued_to"), ("Purpose", "purpose"), ("Issued", "issued_at"),
              ("Returned", "returned_at"), ("Issued by", "issuer"), ("Notes", "notes")],
        summary=lambda rs: {"Keys issued": len(rs), "Not returned": sum(1 for r in rs if not r["returned_at"])}),
    "fire": dict(title="Fire Safety Inspection Report",
        sql="SELECT f.*, u.full_name inspector FROM fire_inspections f LEFT JOIN users u ON u.id=f.inspected_by",
        date="f.inspected_on", order="f.inspected_on",
        cols=[("Inspected", "inspected_on"), ("Location", "location"), ("Item", "item"), ("Result", "result"),
              ("Next due", "next_due"), ("Inspector", "inspector"), ("Notes", "notes")],
        summary=lambda rs: {"Inspections": len(rs), "Passed": cnt(rs, "result", "Passed"),
                            "Needs attention": cnt(rs, "result", "Needs attention"), "Failed": cnt(rs, "result", "Failed")}),
    "emergencies": dict(title="Emergency Events Report",
        sql="SELECT e.*, u.full_name by_name FROM emergencies e LEFT JOIN users u ON u.id=e.reported_by",
        date="DATE(e.opened_at)", order="e.opened_at",
        cols=[("Started", "opened_at"), ("Type", "kind"), ("Location", "location"), ("Description", "description"),
              ("Status", "status"), ("Closed", "closed_at"), ("Recorded by", "by_name")],
        summary=lambda rs: {"Emergencies": len(rs), "Closed": cnt(rs, "status", "Closed")}),
    "schedule": dict(title="Guard Shift Schedule Report",
        sql="SELECT sc.*, s.full_name, s.job_title FROM shift_schedule sc JOIN security_staff s ON s.id=sc.staff_id",
        date="sc.shift_date", order="sc.shift_date, FIELD(sc.shift,'Day','Mid','Night'), s.full_name",
        cols=[("Date", "shift_date"), ("Guard", "full_name"), ("Position", "job_title"), ("Shift", "shift"), ("Post", "post")],
        summary=lambda rs: {"Shifts": len(rs), "Guards": len({r["staff_id"] for r in rs})}),
    "staff": dict(title="Security Personnel List", dated=False, sql="SELECT * FROM security_staff", order="full_name",
        cols=[("Staff ID", "staff_no"), ("Name", "full_name"), ("Position", "job_title"), ("Post", "post"),
              ("Contact", "contact"), ("Hired", "date_hired"), ("Status", "status")],
        summary=lambda rs: {"Personnel": len(rs), "Active": cnt(rs, "status", "Active")}),
})

def build_report(kind):
    kind = kind if kind in REPORT_DEFS else "incidents"
    d = REPORT_DEFS[kind]
    d_from, d_to = date_range()
    where, args, filters = [], [], []
    if d.get("dated", True):
        where.append(f"{d['date']} BETWEEN %s AND %s")
        args += [d_from, d_to]
    where += d.get("where", [])
    if kind == "incidents":
        w, a, chosen = incident_filters()
        where += w
        args += a
        filters = [f"{k.capitalize()}: {v}" for k, v in chosen.items() if v]
    sql = d["sql"] + (" WHERE " + " AND ".join(where) if where else "") + f" ORDER BY {d['order']}"
    rows = q(sql, args)
    if d.get("post"):
        for r in rows:
            d["post"](r)
    return dict(kind=kind, title=d["title"], dated=d.get("dated", True), d_from=d_from, d_to=d_to,
                filters=filters, headers=[c[0] for c in d["cols"]],
                rows=[[fmt(r.get(c[1])) for c in d["cols"]] for r in rows], summary=d["summary"](rows))

@app.route("/reports")
@login_required
def reports():
    d_from, d_to, chosen, rows = report_data()
    stats = dict(
        total=len(rows), resolved=cnt(rows, "status", "resolved"), avg_hours=avg_hours(rows),
        visitors=safe_count("SELECT COUNT(*) c FROM visitors WHERE DATE(time_in) BETWEEN %s AND %s", (d_from, d_to)),
        patrols=safe_count("SELECT COUNT(*) c FROM patrol_logs WHERE DATE(patrolled_at) BETWEEN %s AND %s", (d_from, d_to)))
    return render_template(
        "reports.html", rows=rows, d_from=d_from, d_to=d_to, chosen=chosen, stats=stats,
        by_sev={s: cnt(rows, "severity", s) for s in SEVERITIES},
        by_status={s: cnt(rows, "status", s) for s in STATUSES},
        by_cat={c: cnt(rows, "category", c) for c in CATEGORIES})

@app.route("/reports/print")
@login_required
def print_report():
    me = q("SELECT full_name, job_title, employee_no FROM users WHERE id=%s", (session["user_id"],), one=True)
    return render_template("report_print.html", rep=build_report(request.args.get("type", "incidents")),
                           me=me, generated=datetime.now())

@app.route("/reports/csv")
@login_required
def csv_report():
    rep = build_report(request.args.get("type", "incidents"))
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(rep["headers"])
    for row in rep["rows"]:
        w.writerow([csv_safe(c) for c in row])
    name = f"{rep['kind']}_report_{rep['d_from']}_to_{rep['d_to']}.csv" if rep["dated"] else f"{rep['kind']}_report.csv"
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={name}"})

# ================================ PROFILE ==================================
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    uid = session["user_id"]
    if request.method == "POST":
        f = request.form
        name = f["full_name"].strip()
        username = f.get("username", "").strip()
        email = f["email"].strip().lower() or None
        emp_no = f["employee_no"].strip() or None
        err = account_error(name, email, emp_no, username=username, exclude_id=uid)
        if not username:
            flash("Username is required.", "error")
        elif err:
            flash(err, "error")
        else:
            q("""UPDATE users SET full_name=%s, username=%s, email=%s, phone=%s,
                 job_title=%s, employee_no=%s WHERE id=%s""",
              (name, username, email, f["phone"].strip(), f["job_title"].strip(), emp_no, uid))
            session["name"] = name
            flash("Profile updated.", "success")
            return redirect(url_for("profile"))
    return render_template("profile.html", u=q("SELECT * FROM users WHERE id=%s", (uid,), one=True), editable=True)


def read_profile_photo():
    photo = request.files.get("profile_photo")
    if not photo or not photo.filename:
        return None, None, "Choose a picture to upload."
    extension = Path(photo.filename).suffix.lower()
    image_type = INCIDENT_IMAGE_TYPES.get(extension)
    if not image_type:
        return None, None, "Upload a JPG, PNG, or WebP profile picture."
    data = photo.read(6 * 1024 * 1024 + 1)
    if len(data) > 6 * 1024 * 1024:
        return None, None, "The profile picture must be 6 MB or smaller."
    if not image_type[1](data):
        return None, None, "The uploaded file does not appear to be a valid image."
    return data, extension, None


@app.route("/profile/photo", methods=["POST"])
@login_required
def update_profile_photo():
    data, extension, error = read_profile_photo()
    if error:
        flash(error, "error")
        return redirect(url_for("profile"))
    uid = session["user_id"]
    current = q("SELECT profile_photo_filename FROM users WHERE id=%s", (uid,), one=True)
    old_photo = current["profile_photo_filename"] if current else None
    filename = f"{uuid.uuid4().hex}{extension}"
    PROFILE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    photo_path = PROFILE_UPLOAD_DIR / filename
    photo_path.write_bytes(data)
    try:
        q("UPDATE users SET profile_photo_filename=%s WHERE id=%s", (filename, uid))
    except Exception:
        if photo_path.exists():
            photo_path.unlink()
        raise
    if old_photo:
        old_path = PROFILE_UPLOAD_DIR / Path(old_photo).name
        if old_path.exists():
            old_path.unlink()
    session["profile_photo_filename"] = filename
    flash("Profile picture updated.", "success")
    return redirect(url_for("profile"))


@app.route("/profile/photo/remove", methods=["POST"])
@login_required
def remove_profile_photo():
    uid = session["user_id"]
    current = q("SELECT profile_photo_filename FROM users WHERE id=%s", (uid,), one=True)
    q("UPDATE users SET profile_photo_filename=NULL WHERE id=%s", (uid,))
    if current and current["profile_photo_filename"]:
        photo_path = PROFILE_UPLOAD_DIR / Path(current["profile_photo_filename"]).name
        if photo_path.exists():
            photo_path.unlink()
    session["profile_photo_filename"] = None
    flash("Profile picture removed.", "success")
    return redirect(url_for("profile"))


@app.route("/users/<int:uid>/photo")
@login_required
def profile_photo(uid):
    user = q("SELECT profile_photo_filename FROM users WHERE id=%s", (uid,), one=True)
    if not user or not user["profile_photo_filename"]:
        abort(404)
    filename = user["profile_photo_filename"]
    if Path(filename).name != filename or Path(filename).suffix.lower() not in INCIDENT_IMAGE_TYPES:
        abort(404)
    response = send_from_directory(PROFILE_UPLOAD_DIR, filename, max_age=0)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "private, no-store"
    return response

@app.route("/profile/password", methods=["POST"])
@login_required
def change_password():
    f = request.form
    u = q("SELECT password_hash FROM users WHERE id=%s", (session["user_id"],), one=True)
    if not check_password_hash(u["password_hash"], f["current"]):
        flash("Your current password is incorrect.", "error")
    elif len(f["new"]) < 8:
        flash("New password must be at least 8 characters.", "error")
    elif f["new"] != f["confirm"]:
        flash("New passwords do not match.", "error")
    else:
        q("UPDATE users SET password_hash=%s WHERE id=%s", (generate_password_hash(f["new"]), session["user_id"]))
        flash("Password changed.", "success")
    return redirect(url_for("profile"))

# ============================= ADMIN ACCOUNTS ==============================
@app.route("/users", methods=["GET", "POST"])
@login_required
def users():
    if request.method == "POST":
        f = request.form
        name, user = f["full_name"].strip(), f["username"].strip()
        email = f["email"].strip().lower() or None
        emp_no = f["employee_no"].strip() or None
        err = account_error(name, email, emp_no, username=user)
        if not user:
            flash("Username is required.", "error")
        elif err:
            flash(err, "error")
        elif len(f["password"]) < 8:
            flash("Password must be at least 8 characters.", "error")
        else:
            q("""INSERT INTO users (full_name, username, password_hash, role, is_active,
                                    email, phone, job_title, employee_no)
                 VALUES (%s,%s,%s,'admin',1,%s,%s,%s,%s)""",
              (name, user, generate_password_hash(f["password"]), email,
               f["phone"].strip(), f["job_title"].strip(), emp_no))
            flash(f"User account for {name} created.", "success")
    rows = q("""SELECT id, full_name, username, job_title, email, phone, employee_no,
                       profile_photo_filename,
                       is_active, reset_requested, last_login, created_at
                FROM users ORDER BY is_active, reset_requested DESC, full_name""")
    return render_template("users.html", users=rows)

@app.route("/users/<int:uid>")
@login_required
def user_profile(uid):
    if uid == session["user_id"]:
        return redirect(url_for("profile"))
    u = q("SELECT * FROM users WHERE id=%s", (uid,), one=True)
    if not u:
        flash("Account not found.", "error")
        return redirect(url_for("users"))
    return render_template("profile.html", u=u, editable=False)

@app.route("/users/<int:uid>/status", methods=["POST"])
@login_required
def user_status(uid):
    if uid == session["user_id"]:
        flash("You can't change your own status.", "error")
    else:
        active = 1 if request.form.get("active") == "1" else 0
        q("UPDATE users SET is_active=%s WHERE id=%s", (active, uid))
        flash("Account approved." if active else "Account deactivated.", "success")
    return redirect(url_for("users"))

@app.route("/users/<int:uid>/reset-code", methods=["POST"])
@login_required
def issue_code(uid):
    code = f"{secrets.randbelow(10**8):08d}"
    q("UPDATE users SET reset_code_hash=%s, reset_expires=%s WHERE id=%s",
      (generate_password_hash(code), datetime.now() + timedelta(minutes=15), uid))
    flash(f"Reset code: {code}  (valid 15 minutes). Give it to the admin in person.", "code")
    return redirect(url_for("users"))

if __name__ == "__main__":
    app.run(debug=True)