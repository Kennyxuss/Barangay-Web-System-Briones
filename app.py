"""
BarangayConnect - Barangay Management and Information System
Flask application entry point.

Run with:  python app.py   then open http://127.0.0.1:5000
"""
import csv
import io
import os
import re
import secrets
import sqlite3
from datetime import date, datetime
from functools import wraps

from flask import (
    Flask, Response, abort, flash, g, redirect, render_template, request,
    session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

import database
from config import Config

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config.from_object(Config)

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

DOCUMENT_TYPES = database.DOCUMENT_TYPES


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql: str, params=()) -> list:
    return get_db().execute(sql, params).fetchall()


def query_one(sql: str, params=()):
    return get_db().execute(sql, params).fetchone()


def execute(sql: str, params=()) -> int:
    """Run a write statement, commit, return lastrowid."""
    db = get_db()
    cur = db.execute(sql, params)
    db.commit()
    return cur.lastrowid


def get_or_404(table: str, record_id: int):
    if table not in {"users", "residents", "officials", "announcements",
                     "events", "document_requests", "complaints", "blotter",
                     "activity_logs", "inquiries"}:
        abort(404)
    row = query_one(f"SELECT * FROM {table} WHERE id = ?", (record_id,))
    if row is None:
        abort(404)
    return row


# ---------------------------------------------------------------------------
# Security: sessions, roles, CSRF
# ---------------------------------------------------------------------------

def current_user():
    return session.get("user")


def login_required(roles=None):
    """Decorator protecting private routes. Optionally restrict by role."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if user is None:
                return redirect(url_for("login", next=request.path))
            if roles is not None and user.get("role") not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.before_request
def csrf_protect():
    """Reject unsafe POST requests that lack a valid CSRF token."""
    if request.method != "POST":
        return
    sent = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token")
    expected = session.get("_csrf_token")
    if not expected or not sent or not secrets.compare_digest(expected, sent):
        abort(400, description="Invalid or missing CSRF token.")


def generate_csrf_token() -> str:
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


# Register as a real Jinja global so macros can use it without "with context"
app.jinja_env.globals["csrf_token"] = generate_csrf_token


def log_activity(action: str, description: str = "") -> None:
    user = current_user()
    execute(
        "INSERT INTO activity_logs (user_id, action, description, timestamp, ip_address)"
        " VALUES (?,?,?,?,?)",
        (user["id"] if user else None, action, description,
         datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
         request.headers.get("X-Forwarded-For", request.remote_addr or "")),
    )


# ---------------------------------------------------------------------------
# Uploads
# ---------------------------------------------------------------------------

def save_image(file_storage) -> str | None:
    """Validate + persist an uploaded image; returns stored filename."""
    if file_storage is None or not getattr(file_storage, "filename", ""):
        return None
    filename = secure_filename(file_storage.filename)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in app.config["ALLOWED_IMAGE_EXTENSIONS"]:
        flash("Invalid image type. Allowed: png, jpg, jpeg, webp, gif.", "danger")
        return None
    new_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(6)}.{ext}"
    file_storage.save(os.path.join(app.config["UPLOAD_FOLDER"], new_name))
    return new_name


def delete_image(filename: str | None) -> None:
    if not filename:
        return
    path = os.path.join(app.config["UPLOAD_FOLDER"], os.path.basename(filename))
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------

STATUS_BADGE = {
    "Pending": "warning text-dark", "Processing": "info text-dark",
    "Approved": "primary", "Released": "success", "Rejected": "danger",
    "Investigating": "info text-dark", "Resolved": "success", "Closed": "secondary",
    "Published": "success", "Unpublished": "secondary",
    "Scheduled": "primary", "Ongoing": "warning text-dark",
    "Completed": "success", "Cancelled": "danger",
    "Open": "warning text-dark", "Under Investigation": "info text-dark",
    "Settled": "success", "Active": "success", "Inactive": "secondary",
    "Registered": "success", "Not Registered": "secondary",
}

from markupsafe import Markup


def _status_badge(label) -> str:
    """Render a colored status badge (registered as a Jinja global)."""
    cls = STATUS_BADGE.get(label or "", "secondary")
    return Markup(
        f'<span class="badge status-badge bg-{cls}">{label}</span>')


app.jinja_env.globals["status_badge"] = _status_badge


def _parse_date(value: str):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value.strip(), fmt)
        except (ValueError, AttributeError):
            continue
    return None


@app.template_filter("datefmt")
def datefmt(value, fmt="%B %d, %Y"):
    parsed = _parse_date(value or "")
    return parsed.strftime(fmt) if parsed else (value or "—")


@app.template_filter("timefmt")
def timefmt(value):
    try:
        hour, minute = (value or "").split(":")[:2]
        h = int(hour)
        ampm = "AM" if h < 12 else "PM"
        h12 = h % 12 or 12
        return f"{h12}:{minute} {ampm}"
    except (ValueError, AttributeError):
        return value or "—"


@app.template_filter("age")
def age(birth_date):
    parsed = _parse_date(birth_date or "")
    if not parsed:
        return None
    today = date.today()
    years = today.year - parsed.year
    if (today.month, today.day) < (parsed.month, parsed.day):
        years -= 1
    return max(years, 0)


@app.context_processor
def inject_globals():
    settings_row = query_one("SELECT * FROM system_settings WHERE id = 1")
    settings = dict(settings_row) if settings_row else {}
    return {
        "settings": settings,
        "system_name": Config.SYSTEM_NAME,
        "tagline": Config.SYSTEM_TAGLINE,
        "current_year": date.today().year,
        "current_date": datetime.now().strftime("%B %d, %Y"),
        "current_user": current_user(),
        "document_types": DOCUMENT_TYPES,
    }


def full_name(r) -> str:
    parts = [r["first_name"]]
    if r["middle_name"]:
        parts.append(r["middle_name"])
    parts.append(r["last_name"])
    if r["suffix"]:
        parts.append(r["suffix"])
    return " ".join(parts)


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def valid_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email or ""))


# ===========================================================================
# PUBLIC WEBSITE
# ===========================================================================

@app.route("/")
def home():
    announcements = query(
        "SELECT a.*, u.full_name AS author FROM announcements a "
        "LEFT JOIN users u ON u.id = a.author_id "
        "WHERE a.status = 'Published' ORDER BY a.published_date DESC LIMIT 3")
    events = query(
        "SELECT * FROM events WHERE event_date >= ? AND status != 'Cancelled' "
        "ORDER BY event_date ASC LIMIT 3", (date.today().isoformat(),))
    stats = {
        "residents": query_one("SELECT COUNT(*) c FROM residents")["c"],
        "officials": query_one("SELECT COUNT(*) c FROM officials WHERE status='Active'")["c"],
    }
    return render_template("index.html", announcements=announcements,
                           events=events, stats=stats)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/officials")
def public_officials():
    rows = query(
        """SELECT * FROM officials WHERE status = 'Active'
           ORDER BY CASE position
               WHEN 'Punong Barangay' THEN 1
               WHEN 'Barangay Kagawad' THEN 2
               WHEN 'SK Chairperson' THEN 3
               WHEN 'Barangay Secretary' THEN 4
               WHEN 'Barangay Treasurer' THEN 5
               ELSE 9 END, full_name""")
    captain = [o for o in rows if o["position"] == "Punong Barangay"]
    kagawads = [o for o in rows if o["position"] == "Barangay Kagawad"]
    sk = [o for o in rows if o["position"] == "SK Chairperson"]
    appointive = [o for o in rows if o["position"] in ("Barangay Secretary", "Barangay Treasurer")]
    others = [o for o in rows if o["position"] not in
              ("Punong Barangay", "Barangay Kagawad", "SK Chairperson",
               "Barangay Secretary", "Barangay Treasurer")]
    return render_template("officials.html", captain=captain, kagawads=kagawads,
                           sk=sk, appointive=appointive, others=others)


@app.route("/announcements")
def public_announcements():
    q = request.args.get("q", "").strip()
    sql = ("SELECT a.*, u.full_name AS author FROM announcements a "
           "LEFT JOIN users u ON u.id = a.author_id WHERE a.status = 'Published'")
    params = []
    if q:
        sql += " AND (a.title LIKE ? OR a.content LIKE ?)"
        params += [f"%{q}%", f"%{q}%"]
    sql += " ORDER BY a.published_date DESC"
    announcements = query(sql, params)
    return render_template("announcements.html", announcements=announcements, q=q)


@app.route("/announcements/<int:announcement_id>")
def announcement_detail(announcement_id):
    row = query_one(
        "SELECT a.*, u.full_name AS author FROM announcements a "
        "LEFT JOIN users u ON u.id = a.author_id WHERE a.id = ? AND a.status='Published'",
        (announcement_id,))
    if row is None:
        abort(404)
    others = query(
        "SELECT id, title, published_date FROM announcements "
        "WHERE status='Published' AND id != ? ORDER BY published_date DESC LIMIT 5",
        (announcement_id,))
    return render_template("announcement_detail.html", item=row, others=others)


@app.route("/events")
def public_events():
    today = date.today().isoformat()
    upcoming = query(
        "SELECT * FROM events WHERE event_date >= ? AND status != 'Cancelled' "
        "ORDER BY event_date ASC, start_time ASC", (today,))
    past = query(
        "SELECT * FROM events WHERE event_date < ? ORDER BY event_date DESC LIMIT 10", (today,))
    return render_template("events.html", upcoming=upcoming, past=past)


@app.route("/services")
def services():
    services_info = [
        ("Barangay Clearance", "bi-patch-check", "Certification that the holder is a bona fide resident with no pending case in the barangay."),
        ("Certificate of Residency", "bi-house-check", "Proof that the applicant is an actual resident of the barangay."),
        ("Certificate of Indigency", "bi-heart-pulse", "Issued to indigent residents availing medical, burial, or educational assistance."),
        ("Barangay Business Clearance", "bi-shop", "Required before operating a business within the barangay."),
        ("Certificate of Good Moral Character", "bi-award", "Certification of the resident's good standing in the community."),
        ("Other Services", "bi-three-dots", "Notarization of barangay-related documents, referrals, and certifications upon evaluation."),
    ]
    return render_template("services.html", services_info=services_info)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()
        errors = []
        if len(name) < 2:
            errors.append("Please enter your name.")
        if email and not valid_email(email):
            errors.append("Please enter a valid email address.")
        if len(subject) < 3:
            errors.append("Please enter a subject.")
        if len(message) < 5:
            errors.append("Please enter your message.")
        if errors:
            for err in errors:
                flash(err, "danger")
        else:
            execute(
                "INSERT INTO inquiries (name, email, subject, message, created_at)"
                " VALUES (?,?,?,?,?)",
                (name, email or None, subject, message,
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            log_activity("INQUIRY_SUBMITTED", f"Inquiry '{subject}' submitted by {name}")
            flash("Thank you! Your inquiry has been received. The barangay office will get back to you soon.", "success")
            return redirect(url_for("contact"))
    return render_template("contact.html")


# ===========================================================================
# AUTHENTICATION
# ===========================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        u = current_user()
        if u.get("role") == "resident":
            return redirect(url_for("resident_dashboard"))
        return redirect(url_for("admin_dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = query_one("SELECT * FROM users WHERE username = ?", (username,))
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "danger")
        elif user["status"] == "pending":
            flash("Your account is pending approval by the barangay admin. Please wait or contact the barangay hall.", "warning")
        elif user["status"] != "active":
            flash("This account has been deactivated. Contact the administrator.", "warning")
        else:
            session.clear()
            session["user"] = {"id": user["id"], "username": user["username"],
                               "full_name": user["full_name"], "role": user["role"],
                               "resident_id": user["resident_id"]}
            generate_csrf_token()
            log_activity("LOGIN", f"{user['role'].title()} '{user['username']}' logged in.")
            dest = request.args.get("next")
            if dest and dest.startswith("/") and not dest.startswith("//"):
                return redirect(dest)
            if user["role"] == "resident":
                return redirect(url_for("resident_dashboard"))
            return redirect(url_for("admin_dashboard"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Self-registration for residents — full info like admin view, pending admin approval."""
    if current_user():
        return redirect(url_for("home"))
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        # Resident full fields (mirror admin/resident_form.html)
        first_name = request.form.get("first_name", "").strip()
        middle_name = request.form.get("middle_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        suffix = request.form.get("suffix", "").strip()
        sex = request.form.get("sex", "").strip()
        birth_date = request.form.get("birth_date", "").strip()
        birth_place = request.form.get("birth_place", "").strip()
        civil_status = request.form.get("civil_status", "").strip()
        nationality = request.form.get("nationality", "").strip() or "Filipino"
        religion = request.form.get("religion", "").strip()
        occupation = request.form.get("occupation", "").strip()
        contact_number = request.form.get("contact_number", "").strip()
        email = request.form.get("email", "").strip()
        address = request.form.get("address", "").strip()
        purok = request.form.get("purok", "").strip()
        voter_status = request.form.get("voter_status", "").strip()
        residency_status = request.form.get("residency_status", "").strip()

        errors = []
        if not re.fullmatch(r"[a-z0-9_.]{3,30}", username or ""):
            errors.append("Username must be 3-30 chars (letters, numbers, dot, underscore).")
        if query_one("SELECT id FROM users WHERE username=?", (username,)):
            errors.append("That username is already taken.")
        if len(full_name) < 2:
            errors.append("Full name is required.")
        if email and not valid_email(email):
            errors.append("Email is not valid.")
        if len(password) < 6:
            errors.append("Password must be at least 6 characters.")
        if password != confirm:
            errors.append("Passwords do not match.")
        # Full resident validation (same as admin)
        if len(first_name) < 2:
            errors.append("First name is required (min. 2 characters).")
        if len(last_name) < 2:
            errors.append("Last name is required (min. 2 characters).")
        if sex not in ("Male", "Female"):
            errors.append("Please select a sex.")
        try:
            bday = datetime.strptime(birth_date, "%Y-%m-%d").date()
            if bday > date.today():
                errors.append("Birth date cannot be in the future.")
            elif bday.year < 1900:
                errors.append("Birth date seems invalid.")
        except ValueError:
            errors.append("A valid birth date is required.")
        if not address:
            errors.append("Address is required.")
        if not purok:
            errors.append("Purok is required.")
        if contact_number and not re.fullmatch(r"[0-9()+\-\s]{7,20}", contact_number):
            errors.append("Contact number contains invalid characters.")
        if email and not valid_email(email):
            errors.append("Email address is not valid.")
        # Optional fields validation
        if voter_status and voter_status not in ("Registered", "Not Registered"):
            errors.append("Invalid voter status.")
        if residency_status and residency_status not in ("Permanent", "Renting", "Transient"):
            errors.append("Invalid residency status.")
        if civil_status and civil_status not in ("Single", "Married", "Widowed", "Separated"):
            errors.append("Invalid civil status.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("register.html", form=request.form.to_dict()), 400

        # Handle photo upload (same as admin, 5MB, image only)
        photo = None
        if request.files:
            photo = save_image(request.files.get("photo"))
            # save_image already flashes on invalid type; if it returns None but file was provided with bad type, treat as error?
            # We already checked photo via save_image; if file provided but invalid, save_image returns None and flashes. Allow continue without photo.

        # Try to link to existing resident (exact name + birth_date) to avoid duplicate — same as before
        existing_resident = query_one(
            "SELECT * FROM residents WHERE LOWER(first_name)=LOWER(?) AND LOWER(last_name)=LOWER(?) AND birth_date=? LIMIT 1",
            (first_name, last_name, birth_date))
        resident_pk = None
        if existing_resident:
            linked_user = query_one("SELECT id FROM users WHERE resident_id=?", (existing_resident["id"],))
            if linked_user is None:
                resident_pk = existing_resident["id"]
                # Don't overwrite existing resident's core data automatically; admin will review. Just update updated_at.
                # Optionally update photo if provided
                if photo:
                    # replace photo if new one provided
                    old_photo = existing_resident["photo"]
                    execute("UPDATE residents SET photo=?, updated_at=? WHERE id=?",
                            (photo, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), resident_pk))
                    if old_photo:
                        delete_image(old_photo)
                # For pending review, we still create pending user linked to existing resident; no need to update other fields now
            else:
                if photo:
                    delete_image(photo)
                flash("A resident record with that name and birth date already has an account. Please contact the barangay hall to link your account.", "warning")
                return render_template("register.html", form=request.form.to_dict()), 400

        if resident_pk is None:
            rid = database.next_number("BRGY", "residents", "resident_id")
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            resident_pk = execute(
                """INSERT INTO residents
                   (resident_id, first_name, middle_name, last_name, suffix, sex, birth_date,
                    birth_place, civil_status, nationality, religion, occupation,
                    contact_number, email, address, purok, voter_status, residency_status,
                    photo, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rid, first_name, middle_name or None, last_name, suffix or None, sex, birth_date,
                 birth_place or None, civil_status or None, nationality, religion or None, occupation or None,
                 contact_number or None, email or None, address, purok,
                 voter_status or None, residency_status or None,
                 photo, now, now))

        # Create user linked to resident as PENDING — admin must approve before login
        execute(
            "INSERT INTO users (username, password_hash, full_name, role, resident_id, email, status, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (username, generate_password_hash(password), full_name, "resident", resident_pk, email or None, "pending",
             datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        log_activity("REGISTER_RESIDENT", f"New resident account '{username}' pending approval (resident {resident_pk})")
        flash("Registration submitted! Your account is now pending admin approval. You will be able to log in once the barangay admin approves your registration. Please wait or contact the barangay hall.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form={})


@app.route("/logout")
@login_required()
def logout():
    log_activity("LOGOUT", f"{current_user()['username']} logged out.")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


# ===========================================================================
# RESIDENT PORTAL (resident role)
# ===========================================================================

def _get_my_resident():
    """Return the residents row linked to current resident user, or None."""
    user = current_user()
    if not user or user.get("role") != "resident":
        return None
    rid = user.get("resident_id")
    if rid:
        return query_one("SELECT * FROM residents WHERE id = ?", (rid,))
    # fallback: try to find by username/full_name? return None
    return None


def resident_required(view):
    """Decorator: must be logged in as resident."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login", next=request.path))
        if user.get("role") != "resident":
            abort(403)
        if user.get("status") not in (None, "active"):
            # status is in session? session doesn't have status; check DB
            db_user = query_one("SELECT status FROM users WHERE id=?", (user["id"],))
            if db_user and db_user["status"] != "active":
                flash("Your account is not active. Contact barangay hall.", "warning")
                return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/resident")
@app.route("/resident/dashboard")
@login_required(roles=["resident"])
def resident_dashboard():
    resident = _get_my_resident()
    if resident is None:
        flash("Your account is not linked to a resident record. Please contact the barangay hall.", "warning")
        return render_template("resident/dashboard.html", resident=None, my_docs=[], my_complaints=[])
    my_docs = query(
        "SELECT * FROM document_requests WHERE resident_id = ? ORDER BY request_date DESC, id DESC LIMIT 5",
        (resident["id"],))
    my_complaints = query(
        "SELECT * FROM complaints WHERE resident_id = ? ORDER BY date_reported DESC, id DESC LIMIT 5",
        (resident["id"],))
    # Also include requests where resident_id is null but name matches (legacy)
    # Counts
    doc_pending = query_one("SELECT COUNT(*) c FROM document_requests WHERE resident_id=? AND status IN ('Pending','Processing')", (resident["id"],))["c"]
    cmp_open = query_one("SELECT COUNT(*) c FROM complaints WHERE resident_id=? AND status IN ('Pending','Investigating')", (resident["id"],))["c"]
    return render_template("resident/dashboard.html", resident=resident, my_docs=my_docs,
                           my_complaints=my_complaints, doc_pending=doc_pending, cmp_open=cmp_open)


@app.route("/resident/profile")
@login_required(roles=["resident"])
def resident_profile():
    resident = _get_my_resident()
    if resident is None:
        abort(404)
    return render_template("resident/profile.html", resident=resident)


@app.route("/resident/profile/edit", methods=["GET", "POST"])
@login_required(roles=["resident"])
def resident_profile_edit():
    resident = _get_my_resident()
    if resident is None:
        abort(404)
    if request.method == "POST":
        # Allow editing limited fields: contact, email, address, purok, occupation, civil_status
        contact = request.form.get("contact_number", "").strip()
        email = request.form.get("email", "").strip()
        address = request.form.get("address", "").strip()
        purok = request.form.get("purok", "").strip()
        occupation = request.form.get("occupation", "").strip()
        civil_status = request.form.get("civil_status", "").strip()
        errors = []
        if contact and not re.fullmatch(r"[0-9()+\-\s]{7,20}", contact):
            errors.append("Contact number invalid.")
        if email and not valid_email(email):
            errors.append("Email invalid.")
        if not address:
            errors.append("Address required.")
        if not purok:
            errors.append("Purok required.")
        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("resident/profile_edit.html", resident=dict(resident, **request.form.to_dict()))
        execute(
            "UPDATE residents SET contact_number=?, email=?, address=?, purok=?, occupation=?, civil_status=?, updated_at=? WHERE id=?",
            (contact or None, email or None, address, purok, occupation or None, civil_status or None,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"), resident["id"]))
        log_activity("UPDATE_OWN_PROFILE", f"Resident {resident['resident_id']} updated own profile")
        flash("Profile updated successfully!", "success")
        # refresh session full_name if needed?
        return redirect(url_for("resident_profile"))
    return render_template("resident/profile_edit.html", resident=resident)


@app.route("/resident/documents")
@login_required(roles=["resident"])
def resident_my_documents():
    resident = _get_my_resident()
    if resident is None:
        abort(404)
    docs = query("SELECT d.*, u.full_name AS processor FROM document_requests d LEFT JOIN users u ON u.id=d.processed_by WHERE d.resident_id=? ORDER BY d.request_date DESC, d.id DESC", (resident["id"],))
    return render_template("resident/my_documents.html", docs=docs, resident=resident)


@app.route("/resident/documents/request", methods=["GET", "POST"])
@login_required(roles=["resident"])
def resident_request_document():
    resident = _get_my_resident()
    if resident is None:
        abort(404)
    if request.method == "POST":
        doc_type = request.form.get("document_type", "").strip()
        purpose = request.form.get("purpose", "").strip()
        additional = request.form.get("additional_info", "").strip()
        errors = []
        if doc_type not in DOCUMENT_TYPES:
            errors.append("Invalid document type.")
        if len(purpose) < 3:
            errors.append("Purpose required.")
        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("resident/request_document_logged.html", resident=resident, form=request.form.to_dict()), 400
        number = database.next_number("REQ", "document_requests", "request_number")
        # auto-fill from resident
        req_name = full_name(resident)
        execute(
            """INSERT INTO document_requests
               (request_number, resident_id, requester_name, contact_number, email, address,
                document_type, purpose, additional_info, request_date, status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (number, resident["id"], req_name, resident["contact_number"], resident["email"],
             resident["address"], doc_type, purpose, additional or None, date.today().isoformat(), "Pending"))
        log_activity("SUBMIT_REQUEST_RESIDENT", f"Resident {resident['resident_id']} requested {doc_type} ({number})")
        flash(f"Request submitted! Your request number is {number}.", "success")
        return redirect(url_for("resident_my_documents"))
    return render_template("resident/request_document_logged.html", resident=resident, form={})


@app.route("/resident/complaints")
@login_required(roles=["resident"])
def resident_my_complaints():
    resident = _get_my_resident()
    if resident is None:
        abort(404)
    comps = query("SELECT * FROM complaints WHERE resident_id=? ORDER BY date_reported DESC, id DESC", (resident["id"],))
    return render_template("resident/my_complaints.html", complaints=comps, resident=resident)


@app.route("/resident/complaints/new", methods=["GET", "POST"])
@login_required(roles=["resident"])
def resident_file_complaint():
    resident = _get_my_resident()
    if resident is None:
        abort(404)
    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()
        contact = request.form.get("contact_number", "").strip() or resident["contact_number"] or ""
        email = request.form.get("email", "").strip() or resident["email"] or ""
        errors = []
        if len(subject) < 5:
            errors.append("Subject required (min 5).")
        if len(description) < 10:
            errors.append("Description required (min 10).")
        if contact and not re.fullmatch(r"[0-9()+\-\s]{7,20}", contact):
            errors.append("Contact invalid.")
        if email and not valid_email(email):
            errors.append("Email invalid.")
        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("resident/complaint_logged.html", resident=resident, form=request.form.to_dict()), 400
        number = database.next_number("CMP", "complaints", "complaint_number")
        now = datetime.now()
        execute(
            """INSERT INTO complaints
               (complaint_number, resident_id, complainant_name, contact_number, email, subject, description, location, date_reported, status, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (number, resident["id"], full_name(resident), contact or None, email or None, subject, description, location or None, now.strftime("%Y-%m-%d"), "Pending", now.strftime("%Y-%m-%d %H:%M:%S")))
        log_activity("SUBMIT_COMPLAINT_RESIDENT", f"Resident {resident['resident_id']} filed complaint {number}")
        flash(f"Complaint submitted! Your complaint number is {number}.", "success")
        return redirect(url_for("resident_my_complaints"))
    return render_template("resident/complaint_logged.html", resident=resident, form={})


@app.route("/resident/change-password", methods=["GET", "POST"])
@login_required(roles=["resident"])
def resident_change_password():
    if request.method == "POST":
        cur_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        user = query_one("SELECT * FROM users WHERE id=?", (current_user()["id"],))
        if not check_password_hash(user["password_hash"], cur_pw):
            flash("Current password is incorrect.", "danger")
        elif len(new_pw) < 6:
            flash("New password must be at least 6 characters.", "danger")
        elif new_pw != confirm:
            flash("Passwords do not match.", "danger")
        else:
            execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new_pw), user["id"]))
            log_activity("CHANGE_PASSWORD", "Resident changed own password")
            flash("Password changed successfully!", "success")
            return redirect(url_for("resident_dashboard"))
    return render_template("resident/change_password.html")


# Admin: create resident account from residents list (hybrid admin-created)
@app.route("/admin/residents/<int:resident_pk>/create-account", methods=["GET", "POST"])
@login_required(roles=["admin"])
def admin_create_resident_account(resident_pk):
    resident = get_or_404("residents", resident_pk)
    # check already has account
    existing = query_one("SELECT * FROM users WHERE resident_id=?", (resident_pk,))
    if existing:
        flash(f"This resident already has an account: {existing['username']} ({existing['status']})", "warning")
        return redirect(url_for("admin_residents"))
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        full_name = request.form.get("full_name", "").strip() or full_name(resident)
        email = request.form.get("email", "").strip() or resident["email"] or ""
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        errors = []
        if not re.fullmatch(r"[a-z0-9_.]{3,30}", username or ""):
            errors.append("Invalid username (3-30 chars, a-z 0-9 . _).")
        if query_one("SELECT id FROM users WHERE username=?", (username,)):
            errors.append("Username already taken.")
        if len(full_name) < 2:
            errors.append("Full name required.")
        if email and not valid_email(email):
            errors.append("Invalid email.")
        if len(password) < 6:
            errors.append("Password must be >=6 chars.")
        if password != confirm:
            errors.append("Passwords do not match.")
        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("admin/create_resident_account.html", resident=resident, form=request.form.to_dict())
        execute(
            "INSERT INTO users (username, password_hash, full_name, role, resident_id, email, status, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (username, generate_password_hash(password), full_name, "resident", resident_pk, email or None, "active", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        log_activity("CREATE_RESIDENT_ACCOUNT", f"Admin created resident account '{username}' for {resident['resident_id']}")
        flash(f"Resident account '{username}' created successfully!", "success")
        return redirect(url_for("admin_residents"))
    return render_template("admin/create_resident_account.html", resident=resident, form={})


# ===========================================================================
# ADMIN: PENDING RESIDENT REGISTRATIONS (review before accept)
# ===========================================================================

@app.route("/admin/registrations")
@login_required(roles=["admin"])
def admin_pending_registrations():
    pending = query("""
        SELECT u.*, r.resident_id as r_resident_id, r.first_name, r.middle_name, r.last_name, r.suffix,
               r.sex, r.birth_date, r.birth_place, r.civil_status, r.nationality, r.religion, r.occupation,
               r.contact_number as r_contact, r.email as r_email, r.address as r_address, r.purok as r_purok,
               r.voter_status, r.residency_status, r.photo as r_photo, r.created_at as r_created
        FROM users u LEFT JOIN residents r ON r.id = u.resident_id
        WHERE u.role='resident' AND u.status='pending'
        ORDER BY u.created_at DESC
    """)
    return render_template("admin/pending_registrations.html", pending=pending)


@app.route("/admin/registrations/<int:user_id>")
@login_required(roles=["admin"])
def admin_registration_view(user_id):
    user = get_or_404("users", user_id)
    if user["role"] != "resident" or user["status"] != "pending":
        abort(404)
    resident = None
    if user["resident_id"]:
        resident = query_one("SELECT * FROM residents WHERE id=?", (user["resident_id"],))
    return render_template("admin/registration_view.html", user=user, resident=resident)


@app.route("/admin/registrations/<int:user_id>/approve", methods=["POST"])
@login_required(roles=["admin"])
def admin_registration_approve(user_id):
    user = get_or_404("users", user_id)
    if user["role"] != "resident" or user["status"] != "pending":
        flash("Only pending resident accounts can be approved.", "warning")
        return redirect(url_for("admin_pending_registrations"))
    execute("UPDATE users SET status='active' WHERE id=?", (user_id,))
    log_activity("APPROVE_REGISTRATION", f"Approved resident registration '{user['username']}' (resident {user['resident_id']})")
    flash(f"Resident account '{user['username']}' approved! The resident can now log in.", "success")
    return redirect(url_for("admin_pending_registrations"))


@app.route("/admin/registrations/<int:user_id>/reject", methods=["POST"])
@login_required(roles=["admin"])
def admin_registration_reject(user_id):
    user = get_or_404("users", user_id)
    if user["role"] != "resident" or user["status"] != "pending":
        flash("Only pending resident accounts can be rejected.", "warning")
        return redirect(url_for("admin_pending_registrations"))
    # Keep resident record for audit? Delete only user; admin can delete resident separately if needed.
    # If resident was newly created via registration and has no docs/complaints, we could optionally delete it, but keep for now.
    # To avoid orphan, we delete resident only if it has no other linked user and was created within last 30 days and has no document_requests/complaints.
    resident_id = user["resident_id"]
    execute("DELETE FROM users WHERE id=?", (user_id,))
    # Optional: if resident has no other user linking and no requests, we could delete resident — but keep resident for admin review, just log.
    # Uncomment to auto-clean resident:
    # if resident_id:
    #     other = query_one("SELECT id FROM users WHERE resident_id=?", (resident_id,))
    #     if not other:
    #         has_docs = query_one("SELECT id FROM document_requests WHERE resident_id=? LIMIT 1", (resident_id,))
    #         has_cmps = query_one("SELECT id FROM complaints WHERE resident_id=? LIMIT 1", (resident_id,))
    #         if not has_docs and not has_cmps:
    #             res = query_one("SELECT photo FROM residents WHERE id=?", (resident_id,))
    #             if res and res["photo"]:
    #                 delete_image(res["photo"])
    #             execute("DELETE FROM residents WHERE id=?", (resident_id,))
    log_activity("REJECT_REGISTRATION", f"Rejected resident registration '{user['username']}'")
    flash(f"Registration '{user['username']}' rejected and removed.", "info")
    return redirect(url_for("admin_pending_registrations"))


# ===========================================================================
# ADMIN DASHBOARD
# ===========================================================================

def _age_group(birth_date):
    years = age(birth_date)
    if years is None:
        return "Unknown"
    if years <= 12:
        return "0-12 (Child)"
    if years <= 17:
        return "13-17 (Teen)"
    if years <= 30:
        return "18-30 (Young Adult)"
    if years <= 45:
        return "31-45 (Adult)"
    if years <= 59:
        return "46-59 (Middle Age)"
    return "60+ (Senior)"


@app.route("/admin")
@login_required(roles=["admin", "staff"])
def admin_dashboard():
    today = date.today().isoformat()
    total_residents = query_one("SELECT COUNT(*) c FROM residents")["c"]
    male = query_one("SELECT COUNT(*) c FROM residents WHERE sex='Male'")["c"]
    female = query_one("SELECT COUNT(*) c FROM residents WHERE sex='Female'")["c"]
    voters = query_one("SELECT COUNT(*) c FROM residents WHERE voter_status='Registered'")["c"]
    pending_docs = query_one("SELECT COUNT(*) c FROM document_requests WHERE status IN ('Pending','Processing')")["c"]
    pending_complaints = query_one("SELECT COUNT(*) c FROM complaints WHERE status IN ('Pending','Investigating')")["c"]
    upcoming_events = query_one(
        "SELECT COUNT(*) c FROM events WHERE event_date >= ? AND status != 'Cancelled'", (today,))["c"]
    active_officials = query_one("SELECT COUNT(*) c FROM officials WHERE status='Active'")["c"]

    gender_rows = query("SELECT sex, COUNT(*) c FROM residents GROUP BY sex")
    purok_rows = query(
        "SELECT COALESCE(NULLIF(purok,''),'Unspecified') purok, COUNT(*) c "
        "FROM residents GROUP BY purok ORDER BY purok")
    doc_rows = query("SELECT status, COUNT(*) c FROM document_requests GROUP BY status")
    complaint_rows = query("SELECT status, COUNT(*) c FROM complaints GROUP BY status")

    age_counts = {}
    for r in query("SELECT birth_date FROM residents"):
        grp = _age_group(r["birth_date"])
        age_counts[grp] = age_counts.get(grp, 0) + 1
    age_order = ["0-12 (Child)", "13-17 (Teen)", "18-30 (Young Adult)",
                 "31-45 (Adult)", "46-59 (Middle Age)", "60+ (Senior)", "Unknown"]

    activities = query(
        "SELECT l.*, u.full_name, u.username FROM activity_logs l "
        "LEFT JOIN users u ON u.id = l.user_id ORDER BY l.timestamp DESC LIMIT 8")
    events_list = query(
        "SELECT * FROM events WHERE event_date >= ? ORDER BY event_date ASC LIMIT 5", (today,))

    chart_data = {
        "gender": {"labels": [r["sex"] or "Unspecified" for r in gender_rows],
                   "values": [r["c"] for r in gender_rows]},
        "age": {"labels": [g for g in age_order if g in age_counts],
                "values": [age_counts[g] for g in age_order if g in age_counts]},
        "purok": {"labels": [r["purok"] for r in purok_rows],
                  "values": [r["c"] for r in purok_rows]},
        "docs": {"labels": [r["status"] for r in doc_rows],
                 "values": [r["c"] for r in doc_rows]},
        "complaints": {"labels": [r["status"] for r in complaint_rows],
                       "values": [r["c"] for r in complaint_rows]},
    }
    return render_template(
        "admin/dashboard.html",
        cards={"total_residents": total_residents, "male": male, "female": female,
               "voters": voters, "pending_docs": pending_docs,
               "pending_complaints": pending_complaints,
               "upcoming_events": upcoming_events, "active_officials": active_officials},
        chart_data=chart_data, activities=activities, events_list=events_list)


# ===========================================================================
# RESIDENT MANAGEMENT
# ===========================================================================

RESIDENT_SORTABLE = {"resident_id", "first_name", "last_name", "birth_date",
                     "purok", "sex", "created_at"}


@app.route("/admin/residents")
@login_required(roles=["admin", "staff"])
def admin_residents():
    search = request.args.get("search", "").strip()
    sex = request.args.get("sex", "").strip()
    purok = request.args.get("purok", "").strip()
    voter = request.args.get("voter_status", "").strip()
    residency = request.args.get("residency_status", "").strip()
    sort = request.args.get("sort", "created_at")
    direction = request.args.get("dir", "desc").lower()
    try:
        page = max(int(request.args.get("page", 1)), 1)
    except ValueError:
        page = 1

    if sort not in RESIDENT_SORTABLE:
        sort = "created_at"
    direction = "asc" if direction == "asc" else "desc"

    clauses, params = [], []
    if search:
        clauses.append("(r.first_name LIKE ? OR r.middle_name LIKE ? OR r.last_name LIKE ? "
                       "OR r.resident_id LIKE ? OR r.purok LIKE ? OR r.contact_number LIKE ?)")
        like = f"%{search}%"
        params += [like] * 6
    if sex:
        clauses.append("r.sex = ?"); params.append(sex)
    if purok:
        clauses.append("r.purok = ?"); params.append(purok)
    if voter:
        clauses.append("r.voter_status = ?"); params.append(voter)
    if residency:
        clauses.append("r.residency_status = ?"); params.append(residency)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    total = query_one(f"SELECT COUNT(*) c FROM residents r {where}", params)["c"]
    per_page = app.config["PER_PAGE"]
    total_pages = max((total + per_page - 1) // per_page, 1)
    page = min(page, total_pages)
    offset = (page - 1) * per_page

    residents = query(
        f"SELECT * FROM residents r {where} ORDER BY r.{sort} {direction} "
        f"LIMIT ? OFFSET ?", params + [per_page, offset])
    puroks = [row["purok"] for row in
              query("SELECT DISTINCT purok FROM residents WHERE purok IS NOT NULL AND purok != '' ORDER BY purok")]
    return render_template("admin/residents.html", residents=residents, total=total,
                           page=page, total_pages=total_pages, puroks=puroks,
                           search=search, sex=sex, purok=purok, voter=voter,
                           residency=residency, sort=sort, direction=direction)


def _validate_resident_form(form) -> list:
    errors = []
    if len(form.get("first_name", "").strip()) < 2:
        errors.append("First name is required (min. 2 characters).")
    if len(form.get("last_name", "").strip()) < 2:
        errors.append("Last name is required (min. 2 characters).")
    if form.get("sex") not in ("Male", "Female"):
        errors.append("Please select a sex.")
    birth = form.get("birth_date", "").strip()
    try:
        bday = datetime.strptime(birth, "%Y-%m-%d").date()
        if bday > date.today():
            errors.append("Birth date cannot be in the future.")
        elif bday.year < 1900:
            errors.append("Birth date seems invalid.")
    except ValueError:
        errors.append("A valid birth date is required.")
    if not form.get("address", "").strip():
        errors.append("Address is required.")
    if not form.get("purok", "").strip():
        errors.append("Purok is required.")
    email = form.get("email", "").strip()
    if email and not valid_email(email):
        errors.append("Email address is not valid.")
    contact = form.get("contact_number", "").strip()
    if contact and not re.fullmatch(r"[0-9()+\-\s]{7,20}", contact):
        errors.append("Contact number contains invalid characters.")
    return errors


@app.route("/admin/residents/add", methods=["GET", "POST"])
@login_required(roles=["admin", "staff"])
def admin_resident_add():
    form = {}
    if request.method == "POST":
        form = request.form.to_dict()
        errors = _validate_resident_form(form)
        photo = save_image(request.files.get("photo")) if request.files else None
        if not errors:
            rid = database.next_number("BRGY", "residents", "resident_id")
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            execute(
                """INSERT INTO residents
                   (resident_id, first_name, middle_name, last_name, suffix, sex, birth_date,
                    birth_place, civil_status, nationality, religion, occupation,
                    contact_number, email, address, purok, voter_status, residency_status,
                    photo, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rid, form["first_name"].strip(), form.get("middle_name", "").strip() or None,
                 form["last_name"].strip(), form.get("suffix", "").strip() or None,
                 form["sex"], form["birth_date"], form.get("birth_place", "").strip() or None,
                 form.get("civil_status", "").strip() or None,
                 form.get("nationality", "").strip() or "Filipino",
                 form.get("religion", "").strip() or None,
                 form.get("occupation", "").strip() or None,
                 form.get("contact_number", "").strip() or None,
                 form.get("email", "").strip() or None,
                 form["address"].strip(), form["purok"].strip(),
                 form.get("voter_status", "").strip() or None,
                 form.get("residency_status", "").strip() or None,
                 photo, now, now))
            log_activity("ADD_RESIDENT", f"Added resident {rid} - "
                         f"{form['first_name']} {form['last_name']}")
            flash(f"Resident successfully added! Resident ID: {rid}", "success")
            return redirect(url_for("admin_residents"))
        if photo:
            delete_image(photo)
        for err in errors:
            flash(err, "danger")
    return render_template("admin/resident_form.html", resident=form or None,
                           title="Add Resident")


@app.route("/admin/residents/edit/<int:resident_pk>", methods=["GET", "POST"])
@login_required(roles=["admin", "staff"])
def admin_resident_edit(resident_pk):
    row = get_or_404("residents", resident_pk)
    if request.method == "POST":
        form = request.form.to_dict()
        errors = _validate_resident_form(form)
        if not errors:
            photo = save_image(request.files.get("photo"))
            old_photo = row["photo"]
            if not photo:
                photo = old_photo
            execute(
                """UPDATE residents SET
                   first_name=?, middle_name=?, last_name=?, suffix=?, sex=?, birth_date=?,
                   birth_place=?, civil_status=?, nationality=?, religion=?, occupation=?,
                   contact_number=?, email=?, address=?, purok=?, voter_status=?,
                   residency_status=?, photo=?, updated_at=? WHERE id=?""",
                (form["first_name"].strip(), form.get("middle_name", "").strip() or None,
                 form["last_name"].strip(), form.get("suffix", "").strip() or None,
                 form["sex"], form["birth_date"],
                 form.get("birth_place", "").strip() or None,
                 form.get("civil_status", "").strip() or None,
                 form.get("nationality", "").strip() or "Filipino",
                 form.get("religion", "").strip() or None,
                 form.get("occupation", "").strip() or None,
                 form.get("contact_number", "").strip() or None,
                 form.get("email", "").strip() or None,
                 form["address"].strip(), form["purok"].strip(),
                 form.get("voter_status", "").strip() or None,
                 form.get("residency_status", "").strip() or None,
                 photo, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), resident_pk))
            if photo != old_photo:
                delete_image(old_photo)
            log_activity("UPDATE_RESIDENT",
                         f"Updated resident {row['resident_id']} - {form['first_name']} {form['last_name']}")
            flash("Resident successfully updated!", "success")
            return redirect(url_for("admin_resident_view", resident_pk=resident_pk))
        for err in errors:
            flash(err, "danger")
        merged = dict(row); merged.update(form)
        return render_template("admin/resident_form.html", resident=merged,
                               title="Edit Resident")
    return render_template("admin/resident_form.html", resident=dict(row),
                           title="Edit Resident")


@app.route("/admin/residents/view/<int:resident_pk>")
@login_required(roles=["admin", "staff"])
def admin_resident_view(resident_pk):
    row = get_or_404("residents", resident_pk)
    requests_history = query(
        "SELECT * FROM document_requests WHERE resident_id = ? ORDER BY request_date DESC",
        (resident_pk,))
    return render_template("admin/resident_view.html", resident=row,
                           requests=requests_history)


@app.route("/admin/residents/delete/<int:resident_pk>", methods=["POST"])
@login_required(roles=["admin"])
def admin_resident_delete(resident_pk):
    row = get_or_404("residents", resident_pk)
    execute("DELETE FROM residents WHERE id = ?", (resident_pk,))
    delete_image(row["photo"])
    log_activity("DELETE_RESIDENT", f"Deleted resident {row['resident_id']} - "
                 f"{row['first_name']} {row['last_name']}")
    flash("Resident successfully deleted!", "success")
    return redirect(url_for("admin_residents"))


# ===========================================================================
# BARANGAY OFFICIALS (ADMIN)
# ===========================================================================

OFFICIAL_ORDER = """ORDER BY CASE position
    WHEN 'Punong Barangay' THEN 1 WHEN 'Barangay Kagawad' THEN 2
    WHEN 'SK Chairperson' THEN 3 WHEN 'Barangay Secretary' THEN 4
    WHEN 'Barangay Treasurer' THEN 5 ELSE 9 END, full_name"""


@app.route("/admin/officials")
@login_required(roles=["admin"])
def admin_officials():
    officials = query(f"SELECT * FROM officials {OFFICIAL_ORDER}")
    return render_template("admin/officials.html", officials=officials)


@app.route("/admin/officials/add", methods=["GET", "POST"])
@login_required(roles=["admin"])
def admin_official_add():
    if request.method == "POST":
        errors, data = _validate_official_form()
        if not errors:
            photo = save_image(request.files.get("photo"))
            execute(
                "INSERT INTO officials (full_name, position, contact_number, email, photo,"
                " term_start, term_end, status) VALUES (?,?,?,?,?,?,?,?)",
                (data["full_name"], data["position"], data["contact_number"],
                 data["email"], photo, data["term_start"], data["term_end"],
                 data["status"]))
            log_activity("ADD_OFFICIAL", f"Added official {data['full_name']} ({data['position']})")
            flash("Official successfully added!", "success")
            return redirect(url_for("admin_officials"))
        for err in errors:
            flash(err, "danger")
    return render_template("admin/official_form.html", official=None,
                           positions=_positions(), title="Add Official")


@app.route("/admin/officials/edit/<int:official_id>", methods=["GET", "POST"])
@login_required(roles=["admin"])
def admin_official_edit(official_id):
    row = get_or_404("officials", official_id)
    if request.method == "POST":
        errors, data = _validate_official_form()
        if not errors:
            photo = save_image(request.files.get("photo")) or row["photo"]
            execute(
                "UPDATE officials SET full_name=?, position=?, contact_number=?, email=?,"
                " photo=?, term_start=?, term_end=?, status=? WHERE id=?",
                (data["full_name"], data["position"], data["contact_number"],
                 data["email"], photo, data["term_start"], data["term_end"],
                 data["status"], official_id))
            log_activity("UPDATE_OFFICIAL", f"Updated official {data['full_name']}")
            flash("Official successfully updated!", "success")
            return redirect(url_for("admin_officials"))
        for err in errors:
            flash(err, "danger")
    return render_template("admin/official_form.html", official=dict(row),
                           positions=_positions(), title="Edit Official")


@app.route("/admin/officials/delete/<int:official_id>", methods=["POST"])
@login_required(roles=["admin"])
def admin_official_delete(official_id):
    row = get_or_404("officials", official_id)
    execute("DELETE FROM officials WHERE id=?", (official_id,))
    delete_image(row["photo"])
    log_activity("DELETE_OFFICIAL", f"Deleted official {row['full_name']}")
    flash("Official successfully deleted!", "success")
    return redirect(url_for("admin_officials"))


def _positions():
    return ["Punong Barangay", "Barangay Kagawad", "SK Chairperson",
            "Barangay Secretary", "Barangay Treasurer",
            "BARANGAY Tanod", "Barangay Health Worker", "Lupon Member", "Other"]


def _validate_official_form():
    data = {
        "full_name": request.form.get("full_name", "").strip(),
        "position": request.form.get("position", "").strip(),
        "contact_number": request.form.get("contact_number", "").strip(),
        "email": request.form.get("email", "").strip(),
        "term_start": request.form.get("term_start", "").strip(),
        "term_end": request.form.get("term_end", "").strip(),
        "status": request.form.get("status", "Active").strip(),
    }
    errors = []
    if len(data["full_name"]) < 2:
        errors.append("Official's full name is required.")
    if not data["position"]:
        errors.append("Position is required.")
    if data["email"] and not valid_email(data["email"]):
        errors.append("Official email address is not valid.")
    if data["contact_number"] and not re.fullmatch(r"[0-9()+\-\s]{7,20}", data["contact_number"]):
        errors.append("Contact number contains invalid characters.")
    if data["term_start"] and data["term_end"] and data["term_end"] < data["term_start"]:
        errors.append("Term end must be after term start.")
    return errors, data


# ===========================================================================
# ANNOUNCEMENTS (ADMIN)
# ===========================================================================

@app.route("/admin/announcements")
@login_required(roles=["admin", "staff"])
def admin_announcements():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    sql, params = "SELECT a.*, u.full_name AS author FROM announcements a LEFT JOIN users u ON u.id=a.author_id WHERE 1=1", []
    if q:
        sql += " AND (a.title LIKE ? OR a.content LIKE ?)"; params += [f"%{q}%", f"%{q}%"]
    if status:
        sql += " AND a.status = ?"; params.append(status)
    sql += " ORDER BY a.published_date DESC"
    return render_template("admin/announcements.html",
                           announcements=query(sql, params), q=q, status=status)


@app.route("/admin/announcements/add", methods=["GET", "POST"])
@login_required(roles=["admin", "staff"])
def admin_announcement_add():
    if request.method == "POST":
        errors, data = _validate_announcement_form()
        if not errors:
            image = save_image(request.files.get("image"))
            execute(
                "INSERT INTO announcements (title, content, image, author_id,"
                " published_date, status) VALUES (?,?,?,?,?,?)",
                (data["title"], data["content"], image, current_user()["id"],
                 date.today().isoformat(), data["status"]))
            log_activity("ADD_ANNOUNCEMENT", f"Published announcement: {data['title']}")
            flash("Announcement successfully added!", "success")
            return redirect(url_for("admin_announcements"))
        for err in errors:
            flash(err, "danger")
    return render_template("admin/announcement_form.html", item=None, title="Add Announcement")


@app.route("/admin/announcements/edit/<int:announcement_id>", methods=["GET", "POST"])
@login_required(roles=["admin", "staff"])
def admin_announcement_edit(announcement_id):
    row = get_or_404("announcements", announcement_id)
    if request.method == "POST":
        errors, data = _validate_announcement_form()
        if not errors:
            new_image = save_image(request.files.get("image"))
            image = new_image or row["image"]
            if request.form.get("remove_image"):
                delete_image(row["image"])
                image = None
            elif new_image and row["image"] and new_image != row["image"]:
                delete_image(row["image"])
            execute(
                "UPDATE announcements SET title=?, content=?, image=?, status=? WHERE id=?",
                (data["title"], data["content"], image, data["status"], announcement_id))
            log_activity("UPDATE_ANNOUNCEMENT", f"Updated announcement: {data['title']}")
            flash("Announcement successfully updated!", "success")
            return redirect(url_for("admin_announcements"))
        for err in errors:
            flash(err, "danger")
    return render_template("admin/announcement_form.html", item=dict(row),
                           title="Edit Announcement")


@app.route("/admin/announcements/delete/<int:announcement_id>", methods=["POST"])
@login_required(roles=["admin", "staff"])
def admin_announcement_delete(announcement_id):
    row = get_or_404("announcements", announcement_id)
    execute("DELETE FROM announcements WHERE id=?", (announcement_id,))
    delete_image(row["image"])
    log_activity("DELETE_ANNOUNCEMENT", f"Deleted announcement: {row['title']}")
    flash("Announcement successfully deleted!", "success")
    return redirect(url_for("admin_announcements"))


def _validate_announcement_form():
    data = {
        "title": request.form.get("title", "").strip(),
        "content": request.form.get("content", "").strip(),
        "status": request.form.get("status", "Published").strip(),
    }
    errors = []
    if len(data["title"]) < 5:
        errors.append("Title must be at least 5 characters.")
    if len(data["content"]) < 10:
        errors.append("Content must be at least 10 characters.")
    if data["status"] not in ("Published", "Unpublished"):
        errors.append("Invalid status.")
    return errors, data


# ===========================================================================
# EVENTS (ADMIN)
# ===========================================================================

@app.route("/admin/events")
@login_required(roles=["admin"])
def admin_events():
    events = query("SELECT * FROM events ORDER BY event_date DESC, start_time ASC")
    return render_template("admin/events.html", events=events)


@app.route("/admin/events/add", methods=["GET", "POST"])
@login_required(roles=["admin"])
def admin_event_add():
    if request.method == "POST":
        errors, data = _validate_event_form()
        if not errors:
            image = save_image(request.files.get("image"))
            execute(
                "INSERT INTO events (title, description, event_date, start_time, end_time,"
                " location, organizer, status, image) VALUES (?,?,?,?,?,?,?,?,?)",
                (data["title"], data["description"], data["event_date"],
                 data["start_time"], data["end_time"], data["location"],
                 data["organizer"], data["status"], image))
            log_activity("ADD_EVENT", f"Added event: {data['title']}")
            flash("Event successfully added!", "success")
            return redirect(url_for("admin_events"))
        for err in errors:
            flash(err, "danger")
    return render_template("admin/event_form.html", item=None, title="Add Event")


@app.route("/admin/events/edit/<int:event_id>", methods=["GET", "POST"])
@login_required(roles=["admin"])
def admin_event_edit(event_id):
    row = get_or_404("events", event_id)
    if request.method == "POST":
        errors, data = _validate_event_form()
        if not errors:
            image = save_image(request.files.get("image")) or row["image"]
            if request.form.get("remove_image"):
                delete_image(row["image"])
                image = None
            # if new image uploaded and old exists, delete old
            if image != row["image"] and image is not None and row["image"]:
                delete_image(row["image"])
            execute(
                "UPDATE events SET title=?, description=?, event_date=?, start_time=?,"
                " end_time=?, location=?, organizer=?, status=?, image=? WHERE id=?",
                (data["title"], data["description"], data["event_date"],
                 data["start_time"], data["end_time"], data["location"],
                 data["organizer"], data["status"], image, event_id))
            log_activity("UPDATE_EVENT", f"Updated event: {data['title']}")
            flash("Event successfully updated!", "success")
            return redirect(url_for("admin_events"))
        for err in errors:
            flash(err, "danger")
    return render_template("admin/event_form.html", item=dict(row), title="Edit Event")


@app.route("/admin/events/delete/<int:event_id>", methods=["POST"])
@login_required(roles=["admin"])
def admin_event_delete(event_id):
    row = get_or_404("events", event_id)
    execute("DELETE FROM events WHERE id=?", (event_id,))
    delete_image(row["image"] if "image" in row.keys() else None)
    log_activity("DELETE_EVENT", f"Deleted event: {row['title']}")
    flash("Event successfully deleted!", "success")
    return redirect(url_for("admin_events"))


def _validate_event_form():
    data = {
        "title": request.form.get("title", "").strip(),
        "description": request.form.get("description", "").strip(),
        "event_date": request.form.get("event_date", "").strip(),
        "start_time": request.form.get("start_time", "").strip(),
        "end_time": request.form.get("end_time", "").strip(),
        "location": request.form.get("location", "").strip(),
        "organizer": request.form.get("organizer", "").strip(),
        "status": request.form.get("status", "Scheduled").strip(),
    }
    errors = []
    if len(data["title"]) < 3:
        errors.append("Event title is required (min. 3 characters).")
    try:
        datetime.strptime(data["event_date"], "%Y-%m-%d")
    except ValueError:
        errors.append("A valid event date is required.")
    if data["start_time"] and data["end_time"] and data["end_time"] < data["start_time"]:
        errors.append("End time must be after start time.")
    if data["status"] not in ("Scheduled", "Ongoing", "Completed", "Cancelled"):
        errors.append("Invalid event status.")
    return errors, data


# ===========================================================================
# DOCUMENT REQUESTS (ADMIN)
# ===========================================================================

@app.route("/admin/documents")
@login_required(roles=["admin", "staff"])
def admin_documents():
    status = request.args.get("status", "").strip()
    q = request.args.get("q", "").strip()
    sql = ("SELECT d.*, u.username AS processor FROM document_requests d "
           "LEFT JOIN users u ON u.id = d.processed_by WHERE 1=1")
    params = []
    if status:
        sql += " AND d.status = ?"; params.append(status)
    if q:
        sql += " AND (d.request_number LIKE ? OR d.requester_name LIKE ? OR d.document_type LIKE ?)"
        params += [f"%{q}%"] * 3
    sql += " ORDER BY CASE d.status WHEN 'Pending' THEN 0 WHEN 'Processing' THEN 1 ELSE 2 END," \
           " d.request_date DESC, d.id DESC"
    counts = {r["status"]: r["c"] for r in
              query("SELECT status, COUNT(*) c FROM document_requests GROUP BY status")}
    return render_template("admin/document_requests.html",
                           requests=query(sql, params), status=status, q=q, counts=counts)


@app.route("/admin/documents/<int:request_id>/update", methods=["POST"])
@login_required(roles=["admin", "staff"])
def admin_document_update(request_id):
    row = get_or_404("document_requests", request_id)
    new_status = request.form.get("status", "").strip()
    remarks = request.form.get("remarks", "").strip() or None
    if new_status not in database.REQUEST_STATUSES:
        flash("Invalid status value.", "danger")
        return redirect(url_for("admin_documents"))
    release_date = date.today().isoformat() if new_status == "Released" else row["release_date"]
    execute(
        "UPDATE document_requests SET status=?, remarks=?, processed_by=?, release_date=? WHERE id=?",
        (new_status, remarks, current_user()["id"], release_date, request_id))
    log_activity("PROCESS_REQUEST",
                 f"Document request {row['request_number']} set to {new_status}.")
    flash(f"Request {row['request_number']} updated to {new_status}.", "success")
    return redirect(request.referrer or url_for("admin_documents"))


@app.route("/admin/documents/<int:request_id>/delete", methods=["POST"])
@login_required(roles=["admin"])
def admin_document_delete(request_id):
    row = get_or_404("document_requests", request_id)
    execute("DELETE FROM document_requests WHERE id=?", (request_id,))
    log_activity("DELETE_REQUEST", f"Deleted document request {row['request_number']}")
    flash("Document request deleted.", "success")
    return redirect(url_for("admin_documents"))


# ===========================================================================
# COMPLAINTS & INQUIRIES (ADMIN)
# ===========================================================================

@app.route("/admin/complaints")
@login_required(roles=["admin", "staff"])
def admin_complaints():
    status = request.args.get("status", "").strip()
    q = request.args.get("q", "").strip()
    sql, params = "SELECT * FROM complaints WHERE 1=1", []
    if status:
        sql += " AND status = ?"; params.append(status)
    if q:
        sql += " AND (complaint_number LIKE ? OR complainant_name LIKE ? OR subject LIKE ?)"
        params += [f"%{q}%"] * 3
    sql += (" ORDER BY CASE status WHEN 'Pending' THEN 0 WHEN 'Investigating' THEN 1 ELSE 2 END,"
            " date_reported DESC")
    counts = {r["status"]: r["c"] for r in
              query("SELECT status, COUNT(*) c FROM complaints GROUP BY status")}
    inquiries = query("SELECT * FROM inquiries ORDER BY created_at DESC LIMIT 50")
    return render_template("admin/complaints.html", complaints=query(sql, params),
                           status=status, q=q, counts=counts, inquiries=inquiries)


@app.route("/admin/complaints/<int:complaint_id>/update", methods=["POST"])
@login_required(roles=["admin", "staff"])
def admin_complaint_update(complaint_id):
    row = get_or_404("complaints", complaint_id)
    new_status = request.form.get("status", "").strip()
    assigned_to = request.form.get("assigned_to", "").strip() or None
    remarks = request.form.get("remarks", "").strip() or None
    if new_status not in database.COMPLAINT_STATUSES:
        flash("Invalid complaint status.", "danger")
        return redirect(url_for("admin_complaints"))
    execute(
        "UPDATE complaints SET status=?, assigned_to=?, remarks=? WHERE id=?",
        (new_status, assigned_to, remarks, complaint_id))
    log_activity("UPDATE_COMPLAINT",
                 f"Complaint {row['complaint_number']} set to {new_status}.")
    flash(f"Complaint {row['complaint_number']} updated.", "success")
    return redirect(url_for("admin_complaints"))


@app.route("/admin/complaints/<int:complaint_id>/delete", methods=["POST"])
@login_required(roles=["admin"])
def admin_complaint_delete(complaint_id):
    row = get_or_404("complaints", complaint_id)
    execute("DELETE FROM complaints WHERE id=?", (complaint_id,))
    log_activity("DELETE_COMPLAINT", f"Deleted complaint {row['complaint_number']}")
    flash("Complaint deleted.", "success")
    return redirect(url_for("admin_complaints"))


@app.route("/admin/inquiries/<int:inquiry_id>/toggle", methods=["POST"])
@login_required(roles=["admin", "staff"])
def admin_inquiry_toggle(inquiry_id):
    row = get_or_404("inquiries", inquiry_id)
    new_status = "Read" if row["status"] == "New" else "New"
    execute("UPDATE inquiries SET status=? WHERE id=?", (new_status, inquiry_id))
    flash(f"Inquiry marked as {new_status.lower()}.", "info")
    return redirect(url_for("admin_complaints"))


@app.route("/admin/inquiries/<int:inquiry_id>/delete", methods=["POST"])
@login_required(roles=["admin", "staff"])
def admin_inquiry_delete(inquiry_id):
    get_or_404("inquiries", inquiry_id)
    execute("DELETE FROM inquiries WHERE id=?", (inquiry_id,))
    log_activity("DELETE_INQUIRY", f"Deleted inquiry #{inquiry_id}")
    flash("Inquiry deleted.", "success")
    return redirect(url_for("admin_complaints"))


# ===========================================================================
# BLOTTER RECORDS (ADMIN)
# ===========================================================================

@app.route("/admin/blotter")
@login_required(roles=["admin"])
def admin_blotter():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    sql, params = "SELECT b.*, u.full_name AS recorder FROM blotter b " \
                  "LEFT JOIN users u ON u.id=b.recorded_by WHERE 1=1", []
    if q:
        sql += (" AND (b.blotter_number LIKE ? OR b.complainant LIKE ? OR b.respondent LIKE ?"
                " OR b.incident_type LIKE ?)")
        params += [f"%{q}%"] * 4
    if status:
        sql += " AND b.status = ?"; params.append(status)
    sql += " ORDER BY b.incident_date DESC"
    return render_template("admin/blotter.html", records=query(sql, params), q=q, status=status)


@app.route("/admin/blotter/add", methods=["GET", "POST"])
@login_required(roles=["admin"])
def admin_blotter_add():
    if request.method == "POST":
        errors, data = _validate_blotter_form()
        if not errors:
            number = database.next_number("BLT", "blotter", "blotter_number")
            execute(
                "INSERT INTO blotter (blotter_number, complainant, respondent, incident_type,"
                " incident_date, incident_location, description, action_taken, status,"
                " recorded_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (number, data["complainant"], data["respondent"], data["incident_type"],
                 data["incident_date"], data["incident_location"], data["description"],
                 data["action_taken"], data["status"], current_user()["id"],
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            log_activity("ADD_BLOTTER", f"Recorded blotter {number} ({data['incident_type']})")
            flash(f"Blotter record successfully added! Blotter No.: {number}", "success")
            return redirect(url_for("admin_blotter"))
        for err in errors:
            flash(err, "danger")
    return render_template("admin/blotter_form.html", item=None, title="Record New Blotter Entry")


@app.route("/admin/blotter/edit/<int:entry_id>", methods=["GET", "POST"])
@login_required(roles=["admin"])
def admin_blotter_edit(entry_id):
    row = get_or_404("blotter", entry_id)
    if request.method == "POST":
        errors, data = _validate_blotter_form()
        if not errors:
            execute(
                "UPDATE blotter SET complainant=?, respondent=?, incident_type=?,"
                " incident_date=?, incident_location=?, description=?, action_taken=?,"
                " status=? WHERE id=?",
                (data["complainant"], data["respondent"], data["incident_type"],
                 data["incident_date"], data["incident_location"], data["description"],
                 data["action_taken"], data["status"], entry_id))
            log_activity("UPDATE_BLOTTER", f"Updated blotter {row['blotter_number']}")
            flash("Blotter record successfully updated!", "success")
            return redirect(url_for("admin_blotter"))
        for err in errors:
            flash(err, "danger")
    return render_template("admin/blotter_form.html", item=dict(row), title="Edit Blotter Entry")


@app.route("/admin/blotter/delete/<int:entry_id>", methods=["POST"])
@login_required(roles=["admin"])
def admin_blotter_delete(entry_id):
    row = get_or_404("blotter", entry_id)
    execute("DELETE FROM blotter WHERE id=?", (entry_id,))
    log_activity("DELETE_BLOTTER", f"Deleted blotter {row['blotter_number']}")
    flash("Blotter record deleted.", "success")
    return redirect(url_for("admin_blotter"))


def _validate_blotter_form():
    data = {
        "complainant": request.form.get("complainant", "").strip(),
        "respondent": request.form.get("respondent", "").strip(),
        "incident_type": request.form.get("incident_type", "").strip(),
        "incident_date": request.form.get("incident_date", "").strip(),
        "incident_location": request.form.get("incident_location", "").strip(),
        "description": request.form.get("description", "").strip(),
        "action_taken": request.form.get("action_taken", "").strip(),
        "status": request.form.get("status", "Open").strip(),
    }
    errors = []
    if len(data["complainant"]) < 2:
        errors.append("Complainant name is required.")
    if len(data["incident_type"]) < 3:
        errors.append("Incident type is required.")
    try:
        d = datetime.strptime(data["incident_date"], "%Y-%m-%d").date()
        if d > date.today():
            errors.append("Incident date cannot be in the future.")
    except ValueError:
        errors.append("A valid incident date is required.")
    if data["status"] not in ("Open", "Under Investigation", "Settled", "Closed"):
        errors.append("Invalid blotter status.")
    return errors, data


# ===========================================================================
# USER MANAGEMENT (ADMIN ONLY)
# ===========================================================================

@app.route("/admin/users")
@login_required(roles=["admin"])
def admin_users():
    users = query("SELECT * FROM users ORDER BY created_at ASC")
    return render_template("admin/users.html", users=users)


@app.route("/admin/users/add", methods=["GET", "POST"])
@login_required(roles=["admin"])
def admin_user_add():
    if request.method == "POST":
        errors, data = _validate_user_form(require_password=True)
        if not errors:
            execute(
                "INSERT INTO users (username, password_hash, full_name, role, email,"
                " status, created_at) VALUES (?,?,?,?,?,?,?)",
                (data["username"], generate_password_hash(data["password"]),
                 data["full_name"], data["role"], data["email"], data["status"],
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            log_activity("ADD_USER", f"Created {data['role']} account '{data['username']}'")
            flash(f"User '{data['username']}' successfully created!", "success")
            return redirect(url_for("admin_users"))
        for err in errors:
            flash(err, "danger")
    return render_template("admin/user_form.html", user=None, title="Add User")


@app.route("/admin/users/edit/<int:user_id>", methods=["GET", "POST"])
@login_required(roles=["admin"])
def admin_user_edit(user_id):
    row = get_or_404("users", user_id)
    if request.method == "POST":
        errors, data = _validate_user_form(require_password=False, original=row)
        if not errors:
            execute(
                "UPDATE users SET username=?, full_name=?, role=?, email=?, status=? WHERE id=?",
                (data["username"], data["full_name"], data["role"], data["email"],
                 data["status"], user_id))
            if data["password"]:
                execute("UPDATE users SET password_hash=? WHERE id=?",
                        (generate_password_hash(data["password"]), user_id))
            log_activity("UPDATE_USER", f"Updated user account '{data['username']}'")
            flash("User successfully updated!", "success")
            return redirect(url_for("admin_users"))
        for err in errors:
            flash(err, "danger")
    return render_template("admin/user_form.html", user=dict(row), title="Edit User")


@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
@login_required(roles=["admin"])
def admin_user_delete(user_id):
    row = get_or_404("users", user_id)
    me = current_user()
    if row["id"] == me["id"]:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin_users"))
    if row["role"] == "admin":
        active_admins = query_one(
            "SELECT COUNT(*) c FROM users WHERE role='admin' AND status='active' AND id != ?",
            (user_id,))["c"]
        if active_admins == 0:
            flash("Cannot delete the last active administrator account.", "danger")
            return redirect(url_for("admin_users"))
    execute("DELETE FROM users WHERE id=?", (user_id,))
    log_activity("DELETE_USER", f"Deleted user account '{row['username']}'")
    flash("User successfully deleted!", "success")
    return redirect(url_for("admin_users"))


def _validate_user_form(require_password=True, original=None):
    data = {
        "username": request.form.get("username", "").strip().lower(),
        "password": request.form.get("password", ""),
        "confirm_password": request.form.get("confirm_password", ""),
        "full_name": request.form.get("full_name", "").strip(),
        "role": request.form.get("role", "staff").strip(),
        "email": request.form.get("email", "").strip(),
        "status": request.form.get("status", "active").strip(),
    }
    errors = []
    if not re.fullmatch(r"[a-z0-9_.]{3,30}", data["username"]):
        errors.append("Username must be 3-30 characters (letters, numbers, dot, underscore).")
    existing = query_one("SELECT id FROM users WHERE username = ?", (data["username"],))
    if existing and (original is None or existing["id"] != original["id"]):
        errors.append("That username is already taken.")
    if len(data["full_name"]) < 2:
        errors.append("Full name is required.")
    if data["role"] not in ("admin", "staff", "resident"):
        errors.append("Invalid role.")
    if data["status"] not in ("active", "inactive", "pending"):
        errors.append("Invalid status.")
    if data["email"] and not valid_email(data["email"]):
        errors.append("Email address is not valid.")
    if require_password or data["password"]:
        if len(data["password"]) < 6:
            errors.append("Password must be at least 6 characters.")
        if data["password"] != data["confirm_password"]:
            errors.append("Passwords do not match.")
    # Guard against locking yourself out of the system
    me = current_user()
    if original and original["id"] == me["id"] and \
       (data["role"] != original["role"] or data["status"] != original["status"]):
        errors.append("You cannot change your own role or status.")
    return errors, data


# ===========================================================================
# REPORTS & EXPORTS
# ===========================================================================

@app.route("/admin/reports")
@login_required(roles=["admin", "staff"])
def admin_reports():
    stats = {
        "total": query_one("SELECT COUNT(*) c FROM residents")["c"],
        "male": query_one("SELECT COUNT(*) c FROM residents WHERE sex='Male'")["c"],
        "female": query_one("SELECT COUNT(*) c FROM residents WHERE sex='Female'")["c"],
        "voters": query_one("SELECT COUNT(*) c FROM residents WHERE voter_status='Registered'")["c"],
    }
    purok_rows = query(
        "SELECT COALESCE(NULLIF(purok,''),'Unspecified') label, COUNT(*) c, "
        "SUM(CASE WHEN sex='Male' THEN 1 ELSE 0 END) m, "
        "SUM(CASE WHEN sex='Female' THEN 1 ELSE 0 END) f "
        "FROM residents GROUP BY purok ORDER BY label")
    age_counts = {}
    for r in query("SELECT birth_date FROM residents"):
        grp = _age_group(r["birth_date"])
        age_counts[grp] = age_counts.get(grp, 0) + 1
    age_order = ["0-12 (Child)", "13-17 (Teen)", "18-30 (Young Adult)",
                 "31-45 (Adult)", "46-59 (Middle Age)", "60+ (Senior)", "Unknown"]
    ages = [(g, age_counts[g]) for g in age_order if g in age_counts]
    residency_rows = query(
        "SELECT COALESCE(NULLIF(residency_status,''),'Unspecified') label, COUNT(*) c "
        "FROM residents GROUP BY residency_status ORDER BY label")

    doc_total = query_one("SELECT COUNT(*) c FROM document_requests")["c"]
    doc_by_status = {r["status"]: r["c"] for r in
                     query("SELECT status, COUNT(*) c FROM document_requests GROUP BY status")}
    doc_by_type = query(
        "SELECT document_type, COUNT(*) c FROM document_requests GROUP BY document_type "
        "ORDER BY c DESC")

    cmp_total = query_one("SELECT COUNT(*) c FROM complaints")["c"]
    cmp_by_status = {r["status"]: r["c"] for r in
                     query("SELECT status, COUNT(*) c FROM complaints GROUP BY status")}
    blt_total = query_one("SELECT COUNT(*) c FROM blotter")["c"]

    generated = datetime.now().strftime("%B %d, %Y %I:%M %p")
    return render_template("admin/reports.html", stats=stats, purok_rows=purok_rows,
                           ages=ages, residency_rows=residency_rows, doc_total=doc_total,
                           doc_by_status=doc_by_status, doc_by_type=doc_by_type,
                           cmp_total=cmp_total, cmp_by_status=cmp_by_status,
                           blt_total=blt_total, generated=generated)


EXPORTS = {
    "residents": (
        "SELECT * FROM residents ORDER BY resident_id",
        ["resident_id", "first_name", "middle_name", "last_name", "suffix", "sex",
         "birth_date", "birth_place", "civil_status", "nationality", "religion",
         "occupation", "contact_number", "email", "address", "purok",
         "voter_status", "residency_status"]),
    "documents": (
        "SELECT * FROM document_requests ORDER BY request_number",
        ["request_number", "requester_name", "contact_number", "email", "address",
         "document_type", "purpose", "request_date", "status", "remarks", "release_date"]),
    "complaints": (
        "SELECT * FROM complaints ORDER BY complaint_number",
        ["complaint_number", "complainant_name", "contact_number", "email", "subject",
         "description", "location", "date_reported", "status", "assigned_to", "remarks"]),
    "blotter": (
        "SELECT * FROM blotter ORDER BY blotter_number",
        ["blotter_number", "complainant", "respondent", "incident_type", "incident_date",
         "incident_location", "description", "action_taken", "status"]),
    "officials": (
        "SELECT * FROM officials ORDER BY position, full_name",
        ["full_name", "position", "contact_number", "email", "term_start",
         "term_end", "status"]),
}


@app.route("/admin/export/<which>.csv")
@login_required(roles=["admin", "staff"])
def admin_export(which):
    if which not in EXPORTS:
        abort(404)
    sql, columns = EXPORTS[which]
    rows = query(sql)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([c.replace("_", " ").title() for c in columns])
    for row in rows:
        writer.writerow(["" if row[c] is None else str(row[c]) for c in columns])
    log_activity("EXPORT_REPORT", f"Exported {which}.csv")
    output = Response(buffer.getvalue(), mimetype="text/csv")
    output.headers["Content-Disposition"] = f"attachment; filename={which}_report_{date.today()}.csv"
    return output


# ===========================================================================
# ACTIVITY LOGS (ADMIN ONLY)
# ===========================================================================

@app.route("/admin/activity-logs")
@login_required(roles=["admin"])
def admin_activity_logs():
    q = request.args.get("q", "").strip()
    try:
        page = max(int(request.args.get("page", 1)), 1)
    except ValueError:
        page = 1
    where, params = "", []
    if q:
        where = ("WHERE l.action LIKE ? OR l.description LIKE ? OR u.username LIKE ?"
                 " OR u.full_name LIKE ?")
        params = [f"%{q}%"] * 4
    total = query_one(
        f"SELECT COUNT(*) c FROM activity_logs l LEFT JOIN users u ON u.id=l.user_id {where}",
        params)["c"]
    per_page = 15
    total_pages = max((total + per_page - 1) // per_page, 1)
    page = min(page, total_pages)
    logs = query(
        f"""SELECT l.*, u.full_name, u.username FROM activity_logs l
            LEFT JOIN users u ON u.id=l.user_id {where}
            ORDER BY l.timestamp DESC LIMIT ? OFFSET ?""",
        params + [per_page, (page - 1) * per_page])
    return render_template("admin/activity_logs.html", logs=logs, q=q,
                           page=page, total_pages=total_pages, total=total)


# ===========================================================================
# SYSTEM SETTINGS (ADMIN ONLY)
# ===========================================================================

@app.route("/admin/settings", methods=["GET", "POST"])
@login_required(roles=["admin"])
def admin_settings():
    row = query_one("SELECT * FROM system_settings WHERE id = 1")
    if request.method == "POST":
        logo = save_image(request.files.get("logo")) or (row["logo"] if row else None)
        values = {
            "barangay_name": request.form.get("barangay_name", "").strip(),
            "municipality": request.form.get("municipality", "").strip(),
            "province": request.form.get("province", "").strip(),
            "address": request.form.get("address", "").strip(),
            "contact_number": request.form.get("contact_number", "").strip(),
            "email": request.form.get("email", "").strip(),
            "captain_name": request.form.get("captain_name", "").strip(),
            "history": request.form.get("history", "").strip(),
            "mission": request.form.get("mission", "").strip(),
            "vision": request.form.get("vision", "").strip(),
            "goals": request.form.get("goals", "").strip(),
            "hotlines": request.form.get("hotlines", "").strip(),
        }
        if len(values["barangay_name"]) < 2:
            flash("Barangay name is required.", "danger")
        else:
            if row is None:
                execute(
                    """INSERT INTO system_settings
                       (barangay_name, municipality, province, address, contact_number,
                        email, logo, captain_name, history, mission, vision, goals, hotlines)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    tuple(values.values()) + (logo,))
            else:
                execute(
                    """UPDATE system_settings SET barangay_name=?, municipality=?, province=?,
                       address=?, contact_number=?, email=?, captain_name=?, history=?,
                       mission=?, vision=?, goals=?, hotlines=?, logo=? WHERE id=1""",
                    (values["barangay_name"], values["municipality"], values["province"],
                     values["address"], values["contact_number"], values["email"],
                     values["captain_name"], values["history"], values["mission"],
                     values["vision"], values["goals"], values["hotlines"], logo))
            log_activity("UPDATE_SETTINGS", "System settings updated.")
            flash("Settings saved successfully!", "success")
            return redirect(url_for("admin_settings"))
    return render_template("admin/settings.html", s=dict(row) if row else {})


# ===========================================================================
# PUBLIC RESIDENT SERVICES
# ===========================================================================

@app.route("/request-document", methods=["GET", "POST"])
def request_document():
    if request.method == "POST":
        data = {
            "requester_name": request.form.get("requester_name", "").strip(),
            "contact_number": request.form.get("contact_number", "").strip(),
            "email": request.form.get("email", "").strip(),
            "address": request.form.get("address", "").strip(),
            "document_type": request.form.get("document_type", "").strip(),
            "purpose": request.form.get("purpose", "").strip(),
            "additional_info": request.form.get("additional_info", "").strip(),
        }
        errors = []
        if len(data["requester_name"]) < 2:
            errors.append("Full name is required.")
        if not re.fullmatch(r"[0-9()+\-\s]{7,20}", data["contact_number"]):
            errors.append("A valid contact number is required.")
        if data["email"] and not valid_email(data["email"]):
            errors.append("Email address is not valid.")
        if len(data["address"]) < 5:
            errors.append("Address is required.")
        if data["document_type"] not in DOCUMENT_TYPES:
            errors.append("Please choose a valid document type.")
        if len(data["purpose"]) < 3:
            errors.append("Purpose is required.")
        if errors:
            for err in errors:
                flash(err, "danger")
            return render_template("resident/request_document.html", form=data), 400

        # Link to resident if logged in as resident, else best-effort by name
        linked_id = None
        cur = current_user()
        if cur and cur.get("role") == "resident" and cur.get("resident_id"):
            linked_id = cur.get("resident_id")
        else:
            linked_row = query_one(
                "SELECT id FROM residents WHERE LOWER(first_name || ' ' || last_name) = LOWER(?) "
                "LIMIT 1", (data["requester_name"],))
            linked_id = linked_row["id"] if linked_row else None

        number = database.next_number("REQ", "document_requests", "request_number")
        execute(
            """INSERT INTO document_requests
               (request_number, resident_id, requester_name, contact_number, email, address,
                document_type, purpose, additional_info, request_date, status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (number, linked_id, data["requester_name"],
             data["contact_number"], data["email"] or None, data["address"],
             data["document_type"], data["purpose"], data["additional_info"] or None,
             date.today().isoformat(), "Pending"))
        log_activity("SUBMIT_REQUEST", f"Public document request {number} ({data['document_type']}).")
        flash(f"Your request has been successfully submitted! Your request number is {number}. "
              f"Keep this number to track your request.", "success")
        return redirect(url_for("request_status", q=number, new=1))
    return render_template("resident/request_document.html", form={})


@app.route("/request-status")
def request_status():
    q = request.args.get("q", "").strip()
    record = None
    if q:
        record = query_one(
            "SELECT d.*, u.full_name AS processor FROM document_requests d "
            "LEFT JOIN users u ON u.id=d.processed_by WHERE UPPER(d.request_number) = UPPER(?)",
            (q,))
        if record is None:
            flash("No document request found for that request number. Please double-check it.", "warning")
    return render_template("resident/request_status.html", record=record, q=q)


@app.route("/complaint", methods=["GET", "POST"])
def complaint_file():
    if request.method == "POST":
        data = {
            "complainant_name": request.form.get("complainant_name", "").strip(),
            "contact_number": request.form.get("contact_number", "").strip(),
            "email": request.form.get("email", "").strip(),
            "subject": request.form.get("subject", "").strip(),
            "location": request.form.get("location", "").strip(),
            "description": request.form.get("description", "").strip(),
        }
        errors = []
        if len(data["complainant_name"]) < 2:
            errors.append("Name is required.")
        if not re.fullmatch(r"[0-9()+\-\s]{7,20}", data["contact_number"] or ""):
            errors.append("A valid contact number is required so we can reach you.")
        if data["email"] and not valid_email(data["email"]):
            errors.append("Email address is not valid.")
        if len(data["subject"]) < 5:
            errors.append("Subject is required (min. 5 characters).")
        if len(data["description"]) < 10:
            errors.append("Please describe the complaint in at least 10 characters.")
        if errors:
            for err in errors:
                flash(err, "danger")
            return render_template("resident/complaint.html", form=data), 400

        # Link to resident if logged in as resident
        resident_link = None
        cur2 = current_user()
        if cur2 and cur2.get("role") == "resident" and cur2.get("resident_id"):
            resident_link = cur2.get("resident_id")
        else:
            # best-effort legacy: try name match (optional)
            lr = query_one("SELECT id FROM residents WHERE LOWER(first_name || ' ' || last_name) = LOWER(?) LIMIT 1", (data["complainant_name"],))
            resident_link = lr["id"] if lr else None

        number = database.next_number("CMP", "complaints", "complaint_number")
        now = datetime.now()
        execute(
            """INSERT INTO complaints
               (complaint_number, resident_id, complainant_name, contact_number, email, subject,
                description, location, date_reported, status, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (number, resident_link, data["complainant_name"], data["contact_number"],
             data["email"] or None, data["subject"], data["description"],
             data["location"] or None, now.strftime("%Y-%m-%d"), "Pending",
             now.strftime("%Y-%m-%d %H:%M:%S")))
        log_activity("SUBMIT_COMPLAINT", f"Public complaint {number}: {data['subject']}")
        flash(f"Your complaint has been submitted successfully! Your complaint number is {number}.",
              "success")
        return redirect(url_for("complaint_status", q=number, new=1))
    return render_template("resident/complaint.html", form={})


@app.route("/complaint-status")
def complaint_status():
    q = request.args.get("q", "").strip()
    record = None
    if q:
        record = query_one(
            "SELECT * FROM complaints WHERE UPPER(complaint_number) = UPPER(?)", (q,))
        if record is None:
            flash("No complaint found for that complaint number. Please double-check it.", "warning")
    return render_template("resident/complaint_status.html", record=record, q=q)


# ===========================================================================
# ERROR HANDLERS
# ===========================================================================

@app.errorhandler(404)
def page_not_found(_e):
    return render_template("errors/404.html"), 404


@app.errorhandler(403)
def access_denied(_e):
    return render_template("errors/403.html"), 403


@app.errorhandler(400)
def bad_request(e):
    return render_template("errors/400.html", message=getattr(e, "description", "Bad request")), 400


@app.errorhandler(500)
def server_error(_e):
    try:
        get_db().rollback()
    except Exception:
        pass
    return render_template("errors/500.html"), 500


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

database.init_db()

if __name__ == "__main__":
    print("=" * 70)
    print(f"  {Config.SYSTEM_NAME} - {Config.SYSTEM_TAGLINE}")
    print("  Open http://127.0.0.1:5000 in your browser.")
    print("  Default admin login -> username: admin | password: admin123")
    print("=" * 70)
    app.run(host="127.0.0.1", port=5000, debug=True)
