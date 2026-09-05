# BarangayConnect — Barangay Management and Information System

A complete, working **Barangay Web Management System** built with **Python 3 / Flask / SQLite3 /
Bootstrap 5 / Jinja2**, designed for real Philippine barangay operations: resident records,
document requests, complaints, blotter records, announcements, events, reports, and more.

---

## ✨ Features

| Area | Highlights |
|---|---|
| **Authentication** | Secure login/logout, Werkzeug password hashing, session management, CSRF protection on all POST forms |
| **Roles** | `admin` (full control), `staff` (limited), plus a public website for residents (no login needed) |
| **Dashboard** | Stat cards + Chart.js charts (gender, age groups, purok, document & complaint status) + recent activity |
| **Residents** | Full CRUD, search, filters, sortable columns, pagination, profile page with print, auto IDs (`BRGY-2026-00001`) |
| **Officials** | Manage Punong Barangay, Kagawads, SK, Secretary, Treasurer; public officials page grouped by position |
| **Documents** | Public request form → tracking by request number (`REQ-2026-00001`) → admin status workflow (Pending → Processing → Approved → Released/Rejected) |
| **Complaints** | Public complaint form → complaint number (`CMP-2026-00001`) → admin assignment/status/remarks; public status checker |
| **Blotter** | Admin-only blotter registry (`BLT-2026-00001`) |
| **Announcements / Events** | Publish/unpublish announcements with images; event cards on the public site |
| **Reports** | Resident/document/complaint summaries, printable, exportable to CSV |
| **Users & Security** | Admin manages accounts, activity logs audit trail, system settings for barangay identity |

---

## 🚀 Installation

> Requires Python 3.9+ (tested on Python 3.14).

```bash
# 1. Create a virtual environment
python -m venv venv
```

Windows:

```bash
venv\Scripts\activate
```

Linux/macOS:

```bash
source venv/bin/activate
```

```bash
# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the application
python app.py
```

Then open: **http://127.0.0.1:5000**

On first run the app automatically:
1. Creates `barangay.db`
2. Creates all tables
3. Seeds the default administrator (**and demo staff**) account
4. Inserts sample barangay information, officials, announcements, events, residents,
   document requests, complaints and one blotter record so you can explore immediately

### Default Accounts

| Role | Username | Password |
|---|---|---|
| Administrator | `admin` | `admin123` |
| Staff | `staff` | `staff123` |

> ⚠️ **IMPORTANT — CHANGE THE DEFAULT PASSWORDS IMMEDIATELY.**
> Log in as `admin`, go to **Admin → Users**, edit each account and set a strong new password.
> Anyone who knows these defaults can access your barangay data until they are changed.

---

## 👥 User Roles

### Administrator
Everything: dashboard, residents, officials, staff accounts, documents, complaints, blotter,
announcements, events, users, reports, activity logs, settings, exports.

### Staff
View/add/edit residents, process document requests, manage announcements, manage complaints,
view dashboard and reports. Staff **cannot** manage users, blotter, events, officials,
settings or activity logs, and cannot delete residents/records.

### Public Resident (no login)
Homepage, About, Officials, Announcements, Events, Services, Contact/hotlines,
request documents online, track requests, file complaints, track complaints.

---

## 🗄️ Database Structure

SQLite database file: `barangay.db` (created automatically in the project root).

| Table | Purpose |
|---|---|
| `users` | Admin/staff accounts (`password_hash`, role, status) |
| `residents` | Resident master list (auto `resident_id`, photo, purok, voter/residency status…) |
| `officials` | Barangay officials and their terms |
| `announcements` | News items shown publicly when *Published* |
| `events` | Community events |
| `document_requests` | Online certificate/clearance requests + processing trail |
| `complaints` | Public complaints + assignment/remarks |
| `blotter` | Blotter incident registry |
| `system_settings` | Barangay name/address/logo/history/mission/vision/goals/hotlines (single row, id=1) |
| `activity_logs` | Audit trail of important actions (login, CRUD, processing…), with IP address |
| `inquiries` | Messages from the public contact form |

All SQL uses **parameterized queries**. To reset the whole system, stop the server, delete
`barangay.db`, and start again — everything is re-created and re-seeded.

---

## 🔧 Customization

### Change barangay information
Log in as admin → **Settings**. Edit barangay name, municipality, province, address, contacts,
Punong Barangay name, logo, hotlines, history/mission/vision/goals. These feed the public
homepage, About, Contact, and footer instantly.

### Add officials
**Admin → Barangay Officials → Add Official.** Choose position, term dates, upload a photo.
They appear on the public *Officials* page grouped by position.

### Change the admin password
**Admin → Users → ✏️ (edit) → enter a new password (min. 6 chars) → Save.**
Passwords are stored as salted hashes (Werkzeug PBKDF2); plain text is never saved.

To change a password from the command line instead:

```bash
python - <<'PY'
from werkzeug.security import generate_password_hash
import sqlite3
new = generate_password_hash("YourNewStrongPassword")
db = sqlite3.connect("barangay.db")
db.execute("UPDATE users SET password_hash=? WHERE username='admin'", (new,))
db.commit()
print("done")
PY
```

### Backup the SQLite database
1. **While the server is stopped** (safest): copy `barangay.db` to external storage.
2. Or use SQLite's backup API while running:

```bash
python -c "import sqlite3; sqlite3.connect('backup.db').backup(sqlite3.connect('barangay.db')); print('Backup created: backup.db')"
```

Restore = replace `barangay.db` with your backup file and restart.

---

## 📁 Project Structure

```text
barangay_system/
├── app.py                 # All routes, auth, RBAC, CSRF, validation, exports
├── database.py            # Schema creation + first-run seeding
├── config.py              # Secret key handling, paths, limits
├── requirements.txt
├── barangay.db            # Created automatically on first run
├── static/
│   ├── css/style.css      # Government/community theme on Bootstrap 5
│   ├── js/main.js         # Sidebar, toasts, confirm modal, print
│   ├── images/            # Logo + avatar SVG placeholders
│   └── uploads/           # Uploaded photos/logos (created at runtime)
└── templates/
    ├── base.html          # Skeleton (CDN assets, toasts)
    ├── partials/          # Public navbar + footer
    ├── macros.html        # CSRF field, pagination, badges, confirm modal
    ├── index/about/officials/...   # Public pages
    ├── login.html
    ├── errors/            # 400/403/404/500 pages
    ├── admin/             # Dashboard + management screens
    │   └── base_admin.html  # Sidebar shell (collapses on mobile)
    └── resident/          # Request/complaint forms + status checkers
```

---

## 🔐 Security Notes

* Passwords hashed with Werkzeug (`generate_password_hash`)
* Session-based auth with login required on every private route; `/admin` redirects anonymous
  visitors to the login page; unauthorized roles get a **403 Access Denied** page
* CSRF tokens verified on every POST request
* All queries parameterized; uploads restricted by extension and size (5 MB max);
  secret key persisted in `.secret_key` (override with the `SECRET_KEY` env var)

---

## 🧪 Verifying the Core Workflow

Public site → submit document request → receive `REQ-…` number → admin login → dashboard shows
the pending count → Documents → open request → set *Approved/Released* → resident re-checks the
number on `/request-status` and sees the updated status and release date. The same loop applies
to residents CRUD and complaints.

---

Powered by **BarangayConnect** — built for the community. 🇵🇭
