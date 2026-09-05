"""
BarangayConnect - Barangay Management and Information System
Database layer: connection helpers, schema creation and first-run seeding.

The SQLite database (barangay.db) is created automatically the first time
the application starts.
"""
import os
import sqlite3
from datetime import date, timedelta

from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "barangay.db")

DOCUMENT_TYPES = [
    "Barangay Clearance",
    "Certificate of Residency",
    "Certificate of Indigency",
    "Barangay Business Clearance",
    "Certificate of Good Moral Character",
    "Other",
]

REQUEST_STATUSES = ["Pending", "Processing", "Approved", "Released", "Rejected"]
COMPLAINT_STATUSES = ["Pending", "Investigating", "Resolved", "Closed"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name     TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'staff' CHECK (role IN ('admin', 'staff', 'resident')),
    resident_id   INTEGER REFERENCES residents(id) ON DELETE SET NULL,
    email         TEXT,
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'pending')),
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS residents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    resident_id     TEXT UNIQUE NOT NULL,
    first_name      TEXT NOT NULL,
    middle_name     TEXT,
    last_name       TEXT NOT NULL,
    suffix          TEXT,
    sex             TEXT CHECK (sex IN ('Male', 'Female') OR sex IS NULL),
    birth_date      TEXT,
    birth_place     TEXT,
    civil_status    TEXT,
    nationality     TEXT DEFAULT 'Filipino',
    religion        TEXT,
    occupation      TEXT,
    contact_number  TEXT,
    email           TEXT,
    address         TEXT,
    purok           TEXT,
    voter_status    TEXT CHECK (voter_status IN ('Registered', 'Not Registered') OR voter_status IS NULL),
    residency_status TEXT,
    photo           TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS officials (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name      TEXT NOT NULL,
    position       TEXT NOT NULL,
    contact_number TEXT,
    email          TEXT,
    photo          TEXT,
    term_start     TEXT,
    term_end       TEXT,
    status         TEXT NOT NULL DEFAULT 'Active'
);

CREATE TABLE IF NOT EXISTS announcements (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    title          TEXT NOT NULL,
    content        TEXT NOT NULL,
    image          TEXT,
    author_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    published_date TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'Published' CHECK (status IN ('Published', 'Unpublished'))
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    description TEXT,
    event_date  TEXT NOT NULL,
    start_time  TEXT,
    end_time    TEXT,
    location    TEXT,
    organizer   TEXT,
    status      TEXT NOT NULL DEFAULT 'Scheduled' CHECK (status IN ('Scheduled', 'Ongoing', 'Completed', 'Cancelled')),
    image       TEXT
);

CREATE TABLE IF NOT EXISTS document_requests (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    request_number   TEXT UNIQUE NOT NULL,
    resident_id      INTEGER REFERENCES residents(id) ON DELETE SET NULL,
    requester_name   TEXT NOT NULL,
    contact_number   TEXT,
    email            TEXT,
    address          TEXT,
    document_type    TEXT NOT NULL,
    purpose          TEXT,
    additional_info  TEXT,
    request_date     TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'Pending',
    processed_by     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    remarks          TEXT,
    release_date     TEXT
);

CREATE TABLE IF NOT EXISTS complaints (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    complaint_number TEXT UNIQUE NOT NULL,
    resident_id      INTEGER REFERENCES residents(id) ON DELETE SET NULL,
    complainant_name TEXT NOT NULL,
    contact_number   TEXT,
    email            TEXT,
    subject          TEXT NOT NULL,
    description      TEXT NOT NULL,
    location         TEXT,
    date_reported    TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'Pending',
    assigned_to      TEXT,
    remarks          TEXT,
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blotter (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    blotter_number    TEXT UNIQUE NOT NULL,
    complainant       TEXT NOT NULL,
    respondent        TEXT,
    incident_type     TEXT NOT NULL,
    incident_date     TEXT NOT NULL,
    incident_location TEXT,
    description       TEXT,
    action_taken      TEXT,
    status            TEXT NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'Under Investigation', 'Settled', 'Closed')),
    recorded_by       INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS system_settings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    barangay_name  TEXT NOT NULL,
    municipality   TEXT,
    province       TEXT,
    address        TEXT,
    contact_number TEXT,
    email          TEXT,
    logo           TEXT,
    captain_name   TEXT,
    history        TEXT,
    mission        TEXT,
    vision         TEXT,
    goals          TEXT,
    hotlines       TEXT
);

CREATE TABLE IF NOT EXISTS activity_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action      TEXT NOT NULL,
    description TEXT,
    timestamp   TEXT NOT NULL,
    ip_address  TEXT
);

CREATE TABLE IF NOT EXISTS inquiries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    email      TEXT,
    subject    TEXT NOT NULL,
    message    TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'New' CHECK (status IN ('New', 'Read')),
    created_at TEXT NOT NULL
);
"""


def _migrate_for_resident_support(conn: sqlite3.Connection) -> None:
    """Migrate existing DB to support resident accounts.

    Adds:
      - users.resident_id
      - users role 'resident' and status 'pending'
      - complaints.resident_id
    Handles old CHECK constraints by rebuilding the users table if needed.
    """
    # --- users table ---
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if cols:
        if "resident_id" not in cols:
            # Need to rebuild users table to update CHECK constraints
            # Check if old table has restrictive CHECK by inspecting sql
            cur = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
            sql = (cur["sql"] or "") if cur else ""
            needs_rebuild = ("'resident'" not in sql) or ("'pending'" not in sql) or ("resident_id" not in sql)
            if needs_rebuild:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS users_new (
                        id            INTEGER PRIMARY KEY AUTOINCREMENT,
                        username      TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        full_name     TEXT NOT NULL,
                        role          TEXT NOT NULL DEFAULT 'staff' CHECK (role IN ('admin', 'staff', 'resident')),
                        resident_id   INTEGER REFERENCES residents(id) ON DELETE SET NULL,
                        email         TEXT,
                        status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'pending')),
                        created_at    TEXT NOT NULL
                    )
                """)
                # Copy existing data (resident_id will be NULL for old rows)
                conn.execute("""
                    INSERT INTO users_new (id, username, password_hash, full_name, role, email, status, created_at)
                    SELECT id, username, password_hash, full_name, role, email, status, created_at FROM users
                """)
                conn.execute("DROP TABLE users")
                conn.execute("ALTER TABLE users_new RENAME TO users")
            else:
                # Just add the column if CHECK already allows it (unlikely)
                try:
                    conn.execute("ALTER TABLE users ADD COLUMN resident_id INTEGER REFERENCES residents(id) ON DELETE SET NULL")
                except Exception:
                    pass
    # --- complaints table ---
    try:
        ccols = {row["name"] for row in conn.execute("PRAGMA table_info(complaints)").fetchall()}
        if ccols and "resident_id" not in ccols:
            conn.execute("ALTER TABLE complaints ADD COLUMN resident_id INTEGER REFERENCES residents(id) ON DELETE SET NULL")
    except Exception:
        pass
    # --- events table: add image column for event posters ---
    try:
        ecols = {row["name"] for row in conn.execute("PRAGMA table_info(events)").fetchall()}
        if ecols and "image" not in ecols:
            conn.execute("ALTER TABLE events ADD COLUMN image TEXT")
    except Exception:
        pass


def get_connection(db_path: str | None = None) -> sqlite3.Connection:
    """Return a new SQLite connection with dict-like row access."""
    conn = sqlite3.connect(db_path or DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def next_number(prefix: str, table: str, column: str) -> str:
    """Generate a sequential reference number such as REQ-2026-00001.

    Uses MAX(existing sequence) instead of COUNT(*) so that deleting
    records can never cause a duplicate-number collision.
    """
    year = date.today().year
    prefix_year = f"{prefix}-{year}-"
    pattern = f"{prefix_year}%"
    conn = get_connection()
    try:
        row = conn.execute(
            f"""SELECT MAX(CAST(REPLACE({column}, ?, '') AS INTEGER)) AS m
                FROM {table} WHERE {column} LIKE ?""",
            (prefix_year, pattern),
        ).fetchone()
        return f"{prefix_year}{(row['m'] or 0) + 1:05d}"
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Seeding
# --------------------------------------------------------------------------

def _seed_settings(conn: sqlite3.Connection) -> None:
    conn.execute(
        """INSERT INTO system_settings
           (barangay_name, municipality, province, address, contact_number,
            email, captain_name, history, mission, vision, goals, hotlines)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            "Wao",
            "Wao",
            "Lanao Del Sur",
            "Barangay Hall, Purok 1, Brgy. Wao, Lanao Del Sur",
            "(049) 555-0100",
            "wao.barangay@example.gov.ph",
            "Hon. Juan A. Dela Cruz",
            ("Brgy. Wao Lanao Del Sur was established in 1954 through Republic Act No. 1241. "
             "From a small farming community of forty families, it has grown into a "
             "progressive barangay of more than a thousand households. Through the years, "
             "its leaders have worked hand-in-hand with residents to build roads, schools, "
             "health stations, and community centers that serve every purok."),
            ("To promote the general welfare of all residents through transparent governance, "
             "accessible public services, community participation, and sustainable development."),
            ("A peaceful, self-reliant, and God-loving community where every family enjoys "
             "a safe environment, quality public service, and equal opportunity to prosper."),
            ("1. Deliver prompt and honest frontline services.\n"
             "2. Maintain peace, order, and disaster preparedness.\n"
             "3. Improve health, sanitation, and education programs.\n"
             "4. Empower youth, women, and senior citizens.\n"
             "5. Protect the environment and barangay resources."),
            ("Emergency: 911\nBarangay Hall: (049) 555-0100\nHealth Center: (049) 555-0101\n"
             "Police: 117 / (049) 555-0102\nFire: 116\nRed Cross: 143"),
        ),
    )


def _seed_users(conn: sqlite3.Connection) -> None:
    now = _now_iso()
    conn.execute(
        "INSERT INTO users (username, password_hash, full_name, role, email, status, created_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (
            "admin",
            generate_password_hash("admin123"),
            "System Administrator",
            "admin",
            "admin@sanisidro.gov.ph",
            "active",
            now,
        ),
    )
    conn.execute(
        "INSERT INTO users (username, password_hash, full_name, role, email, status, created_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (
            "staff",
            generate_password_hash("staff123"),
            "Maria Santos",
            "staff",
            "staff@sanisidro.gov.ph",
            "active",
            now,
        ),
    )


def _seed_officials(conn: sqlite3.Connection) -> None:
    officials = [
        ("Hon. Juan A. Dela Cruz", "Punong Barangay", "(049) 555-0100", "captain@sanisidro.gov.ph", "2023-11-30", "2025-11-30"),
        ("Hon. Roberto M. Santiago", "Barangay Kagawad", "(049) 555-0111", None, "2023-11-30", "2025-11-30"),
        ("Hon. Elena R. Bautista", "Barangay Kagawad", "(049) 555-0112", None, "2023-11-30", "2025-11-30"),
        ("Hon. Carlos D. Reyes", "Barangay Kagawad", "(049) 555-0113", None, "2023-11-30", "2025-11-30"),
        ("Hon. Lourdes P. Mendoza", "Barangay Kagawad", "(049) 555-0114", None, "2023-11-30", "2025-11-30"),
        ("Hon. Alfredo T. Villanueva", "Barangay Kagawad", "(049) 555-0115", None, "2023-11-30", "2025-11-30"),
        ("Hon. Carmen S. Aquino", "Barangay Kagawad", "(049) 555-0116", None, "2023-11-30", "2025-11-30"),
        ("Hon. Pedro G. Flores", "Barangay Kagawad", "(049) 555-0117", None, "2023-11-30", "2025-11-30"),
        ("Hon. Angelica K. Ramos", "SK Chairperson", "(049) 555-0118", None, "2023-11-30", "2025-11-30"),
        ("Ms. Teresita L. Navarro", "Barangay Secretary", "(049) 555-0119", "secretary@sanisidro.gov.ph", "2023-11-30", "2025-11-30"),
        ("Mr. Domingo B. Cruz", "Barangay Treasurer", "(049) 555-0120", "treasurer@sanisidro.gov.ph", "2023-11-30", "2025-11-30"),
        ("Mr. Rafael O. Gutierrez", "BARANGAY Tanod - Team Lead", "(049) 555-0121", None, "2023-11-30", "2025-11-30"),
    ]
    conn.executemany(
        "INSERT INTO officials (full_name, position, contact_number, email, term_start, term_end, status)"
        " VALUES (?,?,?,?,?,?,?)",
        [(n, p, c, e, ts, te, "Active") for n, p, c, e, ts, te in officials],
    )


def _seed_announcements(conn: sqlite3.Connection) -> None:
    today = date.today()
    items = [
        (
            "Free Medical and Dental Mission this Coming Sunday",
            "The Barangay Health Center, in partnership with the Municipal Health Office, will hold a FREE medical and dental mission on Sunday at the Barangay Covered Court from 8:00 AM to 3:00 PM. Free consultation, medicines, blood-pressure screening, and tooth extraction will be provided. Please bring your own water bottle and fall in line early. Senior citizens and persons with disability will be prioritized.",
            2,
        ),
        (
            "Schedule of House-to-House Anti-Rabies Vaccination",
            "The Municipal Agriculture Office will conduct house-to-house anti-rabies vaccination for dogs and cats starting next week, Monday to Friday, 9:00 AM to 4:00 PM in all puroks. Kindly restrain your pets during the visit of the vaccination team. The service is free of charge.",
            5,
        ),
        (
            "Cash Assistance Program for Indigent Families Now Open",
            "Qualified indigent families may now apply for the Cash Assistance Program at the Barangay Social Services Office. Requirements: Barangay Certificate of Indigency, valid ID, and proof of residency. Application forms are available at the Barangay Hall window 2, weekdays from 8:00 AM to 5:00 PM.",
            8,
        ),
    ]
    for title, content, days_ago in items:
        conn.execute(
            "INSERT INTO announcements (title, content, author_id, published_date, status)"
            " VALUES (?,?,?,?,?)",
            (title, content, 1, _iso(today - timedelta(days=days_ago)), "Published"),
        )


def _seed_events(conn: sqlite3.Connection) -> None:
    today = date.today()
    events = [
        (
            "Barangay Clean-Up Drive",
            "Join our monthly clean-up drive! Volunteers will be grouped per purok. Gloves, trash bags, and rakes will be provided. Assembly time is 6:30 AM at the covered court. Breakfast will be served after the activity.",
            today + timedelta(days=6),
            "07:00", "10:00", "Barangay Covered Court", "Barangay Environment Committee", "Scheduled",
        ),
        (
            "Free Zumba and Wellness Session",
            "Stay fit and healthy! Open to all ages. Led by certified volunteer instructors from the Municipal Sports Office. Bring your own towel and bottled water.",
            today + timedelta(days=12),
            "05:30", "07:00", "Barangay Plaza", "Barangay Health Workers", "Scheduled",
        ),
        (
            "Youth Leadership Summit 2026",
            "A one-day leadership training for SK members and out-of-school youth featuring talks on volunteerism, digital literacy, and community projects. Limited to 80 participants; register at the SK office.",
            today + timedelta(days=20),
            "08:00", "16:00", "Barangay Hall Session Hall", "Sangguniang Kabataan", "Scheduled",
        ),
        (
            "Bloodletting Activity with Philippine Red Cross",
            "Save a life by donating blood. Donors must be at least 110 lbs, well-rested, and have eaten before donating. Free snacks and donor's card will be given.",
            today + timedelta(days=27),
            "08:00", "14:00", "Barangay Health Center", "Barangay Health Center & Red Cross", "Scheduled",
        ),
    ]
    conn.executemany(
        "INSERT INTO events (title, description, event_date, start_time, end_time, location, organizer, status)"
        " VALUES (?,?,?,?,?,?,?,?)",
        [
            (t, d, _iso(dt), st, et, loc, org, s)
            for t, d, dt, st, et, loc, org, s in events
        ],
    )


def _seed_residents(conn: sqlite3.Connection) -> None:
    """Insert demo resident records so dashboards/reports are meaningful."""
    people = [
        # first, middle, last, suffix, sex, birth, birth_place, civil, occ, contact, purok, voter, residency
        ("Juan", "Reyes", "Dela Cruz", "Jr.", "Male", "1975-03-12", "Sampaguita, Laguna", "Married", "Tricycle Driver", "0917-100-1001", "Purok 1", "Registered", "Permanent"),
        ("Maria", "Santos", "Dela Cruz", "", "Female", "1978-07-22", "Sampaguita, Laguna", "Married", "Public School Teacher", "0917-100-1002", "Purok 1", "Registered", "Permanent"),
        ("Pedro", "Lim", "Santiago", "", "Male", "1952-01-05", "Manila", "Widowed", "Retired Farmer", "0917-100-1003", "Purok 2", "Registered", "Permanent"),
        ("Juana", "Reyes", "Santiago", "", "Female", "1980-11-18", "Sampaguita, Laguna", "Married", "Sari-Sari Store Owner", "0917-100-1004", "Purok 2", "Registered", "Permanent"),
        ("Andres", "Bonifacio", "Mendoza", "", "Male", "1999-06-30", "Sampaguita, Laguna", "Single", "Construction Worker", "0917-100-1005", "Purok 3", "Registered", "Permanent"),
        ("Corazon", "Aquino", "Mendoza", "", "Female", "2001-02-14", "Sampaguita, Laguna", "Single", "Call Center Agent", "0917-100-1006", "Purok 3", "Not Registered", "Renting"),
        ("Jose", "Rizal", "Villanueva", "", "Male", "1988-12-01", "Calamba, Laguna", "Married", "Carpenter", "0917-100-1007", "Purok 4", "Registered", "Permanent"),
        ("Liwayway", "Garcia", "Villanueva", "", "Female", "1990-04-09", "Sampaguita, Laguna", "Married", "Seamstress", "0917-100-1008", "Purok 4", "Registered", "Permanent"),
        ("Antonio", "Luna", "Flores", "", "Male", "1965-08-25", "Sampaguita, Laguna", "Separated", "Fisherman", "0917-100-1009", "Purok 5", "Registered", "Permanent"),
        ("Rosa", "Mercado", "Flores", "", "Female", "2010-09-17", "Sampaguita, Laguna", "Single", "Student", "", "Purok 5", "Not Registered", "Permanent"),
        ("Emmanuel", "Panganiban", "Reyes", "", "Male", "1993-05-21", "Sampaguita, Laguna", "Single", "Delivery Rider", "0917-100-1010", "Purok 1", "Registered", "Renting"),
        ("Angel", "Domingo", "Reyes", "", "Female", "2015-10-03", "Sampaguita, Laguna", "Single", "Student", "", "Purok 1", "Not Registered", "Permanent"),
        ("Gregorio", "Del Pilar", "Bautista", "", "Male", "1958-02-11", "Sampaguita, Laguna", "Married", "Barangay Tanod", "0917-100-1011", "Purok 2", "Registered", "Permanent"),
        ("Teresita", "Navarro", "Bautista", "", "Female", "1962-06-06", "Sampaguita, Laguna", "Married", "Barangay Health Worker", "0917-100-1012", "Purok 2", "Registered", "Permanent"),
        ("Miguel", "Malvar", "Aquino", "", "Male", "2003-08-15", "Sampaguita, Laguna", "Single", "College Student", "0917-100-1013", "Purok 3", "Registered", "Permanent"),
        ("Katrina", "Halili", "Aquino", "", "Female", "1997-12-25", "Biñan, Laguna", "Single", "Nurse", "0917-100-1014", "Purok 3", "Registered", "Renting"),
        ("Danilo", "Cruz", "Gutierrez", "", "Male", "1985-03-30", "Sampaguita, Laguna", "Married", "Jeepney Driver", "0917-100-1015", "Purok 4", "Registered", "Permanent"),
        ("Susan", "Roces", "Gutierrez", "", "Female", "1987-07-08", "Sampaguita, Laguna", "Married", "Housewife", "", "Purok 4", "Not Registered", "Permanent"),
        ("Fernando", "Amorsolo", "Torres", "", "Male", "2012-01-19", "Sampaguita, Laguna", "Single", "Student", "", "Purok 5", "Not Registered", "Permanent"),
        ("Ligaya", "Sarmiento", "Torres", "", "Female", "2018-04-27", "Sampaguita, Laguna", "Single", "Child", "", "Purok 5", "Not Registered", "Permanent"),
        ("Ramon", "Magsaysay", "Ocampo", "", "Male", "1970-09-02", "Sampaguita, Laguna", "Married", "Electrician", "0917-100-1016", "Purok 1", "Registered", "Permanent"),
        ("Imelda", "Marcos", "Ocampo", "", "Female", "1972-11-11", "Sampaguita, Laguna", "Married", "Barangay Kagawad Aide", "0917-100-1017", "Purok 1", "Registered", "Permanent"),
        ("Victor", "Wood", "Domingo", "", "Male", "2007-06-13", "Sta. Cruz, Laguna", "Single", "Student", "0917-100-1018", "Purok 2", "Not Registered", "Transient"),
        ("Perla", "Cristobal", "Domingo", "", "Female", "1955-01-29", "Sampaguita, Laguna", "Widowed", "Retired Midwife", "0917-100-1019", "Purok 3", "Registered", "Permanent"),
        ("Alfredo", "Santos", "Navarro", "", "Male", "1995-10-10", "Sampaguita, Laguna", "Single", "Security Guard", "0917-100-1020", "Purok 4", "Registered", "Renting"),
        ("Divina", "Pastor", "Navarro", "", "Female", "1996-03-23", "Sampaguita, Laguna", "Single", "Saleslady", "0917-100-1021", "Purok 4", "Not Registered", "Renting"),
        ("Rodrigo", "Duterte", "Salazar", "", "Male", "1968-05-05", "Davao City", "Married", "Welder", "0917-100-1022", "Purok 5", "Registered", "Permanent"),
        ("Honeylet", "Avanceña", "Salazar", "", "Female", "1974-08-19", "Sampaguita, Laguna", "Married", "Caregiver", "0917-100-1023", "Purok 5", "Registered", "Permanent"),
        ("Benigno", "Aquino", "Marquez", "", "Male", "2019-12-31", "Sampaguita, Laguna", "Single", "Child", "", "Purok 1", "Not Registered", "Permanent"),
        ("Kris", "Aquino", "Marquez", "", "Female", "2016-02-29", "Sampaguita, Laguna", "Single", "Child", "", "Purok 2", "Not Registered", "Permanent"),
        ("Efren", "Reyes", "Bata", "", "Male", "1982-04-16", "Angeles, Pampanga", "Married", "Billiard Instructor", "0917-100-1024", "Purok 3", "Registered", "Transient"),
        ("Sharon", "Gamboa", "Bata", "", "Female", "1984-09-28", "Sampaguita, Laguna", "Married", "Online Seller", "0917-100-1025", "Purok 3", "Registered", "Transient"),
    ]
    year = date.today().year
    seq = 0
    for p in people:
        seq += 1
        rid = f"BRGY-{year}-{seq:05d}"
        first, middle, last, suffix, sex, bday, bplace, civil, occ, contact, purok, voter, res = p
        conn.execute(
            """INSERT INTO residents
               (resident_id, first_name, middle_name, last_name, suffix, sex, birth_date,
                birth_place, civil_status, nationality, religion, occupation, contact_number,
                email, address, purok, voter_status, residency_status, photo, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                rid, first, middle or None, last, suffix or None, sex, bday, bplace, civil,
                "Filipino", None, occ or None, contact or None, None,
                f"Purok {purok.split()[-1]}, Brgy. Wao, Lanao Del Sur"
                if purok else None,
                purok, voter, res, None, _now_iso(), _now_iso(),
            ),
        )


def _seed_documents_and_complaints(conn: sqlite3.Connection) -> None:
    today = date.today()
    docs = [
        ("REQ-{}-00001".format(today.year), 1, "Juan R. Dela Cruz Jr.", "0917-100-1001", "juan.delacruz@example.com", "Purok 1, Brgy. Wao Lanao Del Sur", "Barangay Clearance", "Local employment requirement", "Pending"),
        ("REQ-{}-00002".format(today.year), 3, "Pedro L. Santiago", "0917-100-1003", None, "Purok 2, Brgy. Wao Lanao Del Sur", "Certificate of Indigency", "Medical assistance application", "Processing"),
        ("REQ-{}-00003".format(today.year), 7, "Jose R. Villanueva", "0917-100-1007", None, "Purok 4, Brgy. Wao Lanao Del Sur", "Certificate of Residency", "School enrollment of child", "Approved"),
    ]
    for num, resid, name, contact, email, addr, dtype, purpose, status in docs:
        conn.execute(
            """INSERT INTO document_requests
               (request_number, resident_id, requester_name, contact_number, email, address,
                document_type, purpose, request_date, status)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (num, resid, name, contact, email, addr, dtype, purpose, _iso(today), status),
        )

    complaints = [
        ("CMP-{}-00001".format(today.year), "Juana R. Santiago", "0917-100-1004", "juana.santiago@example.com", "Stray dogs roaming near daycare center", "There are at least five stray dogs gathering near the daycare every afternoon. Children are scared and one was nearly bitten last week.", "Near Purok 2 Daycare Center", "Investigating", "Tanod Team B"),
        ("CMP-{}-00002".format(today.year), "Danilo C. Gutierrez", "0917-100-1015", None, "Broken streetlight along Purok 4 road", "The streetlight in front of the chapel has been busted for two weeks. The road is very dark at night.", "Purok 4, in front of San Isidro Chapel", "Resolved", "Utilities Committee"),
    ]
    for num, name, contact, email, subject, desc, loc, status, assigned in complaints:
        conn.execute(
            """INSERT INTO complaints
               (complaint_number, complainant_name, contact_number, email, subject, description,
                location, date_reported, status, assigned_to, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (num, name, contact, email, subject, desc, loc,
             _iso(today - timedelta(days=2)), status, assigned, _now_iso()),
        )

    conn.execute(
        """INSERT INTO blotter
           (blotter_number, complainant, respondent, incident_type, incident_date,
            incident_location, description, action_taken, status, recorded_by, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            "BLT-{}-00001".format(today.year),
            "Antonio L. Flores",
            "Unnamed tricycle driver",
            "Traffic Incident / Near-Accident",
            _iso(today - timedelta(days=1)),
            "Corner of Rizal St. and Purok 5 Road",
            "A speeding tricycle almost hit two schoolchildren crossing the street. Complainant requests additional speed hump and tanod post in the area during dismissal hours.",
            "Advised both parties; endorsed request for speed hump to Barangay Engineering Committee.",
            "Under Investigation",
            1,
            _now_iso(),
        ),
    )


def _now_iso() -> str:
    from datetime import datetime

    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _iso(d: date) -> str:
    return d.strftime("%Y-%m-%d")


def init_db(db_path: str | None = None) -> None:
    """Create tables (if missing) and seed first-run data."""
    path = db_path or DATABASE
    conn = get_connection(path)
    try:
        conn.executescript(SCHEMA)
        _migrate_for_resident_support(conn)

        users_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        if users_count == 0:
            _seed_users(conn)
            _seed_settings(conn)
            _seed_officials(conn)
            _seed_announcements(conn)
            _seed_events(conn)
            _seed_residents(conn)
            _seed_documents_and_complaints(conn)
            conn.commit()
            print("[BarangayConnect] Database created and seeded with sample data.")
            print("[BarangayConnect] Default admin -> username: admin | password: admin123 (CHANGE THIS!)")
            print("[BarangayConnect] Demo staff  -> username: staff | password: staff123 (CHANGE THIS!)")
        else:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Database ready at {DATABASE}")
