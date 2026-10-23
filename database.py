import hashlib
import sqlite3
from pathlib import Path
from datetime import datetime
import uuid


DATABASE_PATH = Path(__file__).resolve().parent / "campusgig.db"
SCHEMA_VERSION = 2


def get_connection():
    """Open a reliable SQLite connection with integrity and concurrency settings."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(DATABASE_PATH), timeout=30)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    # WAL lets readers continue while a write is in progress. FULL sync asks
    # SQLite to flush committed transactions safely to disk.
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = FULL")
    return connection


def verify_database(database_path=DATABASE_PATH):
    """Return integrity and foreign-key check results for a SQLite database."""
    check_connection = sqlite3.connect(str(database_path), timeout=30)
    try:
        integrity = check_connection.execute("PRAGMA integrity_check").fetchone()[0]
        foreign_key_errors = check_connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()
        return integrity, foreign_key_errors
    finally:
        check_connection.close()


def create_database_backup(destination=None):
    """Create an atomic, online backup and verify it before publishing the file."""
    if destination is None:
        backup_dir = DATABASE_PATH.parent / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        destination = backup_dir / (
            f"campusgig_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        )

    destination = Path(destination).expanduser().resolve()
    source_path = DATABASE_PATH.resolve()
    if destination == source_path:
        raise ValueError("The backup destination cannot be the active database.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = destination.with_name(
        f".{destination.name}.{uuid.uuid4().hex}.tmp"
    )

    source_connection = None
    backup_connection = None
    try:
        source_connection = get_connection()
        backup_connection = sqlite3.connect(str(temporary_path), timeout=30)
        source_connection.backup(backup_connection)
        backup_connection.commit()
        integrity, foreign_key_errors = verify_database(temporary_path)
        if integrity != "ok" or foreign_key_errors:
            raise sqlite3.DatabaseError(
                f"Backup verification failed: integrity={integrity}, "
                f"foreign_key_errors={len(foreign_key_errors)}"
            )
        backup_connection.close()
        backup_connection = None
        temporary_path.replace(destination)
        return destination
    except Exception:
        if backup_connection is not None:
            backup_connection.close()
            backup_connection = None
        if source_connection is not None:
            source_connection.close()
            source_connection = None
        if temporary_path.exists():
            temporary_path.unlink()
        raise
    finally:
        if backup_connection is not None:
            backup_connection.close()
        if source_connection is not None:
            source_connection.close()


def _ensure_column(cursor, table_name, column_name, column_definition):
    """Add a column to an existing table only when it is not already present."""
    existing_columns = {
        row[1] for row in cursor.execute(f"PRAGMA table_info({table_name})")
    }
    if column_name not in existing_columns:
        cursor.execute(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}"
        )


def add_sample_data(cursor):
    demo_password = hashlib.sha256("demo123".encode()).hexdigest()

    cursor.execute("""
        INSERT OR IGNORE INTO users (username, email, password, user_type)
        VALUES (?, ?, ?, ?)
    """, ("provider_demo", "provider@campusgig.com", demo_password, "Provider"))

    cursor.execute("""
        INSERT OR IGNORE INTO users (username, email, password, user_type)
        VALUES (?, ?, ?, ?)
    """, ("customer_demo", "customer@campusgig.com", demo_password, "Customer"))

    cursor.execute("SELECT user_id FROM users WHERE username = ?", ("provider_demo",))
    provider_id = cursor.fetchone()[0]

    cursor.execute("SELECT user_id FROM users WHERE username = ?", ("customer_demo",))
    customer_id = cursor.fetchone()[0]

    cursor.execute("""
        INSERT OR IGNORE INTO profiles (user_id, full_name, college, bio)
        VALUES (?, ?, ?, ?)
    """, (provider_id, "Aarav Sharma", "Campus University", "Programming tutor and graphic designer."))

    cursor.execute("""
        INSERT OR IGNORE INTO profiles (user_id, full_name, college, bio)
        VALUES (?, ?, ?, ?)
    """, (customer_id, "Meera Patel", "Campus University", "Looking for student services."))

    cursor.execute("SELECT COUNT(*) FROM services WHERE provider_id = ?", (provider_id,))
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO services (provider_id, title, description, category, price)
            VALUES (?, ?, ?, ?, ?)
        """, (
            provider_id,
            "Python Programming Tutoring",
            "One-to-one help with Python basics, assignments, and debugging.",
            "Programming",
            300
        ))

        cursor.execute("""
            INSERT INTO services (provider_id, title, description, category, price)
            VALUES (?, ?, ?, ?, ?)
        """, (
            provider_id,
            "Poster and Presentation Design",
            "Clean posters and presentation slides for college projects and events.",
            "Graphic Design",
            250
        ))


def _create_core_tables(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            user_type TEXT NOT NULL CHECK(user_type IN ('Provider', 'Customer')),
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            profile_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            full_name TEXT,
            phone TEXT,
            college TEXT,
            bio TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS skills (
            skill_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            skill_name TEXT NOT NULL,
            expertise_level TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS services (
            service_id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            status TEXT DEFAULT 'Available',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (provider_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS service_requests (
            request_id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_id INTEGER NOT NULL,
            customer_id INTEGER NOT NULL,
            provider_id INTEGER NOT NULL,
            message TEXT,
            request_status TEXT DEFAULT 'Pending'
                CHECK(request_status IN ('Pending', 'Accepted', 'Rejected', 'Completed')),
            requested_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (service_id) REFERENCES services(service_id) ON DELETE CASCADE,
            FOREIGN KEY (customer_id) REFERENCES users(user_id) ON DELETE CASCADE,
            FOREIGN KEY (provider_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            review_id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL UNIQUE,
            reviewer_id INTEGER NOT NULL,
            provider_id INTEGER NOT NULL,
            rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
            review_text TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (request_id) REFERENCES service_requests(request_id) ON DELETE CASCADE,
            FOREIGN KEY (reviewer_id) REFERENCES users(user_id) ON DELETE CASCADE,
            FOREIGN KEY (provider_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)


def _create_platform_tables(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS project_submissions (
            submission_id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            provider_id INTEGER NOT NULL,
            file_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            message TEXT,
            submission_status TEXT NOT NULL DEFAULT 'Submitted'
                CHECK(submission_status IN ('Submitted', 'Revision Requested', 'Approved', 'Rejected')),
            revision_number INTEGER NOT NULL DEFAULT 1 CHECK(revision_number > 0),
            uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (request_id) REFERENCES service_requests(request_id) ON DELETE CASCADE,
            FOREIGN KEY (provider_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            payment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL UNIQUE,
            customer_id INTEGER NOT NULL,
            provider_id INTEGER NOT NULL,
            gross_amount REAL NOT NULL CHECK(gross_amount >= 0),
            commission_rate REAL NOT NULL CHECK(commission_rate BETWEEN 0 AND 100),
            commission_amount REAL NOT NULL CHECK(commission_amount >= 0),
            provider_amount REAL NOT NULL CHECK(provider_amount >= 0),
            payment_status TEXT NOT NULL DEFAULT 'Pending'
                CHECK(payment_status IN ('Pending', 'Completed', 'Failed', 'Refunded')),
            payment_mode TEXT NOT NULL DEFAULT 'Demo',
            transaction_reference TEXT UNIQUE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            paid_at TEXT,
            FOREIGN KEY (request_id) REFERENCES service_requests(request_id) ON DELETE CASCADE,
            FOREIGN KEY (customer_id) REFERENCES users(user_id) ON DELETE RESTRICT,
            FOREIGN KEY (provider_id) REFERENCES users(user_id) ON DELETE RESTRICT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS provider_payouts (
            payout_id INTEGER PRIMARY KEY AUTOINCREMENT,
            payment_id INTEGER NOT NULL UNIQUE,
            provider_id INTEGER NOT NULL,
            amount REAL NOT NULL CHECK(amount >= 0),
            payout_status TEXT NOT NULL DEFAULT 'Pending'
                CHECK(payout_status IN ('Pending', 'Approved', 'Processed', 'Failed')),
            payout_reference TEXT UNIQUE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            processed_at TEXT,
            processed_by_admin_id INTEGER,
            FOREIGN KEY (payment_id) REFERENCES payments(payment_id) ON DELETE RESTRICT,
            FOREIGN KEY (provider_id) REFERENCES users(user_id) ON DELETE RESTRICT,
            FOREIGN KEY (processed_by_admin_id) REFERENCES admins(admin_id) ON DELETE SET NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            activity_id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_type TEXT NOT NULL CHECK(actor_type IN ('User', 'Admin', 'System')),
            actor_id INTEGER,
            action TEXT NOT NULL,
            description TEXT,
            related_type TEXT,
            related_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS platform_settings (
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_submissions_request
        ON project_submissions(request_id, uploaded_at)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_payments_status
        ON payments(payment_status, created_at)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_payouts_status
        ON provider_payouts(payout_status, created_at)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_activity_created
        ON activity_logs(created_at)
    """)


def create_tables():
    connection = get_connection()
    try:
        cursor = connection.cursor()
        _create_core_tables(cursor)

        # Add the user-management field without replacing existing user records.
        _ensure_column(
            cursor,
            "users",
            "account_status",
            "TEXT NOT NULL DEFAULT 'Active' CHECK(account_status IN ('Active', 'Deactivated', 'Suspended'))",
        )

        _create_platform_tables(cursor)
        # Admin moderation hides a review from public ratings without deleting its history.
        _ensure_column(
            cursor,
            "reviews",
            "moderation_status",
            "TEXT NOT NULL DEFAULT 'Visible' CHECK(moderation_status IN ('Visible', 'Hidden'))",
        )
        _ensure_column(cursor, "reviews", "moderation_note", "TEXT")
        _ensure_column(
            cursor,
            "reviews",
            "moderated_by_admin_id",
            "INTEGER REFERENCES admins(admin_id) ON DELETE SET NULL",
        )
        _ensure_column(cursor, "reviews", "moderated_at", "TEXT")
        cursor.execute("""
            INSERT OR IGNORE INTO platform_settings (setting_key, setting_value)
            VALUES ('commission_rate', '10')
        """)

        add_sample_data(cursor)
        cursor.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        connection.commit()
        print("Database and tables created successfully.")
    finally:
        connection.close()


if __name__ == "__main__":
    create_tables()
