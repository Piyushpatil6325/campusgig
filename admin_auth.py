"""Authentication helpers for the separate CampusGig administrator account."""

import hashlib
import hmac
import secrets
import sqlite3

from database import get_connection


HASH_NAME = "sha256"
HASH_ITERATIONS = 600_000
SALT_BYTES = 16


def admin_exists():
    connection = get_connection()
    try:
        return connection.execute("SELECT EXISTS(SELECT 1 FROM admins)").fetchone()[0] == 1
    finally:
        connection.close()


def _hash_password(password):
    salt = secrets.token_bytes(SALT_BYTES)
    derived_key = hashlib.pbkdf2_hmac(
        HASH_NAME,
        password.encode("utf-8"),
        salt,
        HASH_ITERATIONS,
    )
    return f"pbkdf2_{HASH_NAME}${HASH_ITERATIONS}${salt.hex()}${derived_key.hex()}"


def _verify_password(password, stored_hash):
    try:
        algorithm, iterations_text, salt_text, expected_text = stored_hash.split("$")
        if algorithm != f"pbkdf2_{HASH_NAME}":
            return False

        iterations = int(iterations_text)
        if not 100_000 <= iterations <= 2_000_000:
            return False

        salt = bytes.fromhex(salt_text)
        expected = bytes.fromhex(expected_text)
        actual = hashlib.pbkdf2_hmac(
            HASH_NAME,
            password.encode("utf-8"),
            salt,
            iterations,
        )
        return hmac.compare_digest(actual, expected)
    except (AttributeError, TypeError, ValueError):
        return False


def create_first_admin(username, email, password):
    """Create the first admin exactly once; there is no public admin signup."""
    username = username.strip()
    email = email.strip().lower()

    if len(username) < 3:
        raise ValueError("Admin username must contain at least 3 characters.")
    if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
        raise ValueError("Enter a valid admin email address.")
    if len(password) < 12:
        raise ValueError("Admin password must contain at least 12 characters.")

    connection = get_connection()
    try:
        # Serialize first-run setup so two setup windows cannot create two admins.
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("SELECT EXISTS(SELECT 1 FROM admins)").fetchone()[0]:
            raise ValueError("An administrator is already set up.")

        connection.execute("""
            INSERT INTO admins (username, email, password_hash)
            VALUES (?, ?, ?)
        """, (username, email, _hash_password(password)))
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def authenticate_admin(identifier, password):
    """Return (admin_id, username) only for an active admin with a valid password."""
    identifier = identifier.strip()
    connection = get_connection()
    try:
        row = connection.execute("""
            SELECT admin_id, username, password_hash
            FROM admins
            WHERE is_active = 1
              AND (username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE)
        """, (identifier, identifier)).fetchone()

        if row is None or not _verify_password(password, row[2]):
            return None

        connection.execute(
            "UPDATE admins SET last_login = CURRENT_TIMESTAMP WHERE admin_id = ?",
            (row[0],),
        )
        connection.commit()
        return row[0], row[1]
    finally:
        connection.close()


def is_admin_active(admin_id):
    connection = get_connection()
    try:
        return connection.execute(
            "SELECT EXISTS(SELECT 1 FROM admins WHERE admin_id = ? AND is_active = 1)",
            (admin_id,),
        ).fetchone()[0] == 1
    finally:
        connection.close()
