"""Password hashing and verification for CampusGig customer/provider accounts."""

import hashlib
import hmac
import secrets

HASH_NAME = "sha256"
HASH_ITERATIONS = 600_000
SALT_BYTES = 16


def hash_password(password):
    """Return a salted PBKDF2 hash suitable for storing in the existing password column."""
    salt = secrets.token_bytes(SALT_BYTES)
    derived_key = hashlib.pbkdf2_hmac(
        HASH_NAME,
        password.encode("utf-8"),
        salt,
        HASH_ITERATIONS,
    )
    return f"pbkdf2_{HASH_NAME}${HASH_ITERATIONS}${salt.hex()}${derived_key.hex()}"


def verify_password(password, stored_hash):
    """Return (matches, should_upgrade); legacy unsalted SHA-256 is accepted once."""
    if not isinstance(stored_hash, str):
        return False, False

    if stored_hash.startswith(f"pbkdf2_{HASH_NAME}$"):
        try:
            algorithm, iterations_text, salt_text, expected_text = stored_hash.split("$")
            if algorithm != f"pbkdf2_{HASH_NAME}":
                return False, False
            iterations = int(iterations_text)
            if not 100_000 <= iterations <= 2_000_000:
                return False, False
            salt = bytes.fromhex(salt_text)
            expected = bytes.fromhex(expected_text)
            actual = hashlib.pbkdf2_hmac(
                HASH_NAME, password.encode("utf-8"), salt, iterations
            )
            return hmac.compare_digest(actual, expected), False
        except (TypeError, ValueError):
            return False, False

    # Earlier CampusGig versions stored a plain SHA-256 digest. Validate it
    # without timing-sensitive string comparison, then upgrade after login.
    try:
        legacy_digest = bytes.fromhex(stored_hash)
    except ValueError:
        return False, False
    if len(legacy_digest) != hashlib.sha256().digest_size:
        return False, False
    expected = hashlib.sha256(password.encode("utf-8")).digest()
    matches = hmac.compare_digest(expected, legacy_digest)
    return matches, matches
