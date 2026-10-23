"""Add the CampusGig sample providers, customers, services, and requests."""

from database import create_tables, get_connection
from user_auth import hash_password


DEMO_PASSWORD = "campusgig"

PROVIDERS = [
    ("akash_mali", "Akash Mali", ("Web Development", "Python")),
    ("omkar_patil", "Omkar Patil", ("Graphic Design", "PPT")),
    ("prathmesh_k", "Prathmesh Kumbhar", ("Video Editing", "Reels")),
    ("harsh_jadhav", "Harsh Jadhav", ("Content Writing", "Documentation")),
    ("ashish_more", "Ashish More", ("Java", "Database", "Programming")),
]

BUSINESS_CUSTOMERS = [
    ("shreeganesh_cafe", "Shree Ganesh Cafe"),
    ("citybookstore", "City Book Store"),
    ("omsai_mobile", "Om Sai Mobile Shop"),
    ("royalfitness", "Royal Fitness Gym"),
    ("newstar_clothing", "New Star Clothing"),
    ("patil_bakery", "Patil Bakery"),
    ("freshbite", "Fresh Bite Restaurant"),
    ("vision_computer", "Vision Computer Academy"),
]

STUDENT_CUSTOMERS = [
    ("soham_patil", "Soham Patil", "College Project"),
    ("abhay_sanap", "Abhay Sanap", "PPT / Presentation"),
    ("pranav_jadhav", "Pranav Jadhav", "Project Documentation"),
    ("paras_mali", "Paras Mali", "Project Video"),
    ("aditya_chavare", "Aditya Chavare", "Website / Portfolio"),
]
DEMO_ACCOUNT_USERNAMES = (
    "provider_demo", "customer_demo",
    *(row[0] for row in PROVIDERS),
    *(row[0] for row in BUSINESS_CUSTOMERS),
    *(row[0] for row in STUDENT_CUSTOMERS),
)

SERVICES = [
    ("Website Development", "akash_mali", "Web Development", 800, 5),
    ("Python Project Development", "akash_mali", "Programming", 600, 4),
    ("PPT Presentation Design", "omkar_patil", "Design", 250, 2),
    ("Poster Design", "omkar_patil", "Graphic Design", 200, 1),
    ("Video Editing", "prathmesh_k", "Video Editing", 500, 3),
    ("Instagram Reel Editing", "prathmesh_k", "Video Editing", 300, 2),
    ("Resume Design", "omkar_patil", "Design", 150, 1),
    ("Portfolio Website", "akash_mali", "Web Development", 1000, 7),
    ("College/Business Promotional Video", "prathmesh_k", "Video Editing", 400, 3),
    ("Java Project & Bug Fixing", "ashish_more", "Programming", 500, 3),
]

# The app's valid ongoing value is Accepted; this represents the user's
# "In Progress" rows without changing the existing database constraint.
REQUESTS = [
    ("shreeganesh_cafe", "Instagram Reel Editing", "Pending", "Business", "Instagram Reel Editing"),
    ("citybookstore", "Poster Design", "Accepted", "Business", "Poster Design"),
    ("omsai_mobile", "Website Development", "Accepted", "Business", "Website Development"),
    ("royalfitness", "College/Business Promotional Video", "Pending", "Business", "Promotional Video"),
    ("newstar_clothing", "Instagram Reel Editing", "Accepted", "Business", "Instagram Reel Editing"),
    ("patil_bakery", "Poster Design", "Accepted", "Business", "Poster Design"),
    ("freshbite", "Website Development", "Pending", "Business", "Website Development"),
    ("vision_computer", "Java Project & Bug Fixing", "Accepted", "Business", "Java Project & Bug Fixing"),
    ("soham_patil", "Python Project Development", "Pending", "Student", "Python Project Development"),
    ("abhay_sanap", "PPT Presentation Design", "Accepted", "Student", "PPT Presentation Design"),
    # Student Request #3 is omitted as requested: there is no matching service.
    ("paras_mali", "College/Business Promotional Video", "Pending", "Student", "College Project Video"),
    ("aditya_chavare", "Portfolio Website", "Accepted", "Student", "Portfolio Website"),
]


def _ensure_demo_user(cursor, username, full_name, user_type, college, bio):
    row = cursor.execute(
        "SELECT user_id, user_type FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row:
        user_id, saved_type = row
        if saved_type != user_type:
            raise ValueError(f"Existing account {username!r} has a different role.")
        return user_id, False

    email = f"{username}@campusgig.demo"
    email_owner = cursor.execute(
        "SELECT username FROM users WHERE email = ?", (email,)
    ).fetchone()
    if email_owner:
        raise ValueError(f"Demo email {email!r} is already used by {email_owner[0]!r}.")

    cursor.execute(
        "INSERT INTO users (username, email, password, user_type) VALUES (?, ?, ?, ?)",
        (username, email, hash_password(DEMO_PASSWORD), user_type),
    )
    user_id = cursor.lastrowid
    cursor.execute(
        "INSERT OR IGNORE INTO profiles (user_id, full_name, college, bio) VALUES (?, ?, ?, ?)",
        (user_id, full_name, college, bio),
    )
    return user_id, True


def seed_demo_dataset():
    """Idempotently add the requested demo data without replacing existing rows."""
    create_tables()
    connection = get_connection()
    counts = {"users": 0, "services": 0, "requests": 0}
    try:
        cursor = connection.cursor()
        user_ids = {}
        provider_skills = {}

        for username, full_name, skills in PROVIDERS:
            user_id, created = _ensure_demo_user(
                cursor,
                username,
                full_name,
                "Provider",
                "Campus University",
                "Demo service provider account.",
            )
            user_ids[username] = user_id
            counts["users"] += int(created)
            provider_skills[username] = skills

        for username, business_name in BUSINESS_CUSTOMERS:
            user_id, created = _ensure_demo_user(
                cursor,
                username,
                business_name,
                "Customer",
                "Local Business",
                "Demo local business customer account.",
            )
            user_ids[username] = user_id
            counts["users"] += int(created)

        for username, full_name, purpose in STUDENT_CUSTOMERS:
            user_id, created = _ensure_demo_user(
                cursor,
                username,
                full_name,
                "Customer",
                "Campus University",
                f"Demo student account. Purpose: {purpose}.",
            )
            user_ids[username] = user_id
            counts["users"] += int(created)

        # Keep the shared demo login password consistent across every demo account.
        for username in DEMO_ACCOUNT_USERNAMES:
            cursor.execute(
                "UPDATE users SET password = ? WHERE username = ?",
                (hash_password(DEMO_PASSWORD), username),
            )

        for username, skills in provider_skills.items():
            for skill in skills:
                exists = cursor.execute(
                    "SELECT 1 FROM skills WHERE user_id = ? AND skill_name = ?",
                    (user_ids[username], skill),
                ).fetchone()
                if not exists:
                    cursor.execute(
                        "INSERT INTO skills (user_id, skill_name, expertise_level) VALUES (?, ?, ?)",
                        (user_ids[username], skill, "Demo"),
                    )

        service_ids = {}
        for title, provider_username, category, price, delivery_days in SERVICES:
            provider_id = user_ids[provider_username]
            row = cursor.execute(
                "SELECT service_id FROM services WHERE provider_id = ? AND title = ?",
                (provider_id, title),
            ).fetchone()
            if row:
                service_id = row[0]
            else:
                description = (
                    "CampusGig demo service listing. "
                    f"Estimated delivery: {delivery_days} day(s)."
                )
                cursor.execute(
                    """INSERT INTO services
                       (provider_id, title, description, category, price, status)
                       VALUES (?, ?, ?, ?, ?, 'Available')""",
                    (provider_id, title, description, category, price),
                )
                service_id = cursor.lastrowid
                counts["services"] += 1
            service_ids[title] = service_id

        for index, (customer_username, service_title, status, customer_group, request_text) in enumerate(REQUESTS, 1):
            customer_id = user_ids[customer_username]
            service_id = service_ids[service_title]
            provider_id = cursor.execute(
                "SELECT provider_id FROM services WHERE service_id = ?", (service_id,)
            ).fetchone()[0]
            message = f"Demo {customer_group.lower()} request #{index}: {request_text}."
            existing = cursor.execute(
                """SELECT 1 FROM service_requests
                   WHERE customer_id = ? AND service_id = ? AND message = ?""",
                (customer_id, service_id, message),
            ).fetchone()
            if not existing:
                cursor.execute(
                    """INSERT INTO service_requests
                       (service_id, customer_id, provider_id, message, request_status)
                       VALUES (?, ?, ?, ?, ?)""",
                    (service_id, customer_id, provider_id, message, status),
                )
                counts["requests"] += 1

        connection.commit()
        return counts
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


if __name__ == "__main__":
    print("Added demo records:", seed_demo_dataset())
    print("New demo accounts use the password:", DEMO_PASSWORD)