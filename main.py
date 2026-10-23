import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import sqlite3
import shutil
import uuid
import csv
from pathlib import Path
from datetime import datetime

from database import create_tables, create_database_backup, get_connection
from admin_auth import (
    admin_exists,
    authenticate_admin,
    create_first_admin,
    is_admin_active,
)
from user_auth import hash_password, verify_password


create_tables()

BG_COLOR = "#F5F7FA"
PRIMARY_COLOR = "#2563EB"
TEXT_COLOR = "#1E293B"
current_admin = None
SUBMISSIONS_DIR = Path(__file__).resolve().parent / "submissions"
ALLOWED_SUBMISSION_EXTENSIONS = {".pdf", ".doc", ".docx", ".ppt", ".pptx", ".txt", ".zip", ".png", ".jpg", ".jpeg"}
MAX_SUBMISSION_SIZE = 25 * 1024 * 1024


def clear_window():
    for widget in app.winfo_children():
        widget.destroy()


def _record_activity(actor_type, actor_id, action, description, related_type=None, related_id=None):
    """Write an audit entry without interrupting the main user action if logging fails."""
    connection = None
    try:
        connection = get_connection()
        connection.execute("""
            INSERT INTO activity_logs
                (actor_type, actor_id, action, description, related_type, related_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (actor_type, actor_id, action, description, related_type, related_id))
        connection.commit()
    except sqlite3.Error as error:
        print(f"Activity log could not be written: {error}")
    finally:
        if connection is not None:
            connection.close()


def register_user():
    full_name = name_entry.get().strip()
    username = username_entry.get().strip()
    email = email_entry.get().strip()
    password = password_entry.get()
    confirm_password = confirm_password_entry.get()
    user_type = user_type_var.get()

    if not all([full_name, username, email, password, confirm_password]):
        messagebox.showerror("Missing details", "Please fill in every field.")
        return

    if "@" not in email or "." not in email:
        messagebox.showerror("Invalid email", "Enter a valid email address.")
        return

    if len(password) < 6:
        messagebox.showerror(
            "Weak password",
            "Password must contain at least 6 characters."
        )
        return

    if password != confirm_password:
        messagebox.showerror(
            "Password mismatch",
            "Password and confirm password must match."
        )
        return

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO users (username, email, password, user_type)
            VALUES (?, ?, ?, ?)
        """, (username, email, hash_password(password), user_type))

        user_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO profiles (user_id, full_name)
            VALUES (?, ?)
        """, (user_id, full_name))

        connection.commit()
        connection.close()

        _record_activity("User", user_id, "ACCOUNT_REGISTERED", f"Created a {user_type.lower()} account.", "User", user_id)

        messagebox.showinfo(
            "Registration successful",
            "Your CampusGig account has been created. Please log in."
        )
        show_login_screen()

    except sqlite3.IntegrityError:
        messagebox.showerror(
            "Account already exists",
            "That username or email address is already registered."
        )


def login_user():
    username = login_username_entry.get().strip()
    password = login_password_entry.get()

    if not username or not password:
        messagebox.showerror("Missing details", "Enter your username and password.")
        return

    connection = get_connection()
    try:
        row = connection.execute("""
            SELECT user_id, username, user_type, password
            FROM users
            WHERE username = ? AND account_status = 'Active'
        """, (username,)).fetchone()
        user = None
        password_was_upgraded = False
        if row:
            password_matches, needs_upgrade = verify_password(password, row[3])
            if password_matches:
                user = row[:3]
                if needs_upgrade:
                    upgraded_hash = hash_password(password)
                    connection.execute(
                        "UPDATE users SET password = ? WHERE user_id = ? AND password = ?",
                        (upgraded_hash, row[0], row[3]),
                    )
                    password_was_upgraded = connection.execute("SELECT changes()").fetchone()[0] == 1
                    if password_was_upgraded:
                        connection.commit()
    finally:
        connection.close()

    if user:
        if password_was_upgraded:
            _record_activity("User", user[0], "PASSWORD_HASH_UPGRADED", "Upgraded password storage after successful login.", "User", user[0])
        _record_activity("User", user[0], "USER_LOGIN", "Signed in successfully.", "User", user[0])
        show_logged_in_screen(user)
    else:
        messagebox.showerror(
            "Login failed",
            "Incorrect username or password."
        )


def show_login_screen():
    global login_username_entry, login_password_entry

    clear_window()

    tk.Label(
        app,
        text="CampusGig",
        font=("Segoe UI", 28, "bold"),
        bg=BG_COLOR,
        fg=PRIMARY_COLOR
    ).pack(pady=(70, 5))

    tk.Label(
        app,
        text="Student Skill Marketplace",
        font=("Segoe UI", 13),
        bg=BG_COLOR,
        fg="#64748B"
    ).pack(pady=(0, 25))

    card = tk.Frame(app, bg="white", padx=35, pady=30)
    card.pack()

    tk.Label(
        card,
        text="Welcome Back",
        font=("Segoe UI", 18, "bold"),
        bg="white",
        fg=TEXT_COLOR
    ).grid(row=0, column=0, columnspan=2, pady=(0, 20))

    tk.Label(card, text="Username", bg="white").grid(
        row=1, column=0, sticky="w", pady=5
    )
    login_username_entry = tk.Entry(card, width=30, font=("Segoe UI", 11))
    login_username_entry.grid(row=2, column=0, pady=(0, 12))

    tk.Label(card, text="Password", bg="white").grid(
        row=3, column=0, sticky="w", pady=5
    )
    login_password_entry = tk.Entry(card, width=30, show="*", font=("Segoe UI", 11))
    login_password_entry.grid(row=4, column=0, pady=(0, 18))

    tk.Button(
        card,
        text="Login",
        command=login_user,
        bg=PRIMARY_COLOR,
        fg="white",
        font=("Segoe UI", 11, "bold"),
        width=25,
        relief="flat",
        pady=8
    ).grid(row=5, column=0)

    tk.Button(
        card,
        text="New student? Create an account",
        command=show_register_screen,
        bg="white",
        fg=PRIMARY_COLOR,
        relief="flat",
        font=("Segoe UI", 10, "underline")
    ).grid(row=6, column=0, pady=(15, 0))

    tk.Button(
        card,
        text="Administrator Login",
        command=show_admin_login_screen,
        bg="white",
        fg=TEXT_COLOR,
        relief="flat",
        font=("Segoe UI", 10, "bold")
    ).grid(row=7, column=0, pady=(10, 0))


def show_admin_login_screen():
    global admin_identifier_entry, admin_password_entry
    clear_window()

    tk.Label(
        app,
        text="CampusGig Administrator",
        font=("Segoe UI", 25, "bold"),
        bg=BG_COLOR,
        fg=PRIMARY_COLOR
    ).pack(pady=(65, 8))
    tk.Label(
        app,
        text="Restricted access for platform administrators",
        font=("Segoe UI", 12),
        bg=BG_COLOR,
        fg="#64748B"
    ).pack(pady=(0, 20))

    card = tk.Frame(app, bg="white", padx=35, pady=30)
    card.pack()
    tk.Label(
        card,
        text="Admin Login",
        font=("Segoe UI", 18, "bold"),
        bg="white",
        fg=TEXT_COLOR
    ).grid(row=0, column=0, pady=(0, 18))

    tk.Label(card, text="Admin username or email", bg="white").grid(
        row=1, column=0, sticky="w", pady=5
    )
    admin_identifier_entry = tk.Entry(card, width=34, font=("Segoe UI", 11))
    admin_identifier_entry.grid(row=2, column=0, pady=(0, 12))

    tk.Label(card, text="Admin password", bg="white").grid(
        row=3, column=0, sticky="w", pady=5
    )
    admin_password_entry = tk.Entry(card, width=34, show="*", font=("Segoe UI", 11))
    admin_password_entry.grid(row=4, column=0, pady=(0, 18))

    tk.Button(
        card,
        text="Admin Login",
        command=admin_login,
        bg=PRIMARY_COLOR,
        fg="white",
        font=("Segoe UI", 11, "bold"),
        width=27,
        relief="flat",
        pady=8
    ).grid(row=5, column=0)

    if not admin_exists():
        tk.Button(
            card,
            text="First-time setup: Create Administrator",
            command=show_admin_setup_screen,
            bg="white",
            fg=PRIMARY_COLOR,
            relief="flat",
            font=("Segoe UI", 10, "underline")
        ).grid(row=6, column=0, pady=(13, 0))

    tk.Button(
        card,
        text="Back to student login",
        command=show_login_screen,
        bg="white",
        fg=TEXT_COLOR,
        relief="flat",
        font=("Segoe UI", 10)
    ).grid(row=7, column=0, pady=(12, 0))


def show_admin_setup_screen():
    global admin_setup_username_entry, admin_setup_email_entry
    global admin_setup_password_entry, admin_setup_confirm_entry
    clear_window()

    tk.Label(
        app,
        text="Set Up the First Administrator",
        font=("Segoe UI", 23, "bold"),
        bg=BG_COLOR,
        fg=PRIMARY_COLOR
    ).pack(pady=(35, 8))
    tk.Label(
        app,
        text="This one-time setup is disabled after the first admin is created.",
        font=("Segoe UI", 11),
        bg=BG_COLOR,
        fg="#64748B"
    ).pack(pady=(0, 18))

    card = tk.Frame(app, bg="white", padx=35, pady=22)
    card.pack()
    fields = [
        ("Admin username", "username"),
        ("Admin email", "email"),
        ("Password (minimum 12 characters)", "password"),
        ("Confirm password", "confirm"),
    ]
    entries = {}
    for row, (label, key) in enumerate(fields):
        tk.Label(card, text=label, bg="white").grid(
            row=row * 2, column=0, sticky="w", pady=4
        )
        entry = tk.Entry(
            card,
            width=38,
            show="*" if key in ("password", "confirm") else "",
            font=("Segoe UI", 10),
        )
        entry.grid(row=row * 2 + 1, column=0, pady=(0, 7))
        entries[key] = entry

    admin_setup_username_entry = entries["username"]
    admin_setup_email_entry = entries["email"]
    admin_setup_password_entry = entries["password"]
    admin_setup_confirm_entry = entries["confirm"]

    tk.Button(
        card,
        text="Create First Admin",
        command=create_initial_admin,
        bg=PRIMARY_COLOR,
        fg="white",
        font=("Segoe UI", 10, "bold"),
        width=28,
        relief="flat",
        pady=8
    ).grid(row=8, column=0, pady=(10, 0))
    tk.Button(
        card,
        text="Cancel",
        command=show_admin_login_screen,
        bg="white",
        fg=TEXT_COLOR,
        relief="flat",
        font=("Segoe UI", 10)
    ).grid(row=9, column=0, pady=(8, 0))


def create_initial_admin():
    username = admin_setup_username_entry.get().strip()
    email = admin_setup_email_entry.get().strip()
    password = admin_setup_password_entry.get()
    confirm_password = admin_setup_confirm_entry.get()

    if not all([username, email, password, confirm_password]):
        messagebox.showerror("Missing details", "Complete every field.")
        return
    if password != confirm_password:
        messagebox.showerror("Password mismatch", "The passwords must match.")
        return

    try:
        create_first_admin(username, email, password)
    except ValueError as error:
        messagebox.showerror("Admin setup", str(error))
        return
    except sqlite3.IntegrityError:
        messagebox.showerror(
            "Admin already exists",
            "An administrator account has already been created."
        )
        return

    messagebox.showinfo(
        "Admin created",
        "The first administrator is ready. You can now log in."
    )
    show_admin_login_screen()


def admin_login():
    global current_admin
    identifier = admin_identifier_entry.get().strip()
    password = admin_password_entry.get()
    if not identifier or not password:
        messagebox.showerror("Missing details", "Enter your admin username/email and password.")
        return

    current_admin = authenticate_admin(identifier, password)
    if current_admin is None:
        messagebox.showerror("Admin login failed", "Invalid admin credentials or inactive account.")
        return
    _record_activity("Admin", current_admin[0], "ADMIN_LOGIN", "Admin signed in successfully.", "Admin", current_admin[0])
    show_admin_home()


def get_admin_dashboard_data():
    """Read platform-wide summary counts and the latest records for the admin."""
    connection = get_connection()
    cursor = connection.cursor()

    data = {}
    count_queries = {
        "total_users": "SELECT COUNT(*) FROM users",
        "customers": "SELECT COUNT(*) FROM users WHERE user_type = 'Customer'",
        "providers": "SELECT COUNT(*) FROM users WHERE user_type = 'Provider'",
        "active_users": "SELECT COUNT(*) FROM users WHERE account_status = 'Active'",
        "total_services": "SELECT COUNT(*) FROM services",
        "available_services": "SELECT COUNT(*) FROM services WHERE status = 'Available'",
        "pending_requests": "SELECT COUNT(*) FROM service_requests WHERE request_status = 'Pending'",
        "ongoing_requests": "SELECT COUNT(*) FROM service_requests WHERE request_status = 'Accepted'",
        "rejected_requests": "SELECT COUNT(*) FROM service_requests WHERE request_status = 'Rejected'",
        "completed_services": "SELECT COUNT(*) FROM service_requests WHERE request_status = 'Completed'",
        "pending_payments": "SELECT COUNT(*) FROM payments WHERE payment_status = 'Pending'",
        "completed_payments": "SELECT COUNT(*) FROM payments WHERE payment_status = 'Completed'",
        "pending_payouts": "SELECT COUNT(*) FROM provider_payouts WHERE payout_status IN ('Pending', 'Approved')",
        "completed_payouts": "SELECT COUNT(*) FROM provider_payouts WHERE payout_status = 'Processed'",
        "total_transactions": "SELECT COUNT(*) FROM payments",
    }
    for key, query in count_queries.items():
        data[key] = cursor.execute(query).fetchone()[0]

    data["commission_earned"] = cursor.execute("""
        SELECT COALESCE(ROUND(SUM(commission_amount), 2), 0)
        FROM payments WHERE payment_status = 'Completed'
    """).fetchone()[0]
    data["gross_completed_value"] = cursor.execute("""
        SELECT COALESCE(ROUND(SUM(gross_amount), 2), 0)
        FROM payments WHERE payment_status = 'Completed'
    """).fetchone()[0]
    average_rating, review_count = cursor.execute(
        "SELECT ROUND(AVG(rating), 1), COUNT(*) FROM reviews WHERE moderation_status = 'Visible'"
    ).fetchone()
    data["average_rating"] = average_rating or 0
    data["review_count"] = review_count

    data["recent_registrations"] = cursor.execute("""
        SELECT users.username, users.user_type, users.created_at
        FROM users ORDER BY users.user_id DESC LIMIT 5
    """).fetchall()
    data["recent_requests"] = cursor.execute("""
        SELECT services.title, customer.username, provider.username,
               service_requests.request_status, service_requests.requested_at
        FROM service_requests
        JOIN services ON service_requests.service_id = services.service_id
        JOIN users AS customer ON service_requests.customer_id = customer.user_id
        JOIN users AS provider ON service_requests.provider_id = provider.user_id
        ORDER BY service_requests.request_id DESC LIMIT 5
    """).fetchall()
    data["recent_completed"] = cursor.execute("""
        SELECT services.title, provider.username, customer.username,
               service_requests.requested_at
        FROM service_requests
        JOIN services ON service_requests.service_id = services.service_id
        JOIN users AS customer ON service_requests.customer_id = customer.user_id
        JOIN users AS provider ON service_requests.provider_id = provider.user_id
        WHERE service_requests.request_status = 'Completed'
        ORDER BY service_requests.request_id DESC LIMIT 5
    """).fetchall()
    data["recent_submissions"] = cursor.execute("""
        SELECT project_submissions.file_name, users.username,
               project_submissions.submission_status, project_submissions.uploaded_at
        FROM project_submissions
        JOIN users ON project_submissions.provider_id = users.user_id
        ORDER BY project_submissions.submission_id DESC LIMIT 5
    """).fetchall()
    data["recent_payments"] = cursor.execute("""
        SELECT payments.transaction_reference, customer.username, provider.username,
               payments.gross_amount, payments.payment_status, payments.created_at
        FROM payments
        JOIN users AS customer ON payments.customer_id = customer.user_id
        JOIN users AS provider ON payments.provider_id = provider.user_id
        ORDER BY payments.payment_id DESC LIMIT 5
    """).fetchall()
    data["recent_activity"] = cursor.execute("""
        SELECT actor_type, action, description, created_at
        FROM activity_logs ORDER BY activity_id DESC LIMIT 5
    """).fetchall()
    data["recent_reviews"] = cursor.execute("""
        SELECT reviews.rating, reviewer.username, provider.username,
               reviews.review_text, reviews.created_at
        FROM reviews
        JOIN users AS reviewer ON reviews.reviewer_id = reviewer.user_id
        JOIN users AS provider ON reviews.provider_id = provider.user_id
        ORDER BY reviews.review_id DESC LIMIT 5
    """).fetchall()
    connection.close()
    return data


def _admin_session_is_valid():
    global current_admin
    if current_admin is not None and is_admin_active(current_admin[0]):
        return True
    current_admin = None
    messagebox.showerror("Access denied", "Please sign in with an active admin account.")
    show_admin_login_screen()
    return False


def _add_admin_recent_panel(parent, title, lines, row, column):
    panel = tk.Frame(parent, bg="white", padx=14, pady=12)
    panel.grid(row=row, column=column, sticky="nsew", padx=6, pady=6)
    destinations = {
        "Recent registrations": show_admin_users_screen,
        "Recent service requests": show_admin_requests_screen,
        "Recently completed requests": show_admin_requests_screen,
        "Recent work submissions": show_admin_submissions_screen,
        "Recent payments": show_admin_payments_screen,
        "Recent activity": show_admin_activity_screen,
        "Recent ratings and reviews": show_admin_reviews_screen,
    }
    command = destinations.get(title)
    heading = tk.Frame(panel, bg="white")
    heading.pack(fill="x", pady=(0, 7))
    tk.Label(
        heading,
        text=title,
        font=("Segoe UI", 11, "bold"),
        bg="white",
        fg=TEXT_COLOR
    ).pack(side="left", anchor="w")
    if command:
        tk.Button(
            heading,
            text="View all →",
            command=command,
            font=("Segoe UI", 8, "bold"),
            bg="white",
            fg=PRIMARY_COLOR,
            activebackground="white",
            activeforeground="#1D4ED8",
            relief="flat",
            cursor="hand2",
            padx=4,
            pady=0,
        ).pack(side="right")

    if not lines:
        tk.Label(
            panel,
            text="No records yet.",
            font=("Segoe UI", 9),
            bg="white",
            fg="#64748B"
        ).pack(anchor="w")
        return

    for line in lines:
        tk.Label(
            panel,
            text=line,
            font=("Segoe UI", 9),
            bg="white",
            fg="#64748B",
            wraplength=285,
            justify="left"
        ).pack(anchor="w", pady=2)

def show_admin_placeholder(section_name):
    if not _admin_session_is_valid():
        return
    messagebox.showinfo(
        section_name,
        f"{section_name} management will be added in a later implementation step."
    )


def show_admin_home():
    """Display the platform-wide admin dashboard for an active admin session."""
    global current_admin
    if not _admin_session_is_valid():
        return

    data = get_admin_dashboard_data()
    clear_window()

    shell = tk.Frame(app, bg=BG_COLOR)
    shell.pack(fill="both", expand=True)

    sidebar = tk.Frame(shell, bg="#0F172A", width=185)
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)
    tk.Label(
        sidebar,
        text="CampusGig\nADMIN",
        font=("Segoe UI", 17, "bold"),
        bg="#0F172A",
        fg="white",
        justify="left"
    ).pack(anchor="w", padx=18, pady=(22, 8))
    tk.Label(
        sidebar,
        text=current_admin[1],
        font=("Segoe UI", 9),
        bg="#0F172A",
        fg="#CBD5E1"
    ).pack(anchor="w", padx=18, pady=(0, 16))

    navigation = [
        "Dashboard", "Users", "Services", "Requests", "Submissions",
        "Payments", "Payouts", "Reviews", "Activity Log", "Reports", "Settings"
    ]
    for section in navigation:
        if section == "Dashboard":
            command = show_admin_home
        elif section == "Users":
            command = show_admin_users_screen
        elif section == "Services":
            command = show_admin_services_screen
        elif section == "Requests":
            command = show_admin_requests_screen
        elif section == "Submissions":
            command = show_admin_submissions_screen
        elif section == "Reviews":
            command = show_admin_reviews_screen
        elif section == "Activity Log":
            command = show_admin_activity_screen
        elif section == "Reports":
            command = show_admin_reports_screen
        elif section == "Settings":
            command = show_admin_settings_screen
        elif section == "Payments":
            command = show_admin_payments_screen
        elif section == "Payouts":
            command = show_admin_payouts_screen
        else:
            command = lambda name=section: show_admin_placeholder(name)
        tk.Button(
            sidebar,
            text=section,
            command=command,
            anchor="w",
            bg="#1E293B" if section == "Dashboard" else "#0F172A",
            fg="white",
            activebackground="#334155",
            activeforeground="white",
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            padx=18,
            pady=7
        ).pack(fill="x")

    tk.Button(
        sidebar,
        text="Admin Logout",
        command=admin_logout,
        anchor="w",
        bg="#7F1D1D",
        fg="white",
        activebackground="#991B1B",
        activeforeground="white",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=18,
        pady=8
    ).pack(side="bottom", fill="x", pady=12)

    main_area = tk.Frame(shell, bg=BG_COLOR)
    main_area.pack(side="left", fill="both", expand=True)
    header = tk.Frame(main_area, bg="white", padx=20, pady=12)
    header.pack(fill="x")
    tk.Label(
        header,
        text="Platform Dashboard",
        font=("Segoe UI", 19, "bold"),
        bg="white",
        fg=TEXT_COLOR
    ).pack(anchor="w")
    tk.Label(
        header,
        text="Current overview of CampusGig activity and transactions",
        font=("Segoe UI", 9),
        bg="white",
        fg="#64748B"
    ).pack(anchor="w", pady=(3, 0))

    dashboard_area = tk.Frame(main_area, bg=BG_COLOR)
    dashboard_area.pack(fill="both", expand=True)
    canvas = tk.Canvas(dashboard_area, bg=BG_COLOR, highlightthickness=0)
    scrollbar = ttk.Scrollbar(dashboard_area, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)
    dashboard = tk.Frame(canvas, bg=BG_COLOR, padx=12, pady=12)
    dashboard_window = canvas.create_window((0, 0), window=dashboard, anchor="nw")
    dashboard.bind(
        "<Configure>",
        lambda event: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    canvas.bind(
        "<Configure>",
        lambda event: canvas.itemconfigure(dashboard_window, width=event.width)
    )

    metrics = [
        ("Registered users", data["total_users"], PRIMARY_COLOR),
        ("Customers", data["customers"], PRIMARY_COLOR),
        ("Providers", data["providers"], PRIMARY_COLOR),
        ("Active users", data["active_users"], "#16A34A"),
        ("All services", data["total_services"], PRIMARY_COLOR),
        ("Available services", data["available_services"], "#16A34A"),
        ("Pending requests", data["pending_requests"], "#F59E0B"),
        ("Accepted / ongoing", data["ongoing_requests"], "#2563EB"),
        ("Rejected requests", data["rejected_requests"], "#DC2626"),
        ("Completed services", data["completed_services"], "#16A34A"),
        ("Pending payments", data["pending_payments"], "#F59E0B"),
        ("Completed payments", data["completed_payments"], "#16A34A"),
        ("Pending provider payouts", data["pending_payouts"], "#F59E0B"),
        ("Processed payouts", data["completed_payouts"], "#16A34A"),
        ("Total transactions", data["total_transactions"], PRIMARY_COLOR),
        ("Average rating", f"{data['average_rating']} ★ ({data['review_count']})", "#F59E0B"),
        ("Completed gross value", f"₹{data['gross_completed_value']:.2f}", PRIMARY_COLOR),
        ("Commission earned", f"₹{data['commission_earned']:.2f}", "#16A34A"),
    ]
    for index, (title, value, color) in enumerate(metrics):
        row, column = divmod(index, 3)
        card = tk.Frame(dashboard, bg="white", padx=12, pady=10, height=68)
        card.grid(row=row, column=column, sticky="nsew", padx=5, pady=5)
        card.grid_propagate(False)
        tk.Label(
            card,
            text=title,
            font=("Segoe UI", 8),
            bg="white",
            fg="#64748B",
            wraplength=175,
            justify="left"
        ).pack(anchor="w")
        tk.Label(
            card,
            text=str(value),
            font=("Segoe UI", 16, "bold"),
            bg="white",
            fg=color
        ).pack(anchor="w", pady=(3, 0))
    for column in range(3):
        dashboard.grid_columnconfigure(column, weight=1, uniform="admin_metrics")

    def format_recent(rows, formatter):
        return [formatter(row) for row in rows]

    panels = [
        (
            "Recent registrations",
            format_recent(data["recent_registrations"], lambda r: f"{r[0]} · {r[1]} · {r[2]}"),
        ),
        (
            "Recent service requests",
            format_recent(data["recent_requests"], lambda r: f"{r[0]} · {r[1]} → {r[2]} · {r[3]}"),
        ),
        (
            "Recently completed requests",
            format_recent(data["recent_completed"], lambda r: f"{r[0]} · Provider {r[1]} · Customer {r[2]}"),
        ),
        (
            "Recent work submissions",
            format_recent(data["recent_submissions"], lambda r: f"{r[0]} · {r[1]} · {r[2]} · {r[3]}"),
        ),
        (
            "Recent payments",
            format_recent(data["recent_payments"], lambda r: f"{r[0] or 'No reference'} · ₹{r[3]:.2f} · {r[4]}"),
        ),
        (
            "Recent activity",
            format_recent(data["recent_activity"], lambda r: f"{r[0]} · {r[1]} · {r[2] or ''} · {r[3]}"),
        ),
        (
            "Recent ratings and reviews",
            format_recent(data["recent_reviews"], lambda r: f"{r[0]} ★ · {r[1]} → {r[2]} · {r[3] or 'No comment'}"),
        ),
    ]
    panel_start_row = (len(metrics) + 2) // 3
    for index, (title, lines) in enumerate(panels):
        row, column = divmod(index, 2)
        _add_admin_recent_panel(
            dashboard,
            title,
            lines,
            panel_start_row + row,
            column,
        )
    dashboard.grid_columnconfigure(0, weight=1, uniform="admin_panels")
    dashboard.grid_columnconfigure(1, weight=1, uniform="admin_panels")


def admin_logout():
    global current_admin
    if current_admin is not None:
        _record_activity("Admin", current_admin[0], "ADMIN_LOGOUT", "Admin signed out.", "Admin", current_admin[0])
    current_admin = None
    show_login_screen()


def logout_user(user):
    _record_activity("User", user[0], "USER_LOGOUT", "Signed out.", "User", user[0])
    show_login_screen()


def show_register_screen():
    global name_entry, username_entry, email_entry
    global password_entry, confirm_password_entry, user_type_var

    clear_window()

    tk.Label(
        app,
        text="Create your CampusGig account",
        font=("Segoe UI", 24, "bold"),
        bg=BG_COLOR,
        fg=PRIMARY_COLOR
    ).pack(pady=(35, 5))

    tk.Label(
        app,
        text="Join the student skill marketplace",
        font=("Segoe UI", 12),
        bg=BG_COLOR,
        fg="#64748B"
    ).pack(pady=(0, 18))

    card = tk.Frame(app, bg="white", padx=35, pady=25)
    card.pack()

    tk.Label(card, text="Full name", bg="white").grid(
        row=0, column=0, sticky="w", pady=4
    )
    name_entry = tk.Entry(card, width=35, font=("Segoe UI", 10))
    name_entry.grid(row=1, column=0, pady=(0, 8))

    tk.Label(card, text="Username", bg="white").grid(
        row=2, column=0, sticky="w", pady=4
    )
    username_entry = tk.Entry(card, width=35, font=("Segoe UI", 10))
    username_entry.grid(row=3, column=0, pady=(0, 8))

    tk.Label(card, text="Email address", bg="white").grid(
        row=4, column=0, sticky="w", pady=4
    )
    email_entry = tk.Entry(card, width=35, font=("Segoe UI", 10))
    email_entry.grid(row=5, column=0, pady=(0, 8))

    tk.Label(card, text="Password (minimum 6 characters)", bg="white").grid(
        row=6, column=0, sticky="w", pady=4
    )
    password_entry = tk.Entry(card, width=35, show="*", font=("Segoe UI", 10))
    password_entry.grid(row=7, column=0, pady=(0, 8))

    tk.Label(card, text="Confirm password", bg="white").grid(
        row=8, column=0, sticky="w", pady=4
    )
    confirm_password_entry = tk.Entry(card, width=35, show="*", font=("Segoe UI", 10))
    confirm_password_entry.grid(row=9, column=0, pady=(0, 8))

    tk.Label(card, text="I want to join as", bg="white").grid(
        row=10, column=0, sticky="w", pady=4
    )

    user_type_var = tk.StringVar(value="Customer")

    type_frame = tk.Frame(card, bg="white")
    type_frame.grid(row=11, column=0, sticky="w", pady=(0, 12))

    tk.Radiobutton(
        type_frame,
        text="Customer",
        variable=user_type_var,
        value="Customer",
        bg="white"
    ).pack(side="left")

    tk.Radiobutton(
        type_frame,
        text="Service Provider",
        variable=user_type_var,
        value="Provider",
        bg="white"
    ).pack(side="left", padx=15)

    tk.Button(
        card,
        text="Create Account",
        command=register_user,
        bg=PRIMARY_COLOR,
        fg="white",
        font=("Segoe UI", 11, "bold"),
        width=28,
        relief="flat",
        pady=8
    ).grid(row=12, column=0)

    tk.Button(
        card,
        text="Already have an account? Login",
        command=show_login_screen,
        bg="white",
        fg=PRIMARY_COLOR,
        relief="flat",
        font=("Segoe UI", 10, "underline")
    ).grid(row=13, column=0, pady=(12, 0))
def save_profile(user):
    user_id, username, user_type = user

    full_name = profile_name_entry.get().strip()
    email = profile_email_entry.get().strip()
    phone = profile_phone_entry.get().strip()
    college = profile_college_entry.get().strip()
    bio = profile_bio_text.get("1.0", tk.END).strip()

    if not full_name or not email:
        messagebox.showerror(
            "Missing details",
            "Full name and email are required."
        )
        return

    if "@" not in email or "." not in email:
        messagebox.showerror("Invalid email", "Enter a valid email address.")
        return

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute("""
            UPDATE users
            SET email = ?
            WHERE user_id = ?
        """, (email, user_id))

        cursor.execute("""
            UPDATE profiles
            SET full_name = ?, phone = ?, college = ?, bio = ?
            WHERE user_id = ?
        """, (full_name, phone, college, bio, user_id))

        connection.commit()
        connection.close()

        _record_activity("User", user_id, "PROFILE_UPDATED", "Updated profile details.", "User", user_id)

        messagebox.showinfo("Saved", "Your profile has been updated.")
        show_logged_in_screen(user)

    except sqlite3.IntegrityError:
        messagebox.showerror(
            "Email already used",
            "This email is already registered to another account."
        )


def show_profile_screen(user):
    global profile_name_entry, profile_email_entry
    global profile_phone_entry, profile_college_entry, profile_bio_text

    user_id, username, user_type = user

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT users.email, profiles.full_name, profiles.phone,
               profiles.college, profiles.bio
        FROM users
        LEFT JOIN profiles ON users.user_id = profiles.user_id
        WHERE users.user_id = ?
    """, (user_id,))

    profile = cursor.fetchone()
    connection.close()

    email, full_name, phone, college, bio = profile

    clear_window()

    tk.Label(
        app,
        text="My Profile",
        font=("Segoe UI", 25, "bold"),
        bg=BG_COLOR,
        fg=PRIMARY_COLOR
    ).pack(pady=(35, 5))

    tk.Label(
        app,
        text=f"Username: {username}  |  Account type: {user_type}",
        font=("Segoe UI", 11),
        bg=BG_COLOR,
        fg="#64748B"
    ).pack(pady=(0, 20))

    card = tk.Frame(app, bg="white", padx=35, pady=25)
    card.pack()

    tk.Label(card, text="Full Name", bg="white").grid(
        row=0, column=0, sticky="w", pady=5
    )
    profile_name_entry = tk.Entry(card, width=40, font=("Segoe UI", 10))
    profile_name_entry.grid(row=1, column=0, pady=(0, 10))
    profile_name_entry.insert(0, full_name or "")

    tk.Label(card, text="Email Address", bg="white").grid(
        row=2, column=0, sticky="w", pady=5
    )
    profile_email_entry = tk.Entry(card, width=40, font=("Segoe UI", 10))
    profile_email_entry.grid(row=3, column=0, pady=(0, 10))
    profile_email_entry.insert(0, email or "")

    tk.Label(card, text="Phone Number", bg="white").grid(
        row=4, column=0, sticky="w", pady=5
    )
    profile_phone_entry = tk.Entry(card, width=40, font=("Segoe UI", 10))
    profile_phone_entry.grid(row=5, column=0, pady=(0, 10))
    profile_phone_entry.insert(0, phone or "")

    tk.Label(card, text="College / University", bg="white").grid(
        row=6, column=0, sticky="w", pady=5
    )
    profile_college_entry = tk.Entry(card, width=40, font=("Segoe UI", 10))
    profile_college_entry.grid(row=7, column=0, pady=(0, 10))
    profile_college_entry.insert(0, college or "")

    tk.Label(card, text="About Me", bg="white").grid(
        row=8, column=0, sticky="w", pady=5
    )
    profile_bio_text = tk.Text(card, width=39, height=5, font=("Segoe UI", 10))
    profile_bio_text.grid(row=9, column=0, pady=(0, 15))
    profile_bio_text.insert("1.0", bio or "")

    buttons = tk.Frame(card, bg="white")
    buttons.grid(row=10, column=0)

    tk.Button(
        buttons,
        text="Save Profile",
        command=lambda: save_profile(user),
        bg=PRIMARY_COLOR,
        fg="white",
        font=("Segoe UI", 10, "bold"),
        width=16,
        relief="flat",
        pady=8
    ).pack(side="left", padx=(0, 10))

    tk.Button(
        buttons,
        text="Back to Dashboard",
        command=lambda: show_logged_in_screen(user),
        bg="#E2E8F0",
        fg=TEXT_COLOR,
        font=("Segoe UI", 10, "bold"),
        width=18,
        relief="flat",
        pady=8
    ).pack(side="left")
def save_service(user):
    user_id, username, user_type = user

    title = service_title_entry.get().strip()
    description = service_description_text.get("1.0", tk.END).strip()
    category = service_category_var.get()
    price_text = service_price_entry.get().strip()

    if not title or not description or not category or not price_text:
        messagebox.showerror(
            "Missing details",
            "Please complete every service field."
        )
        return

    try:
        price = float(price_text)
        if price < 0:
            messagebox.showerror("Invalid price", "Price cannot be negative.")
            return
    except ValueError:
        messagebox.showerror(
            "Invalid price",
            "Enter a valid number, for example: 250"
        )
        return

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO services (provider_id, title, description, category, price)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, title, description, category, price))
    connection.commit()
    connection.close()

    _record_activity("User", user_id, "SERVICE_CREATED", f"Created service listing '{title}'.", "Service", cursor.lastrowid)

    messagebox.showinfo(
        "Service added",
        "Your service is now available on CampusGig."
    )
    show_logged_in_screen(user)


def show_add_service_screen(user):
    global service_title_entry, service_description_text
    global service_category_var, service_price_entry

    clear_window()

    tk.Label(
        app,
        text="Add New Service",
        font=("Segoe UI", 25, "bold"),
        bg=BG_COLOR,
        fg=PRIMARY_COLOR
    ).pack(pady=(35, 5))

    tk.Label(
        app,
        text="Tell students what service you can offer.",
        font=("Segoe UI", 12),
        bg=BG_COLOR,
        fg="#64748B"
    ).pack(pady=(0, 20))

    card = tk.Frame(app, bg="white", padx=35, pady=25)
    card.pack()

    tk.Label(card, text="Service Title", bg="white").grid(
        row=0, column=0, sticky="w", pady=5
    )

    service_title_entry = tk.Entry(card, width=45, font=("Segoe UI", 10))
    service_title_entry.grid(row=1, column=0, pady=(0, 10))

    tk.Label(card, text="Description", bg="white").grid(
        row=2, column=0, sticky="w", pady=5
    )

    service_description_text = tk.Text(
        card,
        width=44,
        height=6,
        font=("Segoe UI", 10)
    )
    service_description_text.grid(row=3, column=0, pady=(0, 10))

    tk.Label(card, text="Category", bg="white").grid(
        row=4, column=0, sticky="w", pady=5
    )

    service_category_var = tk.StringVar()

    categories = [
        "Programming",
        "Graphic Design",
        "Writing",
        "Tutoring",
        "Photography",
        "Video Editing",
        "Social Media",
        "Other"
    ]

    category_box = ttk.Combobox(
        card,
        textvariable=service_category_var,
        values=categories,
        state="readonly",
        width=42
    )
    category_box.grid(row=5, column=0, pady=(0, 10))

    tk.Label(card, text="Price (₹)", bg="white").grid(
        row=6, column=0, sticky="w", pady=5
    )

    service_price_entry = tk.Entry(card, width=45, font=("Segoe UI", 10))
    service_price_entry.grid(row=7, column=0, pady=(0, 15))

    buttons = tk.Frame(card, bg="white")
    buttons.grid(row=8, column=0)

    tk.Button(
        buttons,
        text="Add Service",
        command=lambda: save_service(user),
        bg=PRIMARY_COLOR,
        fg="white",
        font=("Segoe UI", 10, "bold"),
        width=16,
        relief="flat",
        pady=8
    ).pack(side="left", padx=(0, 10))

    tk.Button(
        buttons,
        text="Back to Dashboard",
        command=lambda: show_logged_in_screen(user),
        bg="#E2E8F0",
        fg=TEXT_COLOR,
        font=("Segoe UI", 10, "bold"),
        width=18,
        relief="flat",
        pady=8
    ).pack(side="left")
def load_services(user):
    for widget in service_list_frame.winfo_children():
        widget.destroy()

    search_text = browse_search_var.get().strip()
    category = browse_category_var.get()

    connection = get_connection()
    cursor = connection.cursor()

    query = """
        SELECT services.service_id, services.title, services.description,
               services.category, services.price, services.provider_id,
               users.username, profiles.full_name, profiles.college
        FROM services
        JOIN users ON services.provider_id = users.user_id
        LEFT JOIN profiles ON services.provider_id = profiles.user_id
        WHERE services.status = 'Available'
    """

    values = []

    if search_text:
        query += """
            AND (
                services.title LIKE ?
                OR services.description LIKE ?
            )
        """
        values.extend([f"%{search_text}%", f"%{search_text}%"])

    if category != "All Categories":
        query += " AND services.category = ?"
        values.append(category)

    query += " ORDER BY services.service_id DESC"

    cursor.execute(query, values)
    services = cursor.fetchall()
    connection.close()

    if not services:
        tk.Label(
            service_list_frame,
            text="No services found.",
            font=("Segoe UI", 13),
            bg=BG_COLOR,
            fg="#64748B"
        ).pack(pady=30)
        return

    for service in services:
        service_id, title, description, category, price, provider_id, provider_username, full_name, college = service

        card = tk.Frame(
            service_list_frame,
            bg="white",
            padx=20,
            pady=15
        )
        card.pack(fill="x", pady=7)

        tk.Label(
            card,
            text=title,
            font=("Segoe UI", 15, "bold"),
            bg="white",
            fg=TEXT_COLOR
        ).pack(anchor="w")

        tk.Label(
            card,
            text=f"{category}  •  ₹{price:.2f}",
            font=("Segoe UI", 11, "bold"),
            bg="white",
            fg=PRIMARY_COLOR
        ).pack(anchor="w", pady=(4, 6))

        short_description = description[:120]
        if len(description) > 120:
            short_description += "..."

        tk.Label(
            card,
            text=short_description,
            font=("Segoe UI", 10),
            bg="white",
            fg="#64748B",
            justify="left",
            wraplength=650
        ).pack(anchor="w")

        provider_name = full_name if full_name else provider_username

        tk.Label(
            card,
            text=f"Provider: {provider_name}",
            font=("Segoe UI", 10),
            bg="white",
            fg="#64748B"
        ).pack(anchor="w", pady=(8, 0))

        tk.Button(
            card,
            text="View Details",
            command=lambda item=service: show_service_details(user, item),
            bg=PRIMARY_COLOR,
            fg="white",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=5
        ).pack(anchor="e")


def show_service_details(user, service):
    (
        service_id, title, description, category, price,
        provider_id, provider_username, full_name, college
    ) = service

    clear_window()

    provider_name = full_name if full_name else provider_username

    tk.Label(
        app,
        text="Service Details",
        font=("Segoe UI", 25, "bold"),
        bg=BG_COLOR,
        fg=PRIMARY_COLOR
    ).pack(pady=(40, 20))

    card = tk.Frame(app, bg="white", padx=35, pady=30)
    card.pack()

    tk.Label(
        card,
        text=title,
        font=("Segoe UI", 20, "bold"),
        bg="white",
        fg=TEXT_COLOR
    ).pack(anchor="w")

    tk.Label(
        card,
        text=f"{category}  •  ₹{price:.2f}",
        font=("Segoe UI", 12, "bold"),
        bg="white",
        fg=PRIMARY_COLOR
    ).pack(anchor="w", pady=(7, 15))

    tk.Label(
        card,
        text="Service Description",
        font=("Segoe UI", 11, "bold"),
        bg="white",
        fg=TEXT_COLOR
    ).pack(anchor="w")

    tk.Label(
        card,
        text=description,
        font=("Segoe UI", 11),
        bg="white",
        fg="#64748B",
        justify="left",
        wraplength=600
    ).pack(anchor="w", pady=(5, 20))

    tk.Label(
        card,
        text=f"Service Provider: {provider_name}",
        font=("Segoe UI", 11, "bold"),
        bg="white",
        fg=TEXT_COLOR
    ).pack(anchor="w")

    tk.Label(
        card,
        text=f"College: {college or 'Not added'}",
        font=("Segoe UI", 10),
        bg="white",
        fg="#64748B"
    ).pack(anchor="w", pady=(5, 20))

    if user[0] != provider_id:
        tk.Button(
            card,
            text="Send Request",
            command=lambda: show_send_request_screen(user, service),
            bg=PRIMARY_COLOR,
            fg="white",
            font=("Segoe UI", 10, "bold"),
            width=22,
            relief="flat",
            pady=8
        ).pack(pady=(0, 10))

    tk.Button(
        card,
        text="Back to Browse Services",
        command=lambda: show_browse_services_screen(user),
        bg="#E2E8F0",
        fg=TEXT_COLOR,
        font=("Segoe UI", 10, "bold"),
        width=22,
        relief="flat",
        pady=8
    ).pack()


def show_browse_services_screen(user):
    global browse_search_var, browse_category_var, service_list_frame

    clear_window()

    tk.Label(
        app,
        text="Browse Services",
        font=("Segoe UI", 25, "bold"),
        bg=BG_COLOR,
        fg=PRIMARY_COLOR
    ).pack(pady=(30, 5))

    tk.Label(
        app,
        text="Find skilled students and services on campus.",
        font=("Segoe UI", 12),
        bg=BG_COLOR,
        fg="#64748B"
    ).pack(pady=(0, 20))

    filters = tk.Frame(app, bg=BG_COLOR)
    filters.pack()

    browse_search_var = tk.StringVar()
    browse_category_var = tk.StringVar(value="All Categories")

    search_entry = tk.Entry(
        filters,
        textvariable=browse_search_var,
        width=35,
        font=("Segoe UI", 10)
    )
    search_entry.grid(row=0, column=0, padx=(0, 10))

    categories = [
        "All Categories",
        "Programming",
        "Graphic Design",
        "Writing",
        "Tutoring",
        "Photography",
        "Video Editing",
        "Social Media",
        "Other"
    ]

    category_box = ttk.Combobox(
        filters,
        textvariable=browse_category_var,
        values=categories,
        state="readonly",
        width=20
    )
    category_box.grid(row=0, column=1, padx=(0, 10))

    tk.Button(
        filters,
        text="Search",
        command=lambda: load_services(user),
        bg=PRIMARY_COLOR,
        fg="white",
        font=("Segoe UI", 10, "bold"),
        relief="flat",
        padx=15,
        pady=4
    ).grid(row=0, column=2)

    tk.Button(
        app,
        text="Back to Dashboard",
        command=lambda: show_logged_in_screen(user),
        bg="#E2E8F0",
        fg=TEXT_COLOR,
        font=("Segoe UI", 9, "bold"),
        relief="flat",
        padx=12,
        pady=5
    ).pack(pady=12)

    service_list_frame = tk.Frame(app, bg=BG_COLOR)
    service_list_frame.pack(fill="both", expand=True, padx=130)

    load_services(user)


def submit_service_request(user, service):
    customer_id, username, user_type = user
    service_id, title, description, category, price, provider_id, provider_username, full_name, college = service
    message = request_message_text.get("1.0", tk.END).strip()

    if customer_id == provider_id:
        messagebox.showerror("Not allowed", "You cannot request your own service.")
        return

    if not message:
        messagebox.showerror("Missing message", "Please write a message for the provider.")
        return

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT request_id FROM service_requests
        WHERE service_id = ? AND customer_id = ?
          AND request_status IN ('Pending', 'Accepted')
    """, (service_id, customer_id))
    existing_request = cursor.fetchone()

    if existing_request:
        connection.close()
        messagebox.showerror(
            "Request already sent",
            "You already have a pending or accepted request for this service."
        )
        return

    cursor.execute("""
        INSERT INTO service_requests (service_id, customer_id, provider_id, message)
        VALUES (?, ?, ?, ?)
    """, (service_id, customer_id, provider_id, message))
    request_id = cursor.lastrowid
    connection.commit()
    connection.close()

    _record_activity("User", customer_id, "SERVICE_REQUESTED", f"Requested service '{title}'.", "Request", request_id)

    messagebox.showinfo("Request sent", "Your request was sent to the service provider.")
    show_my_requests_screen(user)


def show_send_request_screen(user, service):
    global request_message_text

    service_id, title, description, category, price, provider_id, provider_username, full_name, college = service
    clear_window()

    tk.Label(
        app,
        text="Send Service Request",
        font=("Segoe UI", 25, "bold"),
        bg=BG_COLOR,
        fg=PRIMARY_COLOR
    ).pack(pady=(45, 10))

    card = tk.Frame(app, bg="white", padx=35, pady=28)
    card.pack()

    tk.Label(
        card,
        text=title,
        font=("Segoe UI", 17, "bold"),
        bg="white",
        fg=TEXT_COLOR
    ).pack(anchor="w")

    tk.Label(
        card,
        text=f"Price: ₹{price:.2f}",
        font=("Segoe UI", 11, "bold"),
        bg="white",
        fg=PRIMARY_COLOR
    ).pack(anchor="w", pady=(5, 18))

    tk.Label(
        card,
        text="Message to the provider",
        font=("Segoe UI", 11, "bold"),
        bg="white",
        fg=TEXT_COLOR
    ).pack(anchor="w")

    request_message_text = tk.Text(card, width=55, height=7, font=("Segoe UI", 10))
    request_message_text.pack(pady=(6, 18))
    request_message_text.insert(
        "1.0",
        f"Hello, I am interested in your {title} service."
    )

    buttons = tk.Frame(card, bg="white")
    buttons.pack()

    tk.Button(
        buttons,
        text="Send Request",
        command=lambda: submit_service_request(user, service),
        bg=PRIMARY_COLOR,
        fg="white",
        font=("Segoe UI", 10, "bold"),
        relief="flat",
        width=16,
        pady=8
    ).pack(side="left", padx=(0, 10))

    tk.Button(
        buttons,
        text="Cancel",
        command=lambda: show_service_details(user, service),
        bg="#E2E8F0",
        fg=TEXT_COLOR,
        font=("Segoe UI", 10, "bold"),
        relief="flat",
        width=12,
        pady=8
    ).pack(side="left")


def update_request_status(user, request_id, new_status):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        UPDATE service_requests
        SET request_status = ?
        WHERE request_id = ? AND provider_id = ?
    """, (new_status, request_id, user[0]))
    changed = cursor.rowcount
    connection.commit()
    connection.close()

    if changed:
        _record_activity("User", user[0], "REQUEST_STATUS_CHANGED", f"Changed request #{request_id} to {new_status}.", "Request", request_id)

    messagebox.showinfo("Request updated", f"Request {new_status.lower()}.")
    show_received_requests_screen(user)


def upload_project_submission(user, request_id):
    """Copy a provider's deliverable into the app's local submission folder."""
    provider_id = user[0]
    connection = get_connection()
    try:
        request = connection.execute("""
            SELECT request_id, request_status FROM service_requests
            WHERE request_id = ? AND provider_id = ?
        """, (request_id, provider_id)).fetchone()
    finally:
        connection.close()

    if not request or request[1] != "Accepted":
        messagebox.showerror("Cannot submit work", "Only the provider assigned to an accepted request can submit work.")
        return

    source_path = filedialog.askopenfilename(
        title="Choose the finished work to submit",
        filetypes=[("Allowed project files", "*.pdf *.doc *.docx *.ppt *.pptx *.txt *.zip *.png *.jpg *.jpeg"), ("All files", "*.*")],
    )
    if not source_path:
        return

    source = Path(source_path)
    if source.suffix.lower() not in ALLOWED_SUBMISSION_EXTENSIONS:
        messagebox.showerror("File type not supported", "Choose a PDF, Word, PowerPoint, text, ZIP, or image file.")
        return
    try:
        if source.stat().st_size > MAX_SUBMISSION_SIZE:
            messagebox.showerror("File too large", "Submissions must be 25 MB or smaller.")
            return
        SUBMISSIONS_DIR.mkdir(parents=True, exist_ok=True)
        stored_name = f"request_{request_id}_{uuid.uuid4().hex}{source.suffix.lower()}"
        stored_path = SUBMISSIONS_DIR / stored_name
        shutil.copy2(source, stored_path)
    except OSError as error:
        messagebox.showerror("Could not copy file", f"The selected file could not be added.\n\n{error}")
        return

    connection = get_connection()
    try:
        # Recheck ownership and status immediately before storing the record.
        current_request = connection.execute("""
            SELECT request_status FROM service_requests
            WHERE request_id = ? AND provider_id = ?
        """, (request_id, provider_id)).fetchone()
        if not current_request or current_request[0] != "Accepted":
            stored_path.unlink(missing_ok=True)
            messagebox.showerror("Request changed", "This request is no longer available for submission.")
            return
        connection.execute("""
            INSERT INTO project_submissions
                (request_id, provider_id, file_name, file_path, message, submission_status, revision_number)
            VALUES (?, ?, ?, ?, ?, 'Submitted',
                COALESCE((SELECT MAX(revision_number) + 1 FROM project_submissions WHERE request_id = ?), 1))
        """, (request_id, provider_id, source.name, str(stored_path), "Work submitted by provider.", request_id))
        connection.execute("""
            INSERT INTO activity_logs (actor_type, actor_id, action, description, related_type, related_id)
            VALUES ('User', ?, 'PROJECT_SUBMITTED', ?, 'Request', ?)
        """, (provider_id, f"Submitted {source.name} for request #{request_id}.", request_id))
        connection.commit()
    except sqlite3.Error as error:
        stored_path.unlink(missing_ok=True)
        messagebox.showerror("Could not save submission", f"The submission record was not saved.\n\n{error}")
        return
    finally:
        connection.close()

    messagebox.showinfo("Work submitted", f"{source.name} was submitted for request #{request_id}.")
    show_received_requests_screen(user)


def download_project_submission(user, submission_id):
    """Let only a linked customer download a submission to a chosen location."""
    connection = get_connection()
    try:
        row = connection.execute("""
            SELECT ps.file_name, ps.file_path
            FROM project_submissions AS ps
            JOIN service_requests AS sr ON sr.request_id = ps.request_id
            WHERE ps.submission_id = ? AND sr.customer_id = ?
        """, (submission_id, user[0])).fetchone()
    finally:
        connection.close()
    if not row:
        messagebox.showerror("Submission unavailable", "This file is not available to this account.")
        return

    stored_path = Path(row[1]).resolve()
    submissions_root = SUBMISSIONS_DIR.resolve()
    if submissions_root not in stored_path.parents or not stored_path.is_file():
        messagebox.showerror("File unavailable", "The stored submission file could not be found.")
        return
    destination = filedialog.asksaveasfilename(
        title="Save project submission",
        initialfile=row[0],
        defaultextension=Path(row[0]).suffix,
        filetypes=[("Original file type", f"*{Path(row[0]).suffix}"), ("All files", "*.*")],
    )
    if not destination:
        return
    try:
        shutil.copy2(stored_path, destination)
    except OSError as error:
        messagebox.showerror("Download failed", f"The file could not be saved.\n\n{error}")
        return
    messagebox.showinfo("Download complete", f"Saved submission to:\n{destination}")


def review_project_submission(user, request_id, submission_id, decision):
    """Customer approves the latest delivery or requests a revision."""
    customer_id = user[0]
    if decision not in {"Approved", "Revision Requested"}:
        return
    revision_note = ""
    if decision == "Revision Requested":
        revision_note = simpledialog.askstring(
            "Request a revision",
            "Describe what needs to be changed:",
            parent=app,
        )
        if revision_note is None:
            return
        revision_note = revision_note.strip()
        if not revision_note:
            messagebox.showerror("Revision details needed", "Please describe the changes you need.")
            return
    elif not messagebox.askyesno(
        "Approve finished work?",
        "Approve this submission and mark the service request completed? You can then leave a review.",
    ):
        return

    connection = get_connection()
    try:
        latest = connection.execute("""
            SELECT ps.submission_id, ps.submission_status, sr.request_status
            FROM project_submissions AS ps
            JOIN service_requests AS sr ON sr.request_id = ps.request_id
            WHERE ps.submission_id = ? AND ps.request_id = ? AND sr.customer_id = ?
              AND ps.submission_id = (
                  SELECT MAX(newer.submission_id) FROM project_submissions AS newer
                  WHERE newer.request_id = ps.request_id
              )
        """, (submission_id, request_id, customer_id)).fetchone()
        if not latest or latest[1] != "Submitted" or latest[2] != "Accepted":
            messagebox.showerror("Submission changed", "Only the latest submission on an active accepted request can be reviewed.")
            return

        connection.execute("""
            UPDATE project_submissions SET submission_status = ?, message = ?
            WHERE submission_id = ?
        """, (decision, revision_note if revision_note else "Approved by customer.", submission_id))
        if decision == "Approved":
            connection.execute("""
                UPDATE service_requests SET request_status = 'Completed'
                WHERE request_id = ? AND customer_id = ? AND request_status = 'Accepted'
            """, (request_id, customer_id))
            action = "SUBMISSION_APPROVED"
            description = f"Customer approved submission #{submission_id} for request #{request_id}."
        else:
            action = "REVISION_REQUESTED"
            description = f"Customer requested a revision for submission #{submission_id}, request #{request_id}: {revision_note}"
        connection.execute("""
            INSERT INTO activity_logs (actor_type, actor_id, action, description, related_type, related_id)
            VALUES ('User', ?, ?, ?, 'Request', ?)
        """, (customer_id, action, description, request_id))
        connection.commit()
    except sqlite3.Error as error:
        messagebox.showerror("Could not save decision", f"Your decision could not be saved.\n\n{error}")
        return
    finally:
        connection.close()

    if decision == "Approved":
        messagebox.showinfo("Work approved", "The request is completed. You can now leave a review.")
    else:
        messagebox.showinfo("Revision requested", "Your change request was sent to the provider.")
    show_my_requests_screen(user)


def make_demo_payment(user, request_id):
    """Record a simulated payment and queue the provider's net amount for admin review."""
    customer_id = user[0]
    connection = get_connection()
    try:
        request = connection.execute("""
            SELECT sr.provider_id, sr.request_status, services.price,
                   (SELECT COUNT(*) FROM project_submissions AS ps
                    WHERE ps.request_id = sr.request_id AND ps.submission_status = 'Approved')
            FROM service_requests AS sr
            JOIN services ON services.service_id = sr.service_id
            WHERE sr.request_id = ? AND sr.customer_id = ?
        """, (request_id, customer_id)).fetchone()
        if not request:
            messagebox.showerror("Request unavailable", "This request does not belong to your account.")
            return
        provider_id, request_status, price, approved_count = request
        if request_status != "Completed" or approved_count < 1:
            messagebox.showerror("Approval required", "Approve the provider's submission before paying.")
            return
        if connection.execute("SELECT 1 FROM payments WHERE request_id = ?", (request_id,)).fetchone():
            messagebox.showinfo("Already paid", "A payment record already exists for this request.")
            return

        setting = connection.execute(
            "SELECT setting_value FROM platform_settings WHERE setting_key = 'commission_rate'"
        ).fetchone()
        commission_rate = float(setting[0]) if setting else 10.0
        if not 5.0 <= commission_rate <= 10.0:
            messagebox.showerror("Invalid commission setting", "The platform commission must be between 5% and 10%.")
            return
        gross_amount = round(float(price), 2)
        commission_amount = round(gross_amount * commission_rate / 100.0, 2)
        provider_amount = round(gross_amount - commission_amount, 2)
        confirmation = (
            f"DEMO PAYMENT — no real money will be charged or transferred.\n\n"
            f"Service total: ₹{gross_amount:.2f}\n"
            f"CampusGig commission ({commission_rate:g}%): ₹{commission_amount:.2f}\n"
            f"Provider amount queued for admin payout: ₹{provider_amount:.2f}\n\n"
            "Record this simulated payment?"
        )
        if not messagebox.askyesno("Confirm demo payment", confirmation):
            return

        reference = f"DEMO-{uuid.uuid4().hex[:12].upper()}"
        connection.execute("""
            INSERT INTO payments
                (request_id, customer_id, provider_id, gross_amount, commission_rate,
                 commission_amount, provider_amount, payment_status, payment_mode,
                 transaction_reference, paid_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'Completed', 'Demo', ?, ?)
        """, (
            request_id, customer_id, provider_id, gross_amount, commission_rate,
            commission_amount, provider_amount, reference,
            datetime.now().astimezone().isoformat(timespec="seconds"),
        ))
        payment_id = connection.execute("SELECT last_insert_rowid()").fetchone()[0]
        connection.execute("""
            INSERT INTO provider_payouts (payment_id, provider_id, amount, payout_status)
            VALUES (?, ?, ?, 'Pending')
        """, (payment_id, provider_id, provider_amount))
        connection.execute("""
            INSERT INTO activity_logs (actor_type, actor_id, action, description, related_type, related_id)
            VALUES ('User', ?, 'DEMO_PAYMENT_RECORDED', ?, 'Request', ?)
        """, (
            customer_id,
            f"Recorded demo payment {reference}: gross ₹{gross_amount:.2f}, commission ₹{commission_amount:.2f}, provider net ₹{provider_amount:.2f}.",
            request_id,
        ))
        connection.commit()
    except sqlite3.IntegrityError:
        connection.rollback()
        messagebox.showerror("Payment already recorded", "Only one payment can be recorded per request.")
        return
    except (sqlite3.Error, TypeError, ValueError) as error:
        connection.rollback()
        messagebox.showerror("Payment could not be recorded", f"The demo transaction was not saved.\n\n{error}")
        return
    finally:
        connection.close()

    messagebox.showinfo(
        "Demo payment recorded",
        f"Payment reference: {reference}\nProvider amount is pending admin payout review. No money was transferred."
    )
    show_my_requests_screen(user)


def get_request_submissions(request_id):
    connection = get_connection()
    try:
        return connection.execute("""
            SELECT submission_id, file_name, submission_status, revision_number, uploaded_at, message
            FROM project_submissions WHERE request_id = ?
            ORDER BY submission_id DESC
        """, (request_id,)).fetchall()
    finally:
        connection.close()


def show_received_requests_screen(user):
    provider_id, username, user_type = user
    clear_window()

    tk.Label(
        app,
        text="Received Requests",
        font=("Segoe UI", 25, "bold"),
        bg=BG_COLOR,
        fg=PRIMARY_COLOR
    ).pack(pady=(30, 15))

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT service_requests.request_id, services.title,
               users.username, profiles.full_name,
               service_requests.message, service_requests.request_status
        FROM service_requests
        JOIN services ON service_requests.service_id = services.service_id
        JOIN users ON service_requests.customer_id = users.user_id
        LEFT JOIN profiles ON users.user_id = profiles.user_id
        WHERE service_requests.provider_id = ?
        ORDER BY service_requests.request_id DESC
    """, (provider_id,))
    requests = cursor.fetchall()
    connection.close()

    content = tk.Frame(app, bg=BG_COLOR)
    content.pack(fill="both", expand=True, padx=130)

    if not requests:
        tk.Label(
            content,
            text="You have not received any service requests yet.",
            font=("Segoe UI", 12),
            bg=BG_COLOR,
            fg="#64748B"
        ).pack(pady=40)

    for request in requests:
        request_id, service_title, customer_username, customer_name, message, status = request
        card = tk.Frame(content, bg="white", padx=20, pady=15)
        card.pack(fill="x", pady=7)

        customer = customer_name if customer_name else customer_username
        tk.Label(card, text=service_title, font=("Segoe UI", 14, "bold"), bg="white", fg=TEXT_COLOR).pack(anchor="w")
        tk.Label(card, text=f"Customer: {customer}  |  Status: {status}", font=("Segoe UI", 10, "bold"), bg="white", fg=PRIMARY_COLOR).pack(anchor="w", pady=(4, 6))
        tk.Label(card, text=message, font=("Segoe UI", 10), bg="white", fg="#64748B", wraplength=650, justify="left").pack(anchor="w")

        if status == "Pending":
            actions = tk.Frame(card, bg="white")
            actions.pack(anchor="e", pady=(8, 0))
            tk.Button(actions, text="Accept", command=lambda rid=request_id: update_request_status(user, rid, "Accepted"), bg="#16A34A", fg="white", relief="flat", padx=12).pack(side="left", padx=(0, 8))
            tk.Button(actions, text="Reject", command=lambda rid=request_id: update_request_status(user, rid, "Rejected"), bg="#DC2626", fg="white", relief="flat", padx=12).pack(side="left")
        elif status == "Accepted":
            submissions = get_request_submissions(request_id)
            if submissions:
                tk.Label(
                    card,
                    text="Submitted work: " + " · ".join(
                        f"{item[1]} (v{item[3]}, {item[2]})"
                        + (f" — {item[5]}" if item[2] == "Revision Requested" and item[5] else "")
                        for item in submissions
                    ),
                    font=("Segoe UI", 9), bg="white", fg="#64748B",
                    wraplength=650, justify="left"
                ).pack(anchor="w", pady=(8, 0))
            tk.Button(
                card,
                text="Submit / Resubmit Work",
                command=lambda rid=request_id: upload_project_submission(user, rid),
                bg="#7C3AED", fg="white", relief="flat", padx=12, pady=5
            ).pack(anchor="e", pady=(8, 0))

    tk.Button(
        app,
        text="Back to Dashboard",
        command=lambda: show_logged_in_screen(user),
        bg="#E2E8F0",
        fg=TEXT_COLOR,
        relief="flat",
        padx=14,
        pady=6
    ).pack(pady=15)


def show_provider_earnings_screen(user):
    provider_id, username, user_type = user
    if user_type != "Provider":
        messagebox.showerror("Provider page", "Only provider accounts can view provider earnings.")
        return
    clear_window()
    tk.Label(app, text="My Earnings & Payouts", font=("Segoe UI", 25, "bold"), bg=BG_COLOR, fg=PRIMARY_COLOR).pack(pady=(28, 6))
    tk.Label(app, text="Demo ledger amounts only. This page does not show real transfers.", font=("Segoe UI", 10), bg=BG_COLOR, fg="#64748B").pack(pady=(0, 12))

    connection = get_connection()
    try:
        totals = connection.execute("""
            SELECT COALESCE(SUM(CASE WHEN p.payment_status='Completed' THEN p.provider_amount ELSE 0 END),0),
                   COALESCE(SUM(CASE WHEN p.payment_status='Completed' AND pp.payout_status='Processed' THEN pp.amount ELSE 0 END),0),
                   COALESCE(SUM(CASE WHEN p.payment_status='Completed' AND (pp.payout_status IS NULL OR pp.payout_status!='Processed') THEN p.provider_amount ELSE 0 END),0)
            FROM payments AS p
            LEFT JOIN provider_payouts AS pp ON pp.payment_id=p.payment_id
            WHERE p.provider_id=?
        """, (provider_id,)).fetchone()
        rows = connection.execute("""
            SELECT p.payment_id, p.created_at, p.transaction_reference,
                   sr.request_id, services.title, p.gross_amount,
                   p.commission_rate, p.commission_amount, p.provider_amount,
                   p.payment_status, COALESCE(pp.payout_status, 'No payout'),
                   pp.payout_reference, pp.processed_at
            FROM payments AS p
            JOIN service_requests AS sr ON sr.request_id=p.request_id
            JOIN services ON services.service_id=sr.service_id
            LEFT JOIN provider_payouts AS pp ON pp.payment_id=p.payment_id
            WHERE p.provider_id=?
            ORDER BY p.payment_id DESC
        """, (provider_id,)).fetchall()
    finally:
        connection.close()

    summary = tk.Frame(app, bg=BG_COLOR)
    summary.pack(fill="x", padx=55, pady=(0, 14))
    for title, value, color in [
        ("Provider net earned", totals[0], "#2563EB"),
        ("Demo payouts processed", totals[1], "#16A34A"),
        ("Awaiting payout", totals[2], "#F59E0B"),
    ]:
        card = tk.Frame(summary, bg="white", padx=18, pady=12)
        card.pack(side="left", fill="x", expand=True, padx=6)
        tk.Label(card, text=title, font=("Segoe UI", 9), bg="white", fg="#64748B").pack(anchor="w")
        tk.Label(card, text=f"₹{value:.2f}", font=("Segoe UI", 16, "bold"), bg="white", fg=color).pack(anchor="w", pady=(3, 0))

    table_area = tk.Frame(app, bg="white")
    table_area.pack(fill="both", expand=True, padx=55, pady=(0, 5))
    columns = ("date", "request", "service", "gross", "commission", "net", "payout")
    earnings_tree = ttk.Treeview(table_area, columns=columns, show="headings", height=12)
    for column, title, width in [
        ("date", "Date", 115), ("request", "Request", 65), ("service", "Service", 180),
        ("gross", "Gross", 85), ("commission", "Commission", 110),
        ("net", "Provider net", 95), ("payout", "Payout status", 105),
    ]:
        earnings_tree.heading(column, text=title)
        earnings_tree.column(column, width=width, anchor="w")
    earnings_scroll = ttk.Scrollbar(table_area, orient="vertical", command=earnings_tree.yview)
    earnings_tree.configure(yscrollcommand=earnings_scroll.set)
    earnings_tree.pack(side="left", fill="both", expand=True)
    earnings_scroll.pack(side="right", fill="y")
    details = tk.Text(app, height=5, wrap="word", font=("Segoe UI", 9), bg="white", fg=TEXT_COLOR, relief="flat", padx=10, pady=7, state="disabled")
    details.pack(fill="x", padx=55, pady=(5, 8))

    def show_earning_detail(_event=None):
        selected = earnings_tree.selection()
        if not selected:
            return
        payment_id = int(selected[0])
        payment = next((item for item in rows if item[0] == payment_id), None)
        if not payment:
            return
        text = (
            f"Payment: {payment[2] or 'No reference'} · {payment[9]} · Request #{payment[3]}: {payment[4]}\n"
            f"Gross: ₹{payment[5]:.2f} · Commission: {payment[6]:g}% = ₹{payment[7]:.2f} · Your net: ₹{payment[8]:.2f}\n"
            f"Payout: {payment[10]} · Reference: {payment[11] or 'Not processed'} · Processed: {payment[12] or 'Not yet'}"
        )
        details.configure(state="normal")
        details.delete("1.0", tk.END)
        details.insert("1.0", text)
        details.configure(state="disabled")

    earnings_tree.bind("<<TreeviewSelect>>", show_earning_detail)
    for payment in rows:
        (payment_id, created, reference, request_id, title, gross, rate,
         commission, net, payment_status, payout_status, payout_ref, processed_at) = payment
        earnings_tree.insert("", "end", iid=str(payment_id), values=(
            created or "", f"#{request_id}", title, f"₹{gross:.2f}",
            f"{rate:g}% · ₹{commission:.2f}", f"₹{net:.2f}", payout_status,
        ))
    if rows:
        earnings_tree.selection_set(str(rows[0][0]))
        show_earning_detail()
    else:
        details.configure(state="normal")
        details.insert("1.0", "No payment or payout records yet. Completed customer demo payments will appear here.")
        details.configure(state="disabled")

    tk.Button(app, text="Back to Dashboard", command=lambda: show_logged_in_screen(user), bg="#E2E8F0", fg=TEXT_COLOR, relief="flat", padx=14, pady=6).pack(pady=8)


def show_my_requests_screen(user):
    customer_id, username, user_type = user
    clear_window()

    tk.Label(
        app,
        text="My Requests",
        font=("Segoe UI", 25, "bold"),
        bg=BG_COLOR,
        fg=PRIMARY_COLOR
    ).pack(pady=(30, 15))

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT service_requests.request_id, services.title,
               service_requests.provider_id, users.username, profiles.full_name,
               service_requests.message, service_requests.request_status,
               reviews.review_id, services.price, payments.payment_status,
               payments.gross_amount, payments.commission_amount, payments.provider_amount,
               payments.transaction_reference
        FROM service_requests
        JOIN services ON service_requests.service_id = services.service_id
        JOIN users ON service_requests.provider_id = users.user_id
        LEFT JOIN profiles ON users.user_id = profiles.user_id
        LEFT JOIN reviews ON service_requests.request_id = reviews.request_id
        LEFT JOIN payments ON service_requests.request_id = payments.request_id
        WHERE service_requests.customer_id = ?
        ORDER BY service_requests.request_id DESC
    """, (customer_id,))
    requests = cursor.fetchall()
    connection.close()

    content = tk.Frame(app, bg=BG_COLOR)
    content.pack(fill="both", expand=True, padx=130)

    if not requests:
        tk.Label(content, text="You have not sent any requests yet.", font=("Segoe UI", 12), bg=BG_COLOR, fg="#64748B").pack(pady=40)

    for (request_id, service_title, provider_id, provider_username, provider_name,
         message, status, review_id, service_price, payment_status, gross_amount,
         commission_amount, provider_amount, payment_reference) in requests:
        provider = provider_name if provider_name else provider_username
        card = tk.Frame(content, bg="white", padx=20, pady=15)
        card.pack(fill="x", pady=7)
        tk.Label(card, text=service_title, font=("Segoe UI", 14, "bold"), bg="white", fg=TEXT_COLOR).pack(anchor="w")
        tk.Label(card, text=f"Provider: {provider}  |  Status: {status}", font=("Segoe UI", 10, "bold"), bg="white", fg=PRIMARY_COLOR).pack(anchor="w", pady=(4, 6))
        tk.Label(card, text=message, font=("Segoe UI", 10), bg="white", fg="#64748B", wraplength=650, justify="left").pack(anchor="w")

        submissions = get_request_submissions(request_id)
        if submissions:
            tk.Label(card, text="Provider submissions", font=("Segoe UI", 10, "bold"), bg="white", fg=TEXT_COLOR).pack(anchor="w", pady=(10, 3))
            for submission_id, file_name, submission_status, revision_number, uploaded_at, submission_message in submissions:
                submission_row = tk.Frame(card, bg="white")
                submission_row.pack(fill="x", pady=2)
                tk.Label(
                    submission_row,
                    text=f"{file_name} · v{revision_number} · {submission_status} · {uploaded_at}"
                         + (f"\nNote: {submission_message}" if submission_message else ""),
                    font=("Segoe UI", 9), bg="white", fg="#64748B", wraplength=500, justify="left"
                ).pack(side="left", anchor="w")
                tk.Button(
                    submission_row,
                    text="Download",
                    command=lambda sid=submission_id: download_project_submission(user, sid),
                    bg="#E0E7FF", fg=PRIMARY_COLOR, relief="flat", padx=10, pady=3
                ).pack(side="right", padx=4)
                if status == "Accepted" and submission_status == "Submitted" and submission_id == submissions[0][0]:
                    decisions = tk.Frame(card, bg="white")
                    decisions.pack(anchor="e", pady=(2, 6))
                    tk.Button(
                        decisions, text="Request Revision",
                        command=lambda rid=request_id, sid=submission_id: review_project_submission(user, rid, sid, "Revision Requested"),
                        bg="#FEF3C7", fg="#92400E", relief="flat", padx=10, pady=4
                    ).pack(side="left", padx=4)
                    tk.Button(
                        decisions, text="Approve Work",
                        command=lambda rid=request_id, sid=submission_id: review_project_submission(user, rid, sid, "Approved"),
                        bg="#16A34A", fg="white", relief="flat", padx=10, pady=4
                    ).pack(side="left", padx=4)

        if status == "Completed" and review_id is None:
            tk.Button(
                card,
                text="Rate & Review",
                command=lambda rid=request_id, pid=provider_id, title=service_title: show_review_screen(user, rid, pid, title),
                bg="#F59E0B",
                fg="white",
                relief="flat",
                padx=12,
                pady=5
            ).pack(anchor="e", pady=(8, 0))

        if payment_status:
            tk.Label(
                card,
                text=(f"Payment: {payment_status} · Ref {payment_reference or '—'} · "
                      f"Total ₹{gross_amount:.2f} · Commission ₹{commission_amount:.2f} · "
                      f"Provider net ₹{provider_amount:.2f} (Demo)"),
                font=("Segoe UI", 9, "bold"), bg="white", fg="#64748B", wraplength=650, justify="left"
            ).pack(anchor="w", pady=(8, 0))
        elif status == "Completed" and any(item[2] == "Approved" for item in submissions):
            tk.Button(
                card,
                text=f"Pay ₹{float(service_price):.2f} (Demo)",
                command=lambda rid=request_id: make_demo_payment(user, rid),
                bg="#2563EB", fg="white", relief="flat", padx=12, pady=5
            ).pack(anchor="e", pady=(8, 0))

    tk.Button(app, text="Back to Dashboard", command=lambda: show_logged_in_screen(user), bg="#E2E8F0", fg=TEXT_COLOR, relief="flat", padx=14, pady=6).pack(pady=15)


def save_review(user, request_id, provider_id, service_title):
    rating = review_rating_var.get()
    review_text = review_text_box.get("1.0", tk.END).strip()

    if rating == 0:
        messagebox.showerror("Rating required", "Please select a rating from 1 to 5.")
        return

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO reviews (request_id, reviewer_id, provider_id, rating, review_text)
        VALUES (?, ?, ?, ?, ?)
    """, (request_id, user[0], provider_id, rating, review_text))
    review_id = cursor.lastrowid
    connection.commit()
    connection.close()

    _record_activity("User", user[0], "REVIEW_CREATED", f"Left a {rating}-star review for request #{request_id}.", "Review", review_id)

    messagebox.showinfo("Thank you", "Your rating and review have been saved.")
    show_my_requests_screen(user)


def show_review_screen(user, request_id, provider_id, service_title):
    global review_rating_var, review_text_box
    clear_window()

    tk.Label(
        app,
        text="Rate Your Experience",
        font=("Segoe UI", 25, "bold"),
        bg=BG_COLOR,
        fg=PRIMARY_COLOR
    ).pack(pady=(50, 10))

    card = tk.Frame(app, bg="white", padx=35, pady=30)
    card.pack()

    tk.Label(card, text=service_title, font=("Segoe UI", 17, "bold"), bg="white", fg=TEXT_COLOR).pack()
    tk.Label(card, text="Choose a rating", font=("Segoe UI", 11), bg="white", fg="#64748B").pack(pady=(18, 5))

    review_rating_var = tk.IntVar(value=0)
    ratings = tk.Frame(card, bg="white")
    ratings.pack(pady=(0, 18))

    for value in range(1, 6):
        tk.Radiobutton(
            ratings,
            text=f"{value} ★",
            variable=review_rating_var,
            value=value,
            bg="white",
            fg="#F59E0B",
            font=("Segoe UI", 11, "bold")
        ).pack(side="left", padx=5)

    tk.Label(card, text="Write a review (optional)", font=("Segoe UI", 11, "bold"), bg="white", fg=TEXT_COLOR).pack(anchor="w")
    review_text_box = tk.Text(card, width=55, height=6, font=("Segoe UI", 10))
    review_text_box.pack(pady=(6, 18))

    buttons = tk.Frame(card, bg="white")
    buttons.pack()
    tk.Button(buttons, text="Submit Review", command=lambda: save_review(user, request_id, provider_id, service_title), bg=PRIMARY_COLOR, fg="white", font=("Segoe UI", 10, "bold"), relief="flat", width=16, pady=8).pack(side="left", padx=(0, 10))
    tk.Button(buttons, text="Cancel", command=lambda: show_my_requests_screen(user), bg="#E2E8F0", fg=TEXT_COLOR, font=("Segoe UI", 10, "bold"), relief="flat", width=12, pady=8).pack(side="left")


def show_reviews_screen(user):
    user_id, username, user_type = user
    clear_window()

    tk.Label(app, text="Ratings & Reviews", font=("Segoe UI", 25, "bold"), bg=BG_COLOR, fg=PRIMARY_COLOR).pack(pady=(30, 10))

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT ROUND(AVG(rating), 1), COUNT(*) FROM reviews WHERE provider_id = ? AND moderation_status = 'Visible'", (user_id,))
    average_rating, review_count = cursor.fetchone()
    cursor.execute("""
        SELECT reviews.rating, reviews.review_text, profiles.full_name, users.username
        FROM reviews
        JOIN users ON reviews.reviewer_id = users.user_id
        LEFT JOIN profiles ON users.user_id = profiles.user_id
        WHERE reviews.provider_id = ? AND reviews.moderation_status = 'Visible'
        ORDER BY reviews.review_id DESC
    """, (user_id,))
    reviews = cursor.fetchall()
    connection.close()

    summary = "No ratings received yet." if review_count == 0 else f"Average rating: {average_rating} ★  ({review_count} review(s))"
    tk.Label(app, text=summary, font=("Segoe UI", 13, "bold"), bg=BG_COLOR, fg="#F59E0B").pack(pady=(0, 15))

    content = tk.Frame(app, bg=BG_COLOR)
    content.pack(fill="both", expand=True, padx=130)

    if not reviews:
        tk.Label(content, text="Reviews you receive will appear here.", font=("Segoe UI", 12), bg=BG_COLOR, fg="#64748B").pack(pady=30)

    for rating, review_text, reviewer_name, reviewer_username in reviews:
        reviewer = reviewer_name if reviewer_name else reviewer_username
        card = tk.Frame(content, bg="white", padx=20, pady=15)
        card.pack(fill="x", pady=7)
        tk.Label(card, text=f"{rating} ★  —  {reviewer}", font=("Segoe UI", 12, "bold"), bg="white", fg="#F59E0B").pack(anchor="w")
        tk.Label(card, text=review_text or "No written review.", font=("Segoe UI", 10), bg="white", fg="#64748B", wraplength=650, justify="left").pack(anchor="w", pady=(6, 0))

    tk.Button(app, text="Back to Dashboard", command=lambda: show_logged_in_screen(user), bg="#E2E8F0", fg=TEXT_COLOR, relief="flat", padx=14, pady=6).pack(pady=15)


def delete_service(user, service_id):
    if not messagebox.askyesno("Delete service", "Delete this service permanently?"):
        return

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("DELETE FROM services WHERE service_id = ? AND provider_id = ?", (service_id, user[0]))
    connection.commit()
    connection.close()

    _record_activity("User", user[0], "SERVICE_DELETED", f"Deleted service listing #{service_id}.", "Service", service_id)

    messagebox.showinfo("Service deleted", "The service was deleted.")
    show_my_services_screen(user)


def update_service(user, service_id):
    title = edit_service_title_entry.get().strip()
    description = edit_service_description_text.get("1.0", tk.END).strip()
    category = edit_service_category_var.get()
    price_text = edit_service_price_entry.get().strip()

    if not title or not description or not category or not price_text:
        messagebox.showerror("Missing details", "Please complete every service field.")
        return

    try:
        price = float(price_text)
        if price < 0:
            raise ValueError
    except ValueError:
        messagebox.showerror("Invalid price", "Enter a valid positive price.")
        return

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        UPDATE services
        SET title = ?, description = ?, category = ?, price = ?
        WHERE service_id = ? AND provider_id = ?
    """, (title, description, category, price, service_id, user[0]))
    connection.commit()
    connection.close()

    _record_activity("User", user[0], "SERVICE_UPDATED", f"Updated service listing '{title}'.", "Service", service_id)

    messagebox.showinfo("Service updated", "Your service details have been updated.")
    show_my_services_screen(user)


def show_edit_service_screen(user, service):
    global edit_service_title_entry, edit_service_description_text
    global edit_service_category_var, edit_service_price_entry

    service_id, title, description, category, price = service
    clear_window()

    tk.Label(app, text="Edit Service", font=("Segoe UI", 25, "bold"), bg=BG_COLOR, fg=PRIMARY_COLOR).pack(pady=(35, 15))
    card = tk.Frame(app, bg="white", padx=35, pady=25)
    card.pack()

    tk.Label(card, text="Service Title", bg="white").grid(row=0, column=0, sticky="w", pady=5)
    edit_service_title_entry = tk.Entry(card, width=45, font=("Segoe UI", 10))
    edit_service_title_entry.grid(row=1, column=0, pady=(0, 10))
    edit_service_title_entry.insert(0, title)

    tk.Label(card, text="Description", bg="white").grid(row=2, column=0, sticky="w", pady=5)
    edit_service_description_text = tk.Text(card, width=44, height=6, font=("Segoe UI", 10))
    edit_service_description_text.grid(row=3, column=0, pady=(0, 10))
    edit_service_description_text.insert("1.0", description)

    tk.Label(card, text="Category", bg="white").grid(row=4, column=0, sticky="w", pady=5)
    edit_service_category_var = tk.StringVar(value=category)
    ttk.Combobox(card, textvariable=edit_service_category_var, values=["Programming", "Graphic Design", "Writing", "Tutoring", "Photography", "Video Editing", "Social Media", "Other"], state="readonly", width=42).grid(row=5, column=0, pady=(0, 10))

    tk.Label(card, text="Price (₹)", bg="white").grid(row=6, column=0, sticky="w", pady=5)
    edit_service_price_entry = tk.Entry(card, width=45, font=("Segoe UI", 10))
    edit_service_price_entry.grid(row=7, column=0, pady=(0, 15))
    edit_service_price_entry.insert(0, str(price))

    buttons = tk.Frame(card, bg="white")
    buttons.grid(row=8, column=0)
    tk.Button(buttons, text="Save Changes", command=lambda: update_service(user, service_id), bg=PRIMARY_COLOR, fg="white", font=("Segoe UI", 10, "bold"), relief="flat", width=16, pady=8).pack(side="left", padx=(0, 10))
    tk.Button(buttons, text="Cancel", command=lambda: show_my_services_screen(user), bg="#E2E8F0", fg=TEXT_COLOR, font=("Segoe UI", 10, "bold"), relief="flat", width=12, pady=8).pack(side="left")


def show_my_services_screen(user):
    provider_id, username, user_type = user
    clear_window()

    tk.Label(app, text="My Services", font=("Segoe UI", 25, "bold"), bg=BG_COLOR, fg=PRIMARY_COLOR).pack(pady=(30, 15))

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT service_id, title, description, category, price
        FROM services WHERE provider_id = ? ORDER BY service_id DESC
    """, (provider_id,))
    services = cursor.fetchall()
    connection.close()

    content = tk.Frame(app, bg=BG_COLOR)
    content.pack(fill="both", expand=True, padx=130)

    if not services:
        tk.Label(content, text="You have not added any services yet.", font=("Segoe UI", 12), bg=BG_COLOR, fg="#64748B").pack(pady=35)

    for service in services:
        service_id, title, description, category, price = service
        card = tk.Frame(content, bg="white", padx=20, pady=15)
        card.pack(fill="x", pady=7)
        tk.Label(card, text=title, font=("Segoe UI", 14, "bold"), bg="white", fg=TEXT_COLOR).pack(anchor="w")
        tk.Label(card, text=f"{category}  •  ₹{price:.2f}", font=("Segoe UI", 10, "bold"), bg="white", fg=PRIMARY_COLOR).pack(anchor="w", pady=(4, 6))
        tk.Label(card, text=description, font=("Segoe UI", 10), bg="white", fg="#64748B", wraplength=650, justify="left").pack(anchor="w")
        actions = tk.Frame(card, bg="white")
        actions.pack(anchor="e", pady=(8, 0))
        tk.Button(actions, text="Edit", command=lambda item=service: show_edit_service_screen(user, item), bg=PRIMARY_COLOR, fg="white", relief="flat", padx=12).pack(side="left", padx=(0, 8))
        tk.Button(actions, text="Delete", command=lambda sid=service_id: delete_service(user, sid), bg="#DC2626", fg="white", relief="flat", padx=12).pack(side="left")

    actions = tk.Frame(app, bg=BG_COLOR)
    actions.pack(pady=15)
    tk.Button(actions, text="Add New Service", command=lambda: show_add_service_screen(user), bg=PRIMARY_COLOR, fg="white", relief="flat", padx=14, pady=6).pack(side="left", padx=(0, 10))
    tk.Button(actions, text="Back to Dashboard", command=lambda: show_logged_in_screen(user), bg="#E2E8F0", fg=TEXT_COLOR, relief="flat", padx=14, pady=6).pack(side="left")


def show_feature_message(feature_name):
    messagebox.showinfo(
        "CampusGig",
        f"{feature_name} will be developed in the next steps."
    )


def get_dashboard_counts(user_id, user_type):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM services
        WHERE provider_id = ?
    """, (user_id,))
    service_count = cursor.fetchone()[0]

    if user_type == "Provider":
        cursor.execute("""
            SELECT COUNT(*)
            FROM service_requests
            WHERE provider_id = ? AND request_status = 'Pending'
        """, (user_id,))
    else:
        cursor.execute("""
            SELECT COUNT(*)
            FROM service_requests
            WHERE customer_id = ? AND request_status = 'Pending'
        """, (user_id,))

    pending_requests = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM service_requests
        WHERE (provider_id = ? OR customer_id = ?)
        AND request_status = 'Completed'
    """, (user_id, user_id))
    completed_count = cursor.fetchone()[0]

    connection.close()

    return service_count, pending_requests, completed_count


def create_stat_card(parent, title, value, color):
    card = tk.Frame(
        parent, bg="white", width=250, height=104, padx=20, pady=15,
        highlightbackground="#E2E8F0", highlightthickness=1
    )
    card.pack_propagate(False)

    tk.Label(
        card,
        text=title,
        font=("Segoe UI", 11),
        bg="white",
        fg="#64748B"
    ).pack(anchor="w")

    tk.Label(
        card,
        text=str(value),
        font=("Segoe UI", 24, "bold"),
        bg="white",
        fg=color
    ).pack(anchor="w", pady=(5, 0))

    return card


def show_logged_in_screen(user):
    clear_window()

    user_id, username, user_type = user
    service_count, pending_requests, completed_count = get_dashboard_counts(
        user_id,
        user_type
    )

    top_bar = tk.Frame(app, bg=PRIMARY_COLOR, height=80)
    top_bar.pack(fill="x")
    top_bar.pack_propagate(False)

    tk.Label(
        top_bar,
        text="CampusGig",
        font=("Segoe UI", 22, "bold"),
        bg=PRIMARY_COLOR,
        fg="white"
    ).pack(side="left", padx=35, pady=22)

    tk.Button(
        top_bar,
        text="Logout",
        command=lambda: logout_user(user),
        bg="white",
        fg=PRIMARY_COLOR,
        font=("Segoe UI", 10, "bold"),
        relief="flat",
        padx=15,
        pady=6
    ).pack(side="right", padx=35, pady=20)

    content = tk.Frame(app, bg=BG_COLOR, padx=45, pady=35)
    content.pack(fill="both", expand=True)

    tk.Label(
        content,
        text=f"Hello, {username}!",
        font=("Segoe UI", 25, "bold"),
        bg=BG_COLOR,
        fg=TEXT_COLOR
    ).pack(anchor="w")

    tk.Label(
        content,
        text=f"Account type: {user_type}",
        font=("Segoe UI", 12),
        bg=BG_COLOR,
        fg="#64748B"
    ).pack(anchor="w", pady=(5, 25))

    stats_frame = tk.Frame(content, bg=BG_COLOR)
    stats_frame.pack(fill="x", pady=(0, 30))

    if user_type == "Provider":
        first_title = "My Services"
    else:
        first_title = "Services Offered"

    create_stat_card(
        stats_frame,
        first_title,
        service_count,
        PRIMARY_COLOR
    ).pack(side="left", padx=(0, 20))

    create_stat_card(
        stats_frame,
        "Pending Requests",
        pending_requests,
        "#F59E0B"
    ).pack(side="left", padx=(0, 20))

    create_stat_card(
        stats_frame,
        "Completed Services",
        completed_count,
        "#16A34A"
    ).pack(side="left")

    tk.Label(
        content,
        text="Quick Actions",
        font=("Segoe UI", 18, "bold"),
        bg=BG_COLOR,
        fg=TEXT_COLOR
    ).pack(anchor="w", pady=(5, 15))

    actions_frame = tk.Frame(content, bg=BG_COLOR)
    actions_frame.pack(anchor="w")

    button_style = {
        "font": ("Segoe UI", 11, "bold"),
        "bg": "white",
        "fg": TEXT_COLOR,
        "width": 20,
        "height": 2,
        "relief": "flat",
        "cursor": "hand2"
    }

    tk.Button(
    actions_frame,
    text="My Profile",
    command=lambda: show_profile_screen(user),
    **button_style
).grid(row=0, column=0, padx=(0, 15), pady=8)

    if user_type == "Provider":
        tk.Button(
            actions_frame,
            text="Add New Service",
         command=lambda: show_add_service_screen(user),
            **button_style
        ).grid(row=0, column=1, padx=(0, 15), pady=8)

        tk.Button(
            actions_frame,
            text="Received Requests",
            command=lambda: show_received_requests_screen(user),
            **button_style
        ).grid(row=0, column=2, pady=8)

        tk.Button(
            actions_frame,
            text="My Services",
            command=lambda: show_my_services_screen(user),
            **button_style
        ).grid(row=2, column=0, padx=(0, 15), pady=8)

        tk.Button(
            actions_frame,
            text="My Earnings",
            command=lambda: show_provider_earnings_screen(user),
            **button_style
        ).grid(row=2, column=1, padx=(0, 15), pady=8)

    tk.Button(
        actions_frame,
        text="Browse Services",
        command=lambda: show_browse_services_screen(user),
        **button_style
    ).grid(row=1, column=0, padx=(0, 15), pady=8)

    tk.Button(
        actions_frame,
        text="My Requests",
        command=lambda: show_my_requests_screen(user),
        **button_style
    ).grid(row=1, column=1, padx=(0, 15), pady=8)

    tk.Button(
        actions_frame,
        text="Ratings & Reviews",
        command=lambda: show_reviews_screen(user),
        **button_style
    ).grid(row=1, column=2, pady=8)
def show_admin_users_screen():
    global admin_user_tree, admin_user_search_var
    global admin_user_role_var, admin_user_status_var
    global admin_user_info_text, admin_user_detail_trees

    if not _admin_session_is_valid():
        return
    clear_window()

    shell = tk.Frame(app, bg=BG_COLOR)
    shell.pack(fill="both", expand=True)
    sidebar = tk.Frame(shell, bg="#0F172A", width=185)
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)
    tk.Label(
        sidebar,
        text="CampusGig\nADMIN",
        font=("Segoe UI", 17, "bold"),
        bg="#0F172A",
        fg="white",
        justify="left"
    ).pack(anchor="w", padx=18, pady=(22, 8))
    tk.Label(
        sidebar,
        text=current_admin[1],
        font=("Segoe UI", 9),
        bg="#0F172A",
        fg="#CBD5E1"
    ).pack(anchor="w", padx=18, pady=(0, 16))

    navigation = [
        "Dashboard", "Users", "Services", "Requests", "Submissions",
        "Payments", "Payouts", "Reviews", "Activity Log", "Reports", "Settings"
    ]
    for section in navigation:
        if section == "Dashboard":
            command = show_admin_home
        elif section == "Users":
            command = show_admin_users_screen
        elif section == "Services":
            command = show_admin_services_screen
        elif section == "Requests":
            command = show_admin_requests_screen
        elif section == "Submissions":
            command = show_admin_submissions_screen
        elif section == "Reviews":
            command = show_admin_reviews_screen
        elif section == "Activity Log":
            command = show_admin_activity_screen
        elif section == "Reports":
            command = show_admin_reports_screen
        elif section == "Settings":
            command = show_admin_settings_screen
        elif section == "Payments":
            command = show_admin_payments_screen
        elif section == "Payouts":
            command = show_admin_payouts_screen
        else:
            command = lambda name=section: show_admin_placeholder(name)
        tk.Button(
            sidebar,
            text=section,
            command=command,
            anchor="w",
            bg="#1E293B" if section == "Services" else "#0F172A",
            fg="white",
            activebackground="#334155",
            activeforeground="white",
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            padx=18,
            pady=7
        ).pack(fill="x")
    tk.Button(
        sidebar,
        text="Admin Logout",
        command=admin_logout,
        anchor="w",
        bg="#7F1D1D",
        fg="white",
        activebackground="#991B1B",
        activeforeground="white",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=18,
        pady=8
    ).pack(side="bottom", fill="x", pady=12)

    main_area = tk.Frame(shell, bg=BG_COLOR)
    main_area.pack(side="left", fill="both", expand=True)
    header = tk.Frame(main_area, bg="white", padx=18, pady=10)
    header.pack(fill="x")
    tk.Label(
        header,
        text="User Management",
        font=("Segoe UI", 18, "bold"),
        bg="white",
        fg=TEXT_COLOR
    ).pack(anchor="w")
    tk.Label(
        header,
        text="Search accounts, inspect their platform records, and control account access.",
        font=("Segoe UI", 9),
        bg="white",
        fg="#64748B"
    ).pack(anchor="w", pady=(2, 0))

    filters = tk.Frame(main_area, bg=BG_COLOR, padx=12, pady=8)
    filters.pack(fill="x")
    admin_user_search_var = tk.StringVar()
    admin_user_role_var = tk.StringVar(value="All roles")
    admin_user_status_var = tk.StringVar(value="All statuses")
    tk.Entry(
        filters,
        textvariable=admin_user_search_var,
        width=27,
        font=("Segoe UI", 9)
    ).pack(side="left", padx=(0, 7))
    ttk.Combobox(
        filters,
        textvariable=admin_user_role_var,
        values=["All roles", "Customer", "Provider"],
        state="readonly",
        width=12
    ).pack(side="left", padx=(0, 7))
    ttk.Combobox(
        filters,
        textvariable=admin_user_status_var,
        values=["All statuses", "Active", "Suspended", "Deactivated"],
        state="readonly",
        width=14
    ).pack(side="left", padx=(0, 7))
    tk.Button(
        filters,
        text="Search / Filter",
        command=load_admin_users,
        bg=PRIMARY_COLOR,
        fg="white",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=10,
        pady=4
    ).pack(side="left")

    user_list_frame = tk.Frame(main_area, bg=BG_COLOR, padx=12)
    user_list_frame.pack(fill="x")
    user_columns = ("username", "role", "status", "email", "registered")
    admin_user_tree = ttk.Treeview(
        user_list_frame,
        columns=user_columns,
        show="headings",
        height=7,
        selectmode="browse"
    )
    for column, heading, width in [
        ("username", "Username", 115),
        ("role", "Role", 80),
        ("status", "Status", 85),
        ("email", "Email", 190),
        ("registered", "Registered", 125),
    ]:
        admin_user_tree.heading(column, text=heading)
        admin_user_tree.column(column, width=width, anchor="w")
    user_scroll = ttk.Scrollbar(
        user_list_frame,
        orient="vertical",
        command=admin_user_tree.yview
    )
    admin_user_tree.configure(yscrollcommand=user_scroll.set)
    admin_user_tree.pack(side="left", fill="x", expand=True)
    user_scroll.pack(side="right", fill="y")
    admin_user_tree.bind("<<TreeviewSelect>>", show_admin_user_details)

    details = ttk.Notebook(main_area)
    details.pack(fill="both", expand=True, padx=12, pady=(6, 4))
    info_tab = tk.Frame(details, bg="white")
    admin_user_info_text = tk.Text(
        info_tab,
        height=6,
        wrap="word",
        relief="flat",
        font=("Segoe UI", 9),
        padx=10,
        pady=8
    )
    admin_user_info_text.pack(fill="both", expand=True)
    admin_user_info_text.insert("1.0", "Select a user above to view their profile and account summary.")
    admin_user_info_text.configure(state="disabled")
    details.add(info_tab, text="Profile")

    admin_user_detail_trees = {}
    detail_tabs = [
        ("Services", ("ID", "Title", "Category", "Price", "Status", "Created")),
        ("Requests", ("ID", "Role", "Service", "Customer", "Provider", "Status", "Date")),
        ("Transactions", ("ID", "Reference", "Gross", "Commission", "Provider net", "Payment", "Payout")),
        ("Reviews", ("Rating", "Direction", "Reviewer", "Provider", "Comment", "Date")),
        ("Activity", ("Kind", "Action", "Description", "Date")),
    ]
    for tab_name, columns in detail_tabs:
        tab = tk.Frame(details, bg="white")
        tree = ttk.Treeview(tab, columns=columns, show="headings", height=5)
        for column in columns:
            tree.heading(column, text=column)
            tree.column(column, width=max(82, min(145, len(column) * 10)), anchor="w")
        tree.pack(fill="both", expand=True)
        details.add(tab, text=tab_name)
        admin_user_detail_trees[tab_name] = tree

    actions = tk.Frame(main_area, bg=BG_COLOR, padx=12, pady=7)
    actions.pack(fill="x")
    for title, status, color in [
        ("Activate", "Active", "#16A34A"),
        ("Suspend", "Suspended", "#F59E0B"),
        ("Deactivate", "Deactivated", "#64748B"),
    ]:
        tk.Button(
            actions,
            text=title,
            command=lambda value=status: set_admin_user_status(value),
            bg=color,
            fg="white",
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=5
        ).pack(side="left", padx=(0, 7))
    tk.Button(
        actions,
        text="Delete unused account",
        command=delete_admin_user,
        bg="#DC2626",
        fg="white",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=12,
        pady=5
    ).pack(side="left")

    load_admin_users()


def load_admin_users():
    global admin_user_tree
    if not _admin_session_is_valid():
        return

    search_text = admin_user_search_var.get().strip()
    role = admin_user_role_var.get()
    status = admin_user_status_var.get()
    query = """
        SELECT users.user_id, users.username, users.user_type,
               users.account_status, users.email, users.created_at
        FROM users
        LEFT JOIN profiles ON users.user_id = profiles.user_id
        WHERE 1 = 1
    """
    values = []
    if search_text:
        query += " AND (users.username LIKE ? OR users.email LIKE ? OR profiles.full_name LIKE ? OR profiles.phone LIKE ?)"
        values.extend([f"%{search_text}%"] * 4)
    if role != "All roles":
        query += " AND users.user_type = ?"
        values.append(role)
    if status != "All statuses":
        query += " AND users.account_status = ?"
        values.append(status)
    query += " ORDER BY users.user_id DESC"

    connection = get_connection()
    try:
        rows = connection.execute(query, values).fetchall()
    finally:
        connection.close()

    for item in admin_user_tree.get_children():
        admin_user_tree.delete(item)
    for user_id, username, role, status, email, created_at in rows:
        admin_user_tree.insert(
            "",
            "end",
            iid=str(user_id),
            values=(username, role, status, email, created_at or ""),
        )


def show_admin_user_details(_event=None):
    global admin_user_info_text
    if not _admin_session_is_valid():
        return
    selection = admin_user_tree.selection()
    if not selection:
        return
    user_id = int(selection[0])

    connection = get_connection()
    try:
        user = connection.execute("""
            SELECT users.username, users.user_type, users.account_status,
                   users.email, users.created_at, profiles.full_name,
                   profiles.phone, profiles.college, profiles.bio
            FROM users
            LEFT JOIN profiles ON users.user_id = profiles.user_id
            WHERE users.user_id = ?
        """, (user_id,)).fetchone()
        if user is None:
            return

        counts = {
            "Services created": connection.execute(
                "SELECT COUNT(*) FROM services WHERE provider_id = ?", (user_id,)
            ).fetchone()[0],
            "Requests as customer": connection.execute(
                "SELECT COUNT(*) FROM service_requests WHERE customer_id = ?", (user_id,)
            ).fetchone()[0],
            "Requests as provider": connection.execute(
                "SELECT COUNT(*) FROM service_requests WHERE provider_id = ?", (user_id,)
            ).fetchone()[0],
            "Transactions": connection.execute(
                "SELECT COUNT(*) FROM payments WHERE customer_id = ? OR provider_id = ?",
                (user_id, user_id),
            ).fetchone()[0],
            "Reviews written / received": connection.execute(
                "SELECT COUNT(*) FROM reviews WHERE reviewer_id = ? OR provider_id = ?",
                (user_id, user_id),
            ).fetchone()[0],
        }
        services = connection.execute("""
            SELECT service_id, title, category, price, status, created_at
            FROM services WHERE provider_id = ? ORDER BY service_id DESC LIMIT 100
        """, (user_id,)).fetchall()
        requests = connection.execute("""
            SELECT service_requests.request_id,
                   CASE WHEN service_requests.customer_id = ? THEN 'Customer' ELSE 'Provider' END,
                   services.title, customer.username, provider.username,
                   service_requests.request_status, service_requests.requested_at
            FROM service_requests
            JOIN services ON service_requests.service_id = services.service_id
            JOIN users AS customer ON service_requests.customer_id = customer.user_id
            JOIN users AS provider ON service_requests.provider_id = provider.user_id
            WHERE service_requests.customer_id = ? OR service_requests.provider_id = ?
            ORDER BY service_requests.request_id DESC LIMIT 100
        """, (user_id, user_id, user_id)).fetchall()
        transactions = connection.execute("""
            SELECT payments.payment_id, payments.transaction_reference,
                   payments.gross_amount, payments.commission_amount,
                   payments.provider_amount, payments.payment_status,
                   COALESCE(provider_payouts.payout_status, 'Not created')
            FROM payments
            LEFT JOIN provider_payouts ON payments.payment_id = provider_payouts.payment_id
            WHERE payments.customer_id = ? OR payments.provider_id = ?
            ORDER BY payments.payment_id DESC LIMIT 100
        """, (user_id, user_id)).fetchall()
        reviews = connection.execute("""
            SELECT reviews.rating,
                   CASE WHEN reviews.reviewer_id = ? THEN 'Written' ELSE 'Received' END,
                   reviewer.username, provider.username, reviews.review_text,
                   reviews.created_at
            FROM reviews
            JOIN users AS reviewer ON reviews.reviewer_id = reviewer.user_id
            JOIN users AS provider ON reviews.provider_id = provider.user_id
            WHERE reviews.reviewer_id = ? OR reviews.provider_id = ?
            ORDER BY reviews.review_id DESC LIMIT 100
        """, (user_id, user_id, user_id)).fetchall()
        activity = connection.execute("""
            SELECT actor_type, action, description, created_at
            FROM activity_logs
            WHERE actor_type = 'User' AND actor_id = ?
            ORDER BY activity_id DESC LIMIT 100
        """, (user_id,)).fetchall()
    finally:
        connection.close()

    username, role, status, email, registered, full_name, phone, college, bio = user
    information = [
        f"User ID: {user_id}    Username: {username}    Type: {role}    Status: {status}",
        f"Full name: {full_name or 'Not provided'}    Email: {email}",
        f"Phone: {phone or 'Not provided'}    College: {college or 'Not provided'}",
        f"Registered: {registered or 'Unknown'}",
        f"Bio: {bio or 'Not provided'}",
        "    |    ".join(f"{label}: {count}" for label, count in counts.items()),
    ]
    admin_user_info_text.configure(state="normal")
    admin_user_info_text.delete("1.0", tk.END)
    admin_user_info_text.insert("1.0", "\n".join(information))
    admin_user_info_text.configure(state="disabled")

    tab_rows = {
        "Services": services,
        "Requests": requests,
        "Transactions": transactions,
        "Reviews": reviews,
        "Activity": activity,
    }
    for tab_name, rows in tab_rows.items():
        tree = admin_user_detail_trees[tab_name]
        tree.delete(*tree.get_children())
        for row in rows:
            tree.insert("", "end", values=row)


def set_admin_user_status(new_status):
    if not _admin_session_is_valid():
        return
    if new_status not in {"Active", "Suspended", "Deactivated"}:
        messagebox.showerror("Invalid status", "That account status is not allowed.")
        return
    selection = admin_user_tree.selection()
    if not selection:
        messagebox.showwarning("Select a user", "Select a user row first.")
        return
    user_id = int(selection[0])
    username = admin_user_tree.item(selection[0], "values")[0]
    if not messagebox.askyesno(
        f"Confirm {new_status.lower()}",
        f"Set {username}'s account status to {new_status}?"
    ):
        return

    connection = get_connection()
    try:
        connection.execute(
            "UPDATE users SET account_status = ? WHERE user_id = ?",
            (new_status, user_id),
        )
        connection.execute("""
            INSERT INTO activity_logs (actor_type, actor_id, action, description, related_type, related_id)
            VALUES ('Admin', ?, 'USER_STATUS_CHANGED', ?, 'User', ?)
        """, (current_admin[0], f"Set {username} account status to {new_status}.", user_id))
        connection.commit()
    finally:
        connection.close()
    load_admin_users()
    if str(user_id) in admin_user_tree.get_children():
        admin_user_tree.selection_set(str(user_id))
        admin_user_tree.focus(str(user_id))
        show_admin_user_details()
    messagebox.showinfo("Account updated", f"{username}'s status is now {new_status}.")


def delete_admin_user():
    if not _admin_session_is_valid():
        return
    selection = admin_user_tree.selection()
    if not selection:
        messagebox.showwarning("Select a user", "Select a user row first.")
        return
    user_id = int(selection[0])
    username = admin_user_tree.item(selection[0], "values")[0]

    connection = get_connection()
    try:
        linked_records = sum([
            connection.execute("SELECT COUNT(*) FROM services WHERE provider_id = ?", (user_id,)).fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM service_requests WHERE customer_id = ? OR provider_id = ?", (user_id, user_id)).fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM reviews WHERE reviewer_id = ? OR provider_id = ?", (user_id, user_id)).fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM payments WHERE customer_id = ? OR provider_id = ?", (user_id, user_id)).fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM provider_payouts WHERE provider_id = ?", (user_id,)).fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM project_submissions WHERE provider_id = ?", (user_id,)).fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM activity_logs WHERE actor_type = 'User' AND actor_id = ?", (user_id,)).fetchone()[0],
        ])
        if linked_records:
            messagebox.showwarning(
                "Account has platform records",
                "This account is linked to services, requests, reviews, submissions, or transactions. "
                "Suspend or deactivate it to preserve its history."
            )
            return
        if not messagebox.askyesno(
            "Permanently delete unused account?",
            f"Delete {username}'s account and profile permanently? This cannot be undone."
        ):
            return
        connection.execute("""
            INSERT INTO activity_logs (actor_type, actor_id, action, description, related_type, related_id)
            VALUES ('Admin', ?, 'USER_DELETED', ?, 'User', ?)
        """, (current_admin[0], f"Deleted unused account {username}.", user_id))
        connection.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
        connection.commit()
    finally:
        connection.close()

    load_admin_users()
    admin_user_info_text.configure(state="normal")
    admin_user_info_text.delete("1.0", tk.END)
    admin_user_info_text.insert("1.0", "Select a user above to view their profile and account summary.")
    admin_user_info_text.configure(state="disabled")
    for tree in admin_user_detail_trees.values():
        tree.delete(*tree.get_children())
    messagebox.showinfo("Account deleted", f"Unused account {username} was deleted.")


def show_admin_services_screen():
    global admin_service_tree, admin_service_search_var
    global admin_service_category_var, admin_service_status_var
    global admin_service_info_text

    if not _admin_session_is_valid():
        return
    clear_window()

    shell = tk.Frame(app, bg=BG_COLOR)
    shell.pack(fill="both", expand=True)
    sidebar = tk.Frame(shell, bg="#0F172A", width=185)
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)
    tk.Label(
        sidebar,
        text="CampusGig\nADMIN",
        font=("Segoe UI", 17, "bold"),
        bg="#0F172A",
        fg="white",
        justify="left"
    ).pack(anchor="w", padx=18, pady=(22, 8))
    tk.Label(
        sidebar,
        text=current_admin[1],
        font=("Segoe UI", 9),
        bg="#0F172A",
        fg="#CBD5E1"
    ).pack(anchor="w", padx=18, pady=(0, 16))

    navigation = [
        "Dashboard", "Users", "Services", "Requests", "Submissions",
        "Payments", "Payouts", "Reviews", "Activity Log", "Reports", "Settings"
    ]
    for section in navigation:
        if section == "Dashboard":
            command = show_admin_home
        elif section == "Users":
            command = show_admin_users_screen
        elif section == "Services":
            command = show_admin_services_screen
        elif section == "Requests":
            command = show_admin_requests_screen
        elif section == "Submissions":
            command = show_admin_submissions_screen
        elif section == "Reviews":
            command = show_admin_reviews_screen
        elif section == "Activity Log":
            command = show_admin_activity_screen
        elif section == "Reports":
            command = show_admin_reports_screen
        elif section == "Settings":
            command = show_admin_settings_screen
        elif section == "Payments":
            command = show_admin_payments_screen
        elif section == "Payouts":
            command = show_admin_payouts_screen
        else:
            command = lambda name=section: show_admin_placeholder(name)
        tk.Button(
            sidebar,
            text=section,
            command=command,
            anchor="w",
            bg="#1E293B" if section == "Services" else "#0F172A",
            fg="white",
            activebackground="#334155",
            activeforeground="white",
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            padx=18,
            pady=7
        ).pack(fill="x")
    tk.Button(
        sidebar,
        text="Admin Logout",
        command=admin_logout,
        anchor="w",
        bg="#7F1D1D",
        fg="white",
        activebackground="#991B1B",
        activeforeground="white",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=18,
        pady=8
    ).pack(side="bottom", fill="x", pady=12)

    main_area = tk.Frame(shell, bg=BG_COLOR)
    main_area.pack(side="left", fill="both", expand=True)
    header = tk.Frame(main_area, bg="white", padx=18, pady=10)
    header.pack(fill="x")
    tk.Label(
        header,
        text="Service Management",
        font=("Segoe UI", 18, "bold"),
        bg="white",
        fg=TEXT_COLOR
    ).pack(anchor="w")
    tk.Label(
        header,
        text="Review listings, inspect provider and request activity, and moderate availability.",
        font=("Segoe UI", 9),
        bg="white",
        fg="#64748B"
    ).pack(anchor="w", pady=(2, 0))

    filters = tk.Frame(main_area, bg=BG_COLOR, padx=12, pady=8)
    filters.pack(fill="x")
    admin_service_search_var = tk.StringVar()
    admin_service_category_var = tk.StringVar(value="All categories")
    admin_service_status_var = tk.StringVar(value="All statuses")
    tk.Entry(
        filters,
        textvariable=admin_service_search_var,
        width=22,
        font=("Segoe UI", 9)
    ).pack(side="left", padx=(0, 6))
    ttk.Combobox(
        filters,
        textvariable=admin_service_category_var,
        values=[
            "All categories", "Programming", "Graphic Design", "Writing",
            "Tutoring", "Photography", "Video Editing", "Social Media", "Other"
        ],
        state="readonly",
        width=16
    ).pack(side="left", padx=(0, 6))
    ttk.Combobox(
        filters,
        textvariable=admin_service_status_var,
        values=["All statuses", "Available", "Inactive"],
        state="readonly",
        width=13
    ).pack(side="left", padx=(0, 6))
    tk.Button(
        filters,
        text="Search / Filter",
        command=load_admin_services,
        bg=PRIMARY_COLOR,
        fg="white",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=9,
        pady=4
    ).pack(side="left")

    service_list = tk.Frame(main_area, bg=BG_COLOR, padx=12)
    service_list.pack(fill="x")
    columns = ("title", "category", "provider", "price", "status", "requests", "rating")
    admin_service_tree = ttk.Treeview(
        service_list,
        columns=columns,
        show="headings",
        height=9,
        selectmode="browse"
    )
    for column, heading, width in [
        ("title", "Service", 145),
        ("category", "Category", 100),
        ("provider", "Provider", 100),
        ("price", "Price", 70),
        ("status", "Status", 80),
        ("requests", "Requests", 65),
        ("rating", "Rating", 65),
    ]:
        admin_service_tree.heading(column, text=heading)
        admin_service_tree.column(column, width=width, anchor="w")
    service_scroll = ttk.Scrollbar(
        service_list,
        orient="vertical",
        command=admin_service_tree.yview
    )
    admin_service_tree.configure(yscrollcommand=service_scroll.set)
    admin_service_tree.pack(side="left", fill="x", expand=True)
    service_scroll.pack(side="right", fill="y")
    admin_service_tree.bind("<<TreeviewSelect>>", show_admin_service_details)

    detail_frame = tk.Frame(main_area, bg="white", padx=12, pady=7)
    detail_frame.pack(fill="both", expand=True, padx=12, pady=(5, 3))
    admin_service_info_text = tk.Text(
        detail_frame,
        height=6,
        wrap="word",
        relief="flat",
        font=("Segoe UI", 9),
        padx=5,
        pady=4
    )
    admin_service_info_text.pack(fill="both", expand=True)
    admin_service_info_text.insert("1.0", "Select a service above to inspect its details and activity.")
    admin_service_info_text.configure(state="disabled")

    actions = tk.Frame(main_area, bg=BG_COLOR, padx=12, pady=7)
    actions.pack(fill="x")
    tk.Button(
        actions,
        text="Edit Service",
        command=open_admin_service_editor,
        bg=PRIMARY_COLOR,
        fg="white",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=12,
        pady=5
    ).pack(side="left", padx=(0, 7))
    for title, status, color in [
        ("Activate", "Available", "#16A34A"),
        ("Deactivate", "Inactive", "#F59E0B"),
    ]:
        tk.Button(
            actions,
            text=title,
            command=lambda value=status: set_admin_service_status(value),
            bg=color,
            fg="white",
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=5
        ).pack(side="left", padx=(0, 7))
    tk.Button(
        actions,
        text="Delete unused service",
        command=delete_admin_service,
        bg="#DC2626",
        fg="white",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=12,
        pady=5
    ).pack(side="left")

    load_admin_services()


def load_admin_services():
    if not _admin_session_is_valid():
        return
    search_text = admin_service_search_var.get().strip()
    category = admin_service_category_var.get()
    status = admin_service_status_var.get()
    query = """
        SELECT services.service_id, services.title, services.category,
               COALESCE(NULLIF(profiles.full_name, ''), users.username),
               services.price, services.status,
               (SELECT COUNT(*) FROM service_requests
                WHERE service_requests.service_id = services.service_id),
               COALESCE((SELECT ROUND(AVG(reviews.rating), 1)
                         FROM reviews JOIN service_requests AS rated_request
                           ON reviews.request_id = rated_request.request_id
                         WHERE rated_request.service_id = services.service_id
                           AND reviews.moderation_status = 'Visible'), 0)
        FROM services
        JOIN users ON services.provider_id = users.user_id
        LEFT JOIN profiles ON users.user_id = profiles.user_id
        WHERE 1 = 1
    """
    values = []
    if search_text:
        query += " AND (services.title LIKE ? OR services.description LIKE ? OR services.category LIKE ? OR users.username LIKE ? OR profiles.full_name LIKE ?)"
        values.extend([f"%{search_text}%"] * 5)
    if category != "All categories":
        query += " AND services.category = ?"
        values.append(category)
    if status != "All statuses":
        query += " AND services.status = ?"
        values.append(status)
    query += " ORDER BY services.service_id DESC"

    connection = get_connection()
    try:
        rows = connection.execute(query, values).fetchall()
    finally:
        connection.close()
    for item in admin_service_tree.get_children():
        admin_service_tree.delete(item)
    for service_id, title, category, provider, price, status, requests, rating in rows:
        admin_service_tree.insert(
            "",
            "end",
            iid=str(service_id),
            values=(title, category, provider, f"₹{price:.2f}", status, requests, rating),
        )


def show_admin_service_details(_event=None):
    if not _admin_session_is_valid():
        return
    selection = admin_service_tree.selection()
    if not selection:
        return
    service_id = int(selection[0])
    connection = get_connection()
    try:
        service = connection.execute("""
            SELECT services.title, services.description, services.category,
                   services.price, services.status, services.created_at,
                   users.username, profiles.full_name, profiles.college,
                   (SELECT COUNT(*) FROM service_requests
                    WHERE service_requests.service_id = services.service_id),
                   (SELECT COUNT(*) FROM service_requests
                    WHERE service_requests.service_id = services.service_id
                      AND service_requests.request_status = 'Completed'),
                   (SELECT ROUND(AVG(reviews.rating), 1)
                    FROM reviews JOIN service_requests AS rated_request
                      ON reviews.request_id = rated_request.request_id
                    WHERE rated_request.service_id = services.service_id
                      AND reviews.moderation_status = 'Visible')
            FROM services
            JOIN users ON services.provider_id = users.user_id
            LEFT JOIN profiles ON users.user_id = profiles.user_id
            WHERE services.service_id = ?
        """, (service_id,)).fetchone()
    finally:
        connection.close()
    if service is None:
        return

    (title, description, category, price, status, created_at, username,
     full_name, college, request_count, completed_count, average_rating) = service
    details = (
        f"Service ID: {service_id}    Title: {title}    Category: {category}    Status: {status}\n"
        f"Provider: {full_name or username} (@{username})    College: {college or 'Not provided'}\n"
        f"Price: ₹{price:.2f}    Created: {created_at or 'Unknown'}    Requests: {request_count}    "
        f"Completed: {completed_count}    Average rating: {average_rating or 'No ratings'}\n\n"
        f"Description: {description}"
    )
    admin_service_info_text.configure(state="normal")
    admin_service_info_text.delete("1.0", tk.END)
    admin_service_info_text.insert("1.0", details)
    admin_service_info_text.configure(state="disabled")


def _selected_admin_service():
    selection = admin_service_tree.selection()
    if not selection:
        messagebox.showwarning("Select a service", "Select a service row first.")
        return None
    return int(selection[0])


def set_admin_service_status(new_status):
    if not _admin_session_is_valid():
        return
    if new_status not in {"Available", "Inactive"}:
        messagebox.showerror("Invalid status", "That service status is not allowed.")
        return
    service_id = _selected_admin_service()
    if service_id is None:
        return
    service_title = admin_service_tree.item(str(service_id), "values")[0]
    if not messagebox.askyesno(
        "Confirm service status",
        f"Set '{service_title}' to {new_status.lower()}?"
    ):
        return

    connection = get_connection()
    try:
        connection.execute(
            "UPDATE services SET status = ? WHERE service_id = ?",
            (new_status, service_id),
        )
        connection.execute("""
            INSERT INTO activity_logs (actor_type, actor_id, action, description, related_type, related_id)
            VALUES ('Admin', ?, 'SERVICE_STATUS_CHANGED', ?, 'Service', ?)
        """, (current_admin[0], f"Set service '{service_title}' to {new_status}.", service_id))
        connection.commit()
    finally:
        connection.close()
    load_admin_services()
    if str(service_id) in admin_service_tree.get_children():
        admin_service_tree.selection_set(str(service_id))
        admin_service_tree.focus(str(service_id))
        show_admin_service_details()
    messagebox.showinfo("Service updated", f"'{service_title}' is now {new_status.lower()}.")


def delete_admin_service():
    if not _admin_session_is_valid():
        return
    service_id = _selected_admin_service()
    if service_id is None:
        return
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT title FROM services WHERE service_id = ?", (service_id,)
        ).fetchone()
        if row is None:
            return
        service_title = row[0]
        request_count = connection.execute(
            "SELECT COUNT(*) FROM service_requests WHERE service_id = ?", (service_id,)
        ).fetchone()[0]
        if request_count:
            messagebox.showwarning(
                "Service has request history",
                "This service has requests. Deactivate it to keep its request and transaction history."
            )
            return
        if not messagebox.askyesno(
            "Permanently delete unused service?",
            f"Delete '{service_title}' permanently? This cannot be undone."
        ):
            return
        connection.execute("""
            INSERT INTO activity_logs (actor_type, actor_id, action, description, related_type, related_id)
            VALUES ('Admin', ?, 'SERVICE_DELETED', ?, 'Service', ?)
        """, (current_admin[0], f"Deleted unused service '{service_title}'.", service_id))
        connection.execute("DELETE FROM services WHERE service_id = ?", (service_id,))
        connection.commit()
    finally:
        connection.close()
    load_admin_services()
    admin_service_info_text.configure(state="normal")
    admin_service_info_text.delete("1.0", tk.END)
    admin_service_info_text.insert("1.0", "Select a service above to inspect its details and activity.")
    admin_service_info_text.configure(state="disabled")
    messagebox.showinfo("Service deleted", f"Unused service '{service_title}' was deleted.")


def open_admin_service_editor():
    if not _admin_session_is_valid():
        return
    service_id = _selected_admin_service()
    if service_id is None:
        return
    connection = get_connection()
    try:
        service = connection.execute("""
            SELECT title, description, category, price
            FROM services WHERE service_id = ?
        """, (service_id,)).fetchone()
    finally:
        connection.close()
    if service is None:
        return

    editor = tk.Toplevel(app)
    editor.title("Edit Service")
    editor.geometry("470x470")
    editor.configure(bg=BG_COLOR)
    editor.resizable(False, False)
    editor.transient(app)
    editor.grab_set()
    card = tk.Frame(editor, bg="white", padx=24, pady=20)
    card.pack(fill="both", expand=True, padx=22, pady=22)
    tk.Label(card, text="Edit service listing", font=("Segoe UI", 17, "bold"), bg="white", fg=TEXT_COLOR).pack(anchor="w", pady=(0, 12))

    tk.Label(card, text="Title", bg="white").pack(anchor="w")
    title_entry = tk.Entry(card, font=("Segoe UI", 10))
    title_entry.pack(fill="x", pady=(2, 8))
    title_entry.insert(0, service[0])

    tk.Label(card, text="Description", bg="white").pack(anchor="w")
    description_text = tk.Text(card, height=5, wrap="word", font=("Segoe UI", 10))
    description_text.pack(fill="x", pady=(2, 8))
    description_text.insert("1.0", service[1])

    tk.Label(card, text="Category", bg="white").pack(anchor="w")
    category_var = tk.StringVar(value=service[2])
    ttk.Combobox(
        card,
        textvariable=category_var,
        values=["Programming", "Graphic Design", "Writing", "Tutoring", "Photography", "Video Editing", "Social Media", "Other"],
        state="readonly"
    ).pack(fill="x", pady=(2, 8))

    tk.Label(card, text="Price (₹)", bg="white").pack(anchor="w")
    price_entry = tk.Entry(card, font=("Segoe UI", 10))
    price_entry.pack(fill="x", pady=(2, 12))
    price_entry.insert(0, str(service[3]))

    buttons = tk.Frame(card, bg="white")
    buttons.pack(anchor="e")
    tk.Button(
        buttons,
        text="Save Changes",
        command=lambda: save_admin_service_edit(
            service_id, editor, title_entry, description_text, category_var, price_entry
        ),
        bg=PRIMARY_COLOR,
        fg="white",
        relief="flat",
        padx=13,
        pady=6
    ).pack(side="left", padx=(0, 8))
    tk.Button(
        buttons,
        text="Cancel",
        command=editor.destroy,
        bg="#E2E8F0",
        fg=TEXT_COLOR,
        relief="flat",
        padx=13,
        pady=6
    ).pack(side="left")


def save_admin_service_edit(service_id, editor, title_entry, description_text, category_var, price_entry):
    if not _admin_session_is_valid():
        editor.destroy()
        return
    title = title_entry.get().strip()
    description = description_text.get("1.0", tk.END).strip()
    category = category_var.get().strip()
    price_text = price_entry.get().strip()
    if not all([title, description, category, price_text]):
        messagebox.showerror("Missing details", "Complete every service field.", parent=editor)
        return
    try:
        price = float(price_text)
        if price < 0:
            raise ValueError
    except ValueError:
        messagebox.showerror("Invalid price", "Enter a non-negative number.", parent=editor)
        return

    connection = get_connection()
    try:
        connection.execute("""
            UPDATE services
            SET title = ?, description = ?, category = ?, price = ?
            WHERE service_id = ?
        """, (title, description, category, price, service_id))
        connection.execute("""
            INSERT INTO activity_logs (actor_type, actor_id, action, description, related_type, related_id)
            VALUES ('Admin', ?, 'SERVICE_EDITED', ?, 'Service', ?)
        """, (current_admin[0], f"Edited service '{title}'.", service_id))
        connection.commit()
    finally:
        connection.close()
    editor.destroy()
    load_admin_services()
    if str(service_id) in admin_service_tree.get_children():
        admin_service_tree.selection_set(str(service_id))
        admin_service_tree.focus(str(service_id))
        show_admin_service_details()
    messagebox.showinfo("Service updated", "The listing has been updated.")


def show_admin_submissions_screen():
    global admin_submission_tree, admin_submission_detail
    global admin_submission_search_var, admin_submission_filter_var
    if not _admin_session_is_valid():
        return
    clear_window()
    shell = tk.Frame(app, bg=BG_COLOR)
    shell.pack(fill="both", expand=True)
    sidebar = tk.Frame(shell, bg="#0F172A", width=185)
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)
    tk.Label(sidebar, text="CampusGig\nADMIN", font=("Segoe UI", 17, "bold"), bg="#0F172A", fg="white", justify="left").pack(anchor="w", padx=18, pady=(22, 8))
    tk.Label(sidebar, text=current_admin[1], font=("Segoe UI", 9), bg="#0F172A", fg="#CBD5E1").pack(anchor="w", padx=18, pady=(0, 16))
    for section in ["Dashboard", "Users", "Services", "Requests", "Submissions", "Payments", "Payouts", "Reviews", "Activity Log", "Reports", "Settings"]:
        command = {
            "Dashboard": show_admin_home,
            "Users": show_admin_users_screen,
            "Services": show_admin_services_screen,
            "Requests": show_admin_requests_screen,
            "Submissions": show_admin_submissions_screen,
            "Reviews": show_admin_reviews_screen,
            "Payments": show_admin_payments_screen,
            "Payouts": show_admin_payouts_screen,
            "Activity Log": show_admin_activity_screen,
            "Reports": show_admin_reports_screen,
            "Settings": show_admin_settings_screen,
        }.get(section, lambda name=section: show_admin_placeholder(name))
        tk.Button(sidebar, text=section, command=command, anchor="w", bg="#1E293B" if section == "Submissions" else "#0F172A", fg="white", activebackground="#334155", activeforeground="white", relief="flat", font=("Segoe UI", 9, "bold"), padx=18, pady=7).pack(fill="x")
    tk.Button(sidebar, text="Admin Logout", command=admin_logout, anchor="w", bg="#7F1D1D", fg="white", relief="flat", padx=18, pady=8).pack(side="bottom", fill="x", pady=12)

    main_area = tk.Frame(shell, bg=BG_COLOR, padx=18, pady=16)
    main_area.pack(side="left", fill="both", expand=True)
    tk.Label(main_area, text="Project Submissions", font=("Segoe UI", 20, "bold"), bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
    tk.Label(main_area, text="Review uploaded filenames, request context, and customer decisions. Saving a copy does not alter the stored submission.", font=("Segoe UI", 9), bg=BG_COLOR, fg="#64748B", wraplength=760, justify="left").pack(anchor="w", pady=(3, 10))

    controls = tk.Frame(main_area, bg=BG_COLOR)
    controls.pack(fill="x", pady=(0, 8))
    admin_submission_search_var = tk.StringVar()
    admin_submission_filter_var = tk.StringVar(value="All statuses")
    tk.Label(controls, text="Search", bg=BG_COLOR, fg=TEXT_COLOR).pack(side="left")
    search_entry = tk.Entry(controls, textvariable=admin_submission_search_var, width=30)
    search_entry.pack(side="left", padx=(6, 14))
    tk.Label(controls, text="Status", bg=BG_COLOR, fg=TEXT_COLOR).pack(side="left")
    ttk.Combobox(controls, textvariable=admin_submission_filter_var, values=["All statuses", "Submitted", "Revision Requested", "Approved", "Rejected"], state="readonly", width=18).pack(side="left", padx=6)
    tk.Button(controls, text="Apply", command=load_admin_submissions, bg=PRIMARY_COLOR, fg="white", relief="flat", padx=12).pack(side="left", padx=4)
    search_entry.bind("<Return>", lambda _event: load_admin_submissions())

    table_area = tk.Frame(main_area, bg="white")
    table_area.pack(fill="both", expand=True)
    columns = ("file", "request", "customer", "provider", "version", "status", "uploaded")
    admin_submission_tree = ttk.Treeview(table_area, columns=columns, show="headings", height=9)
    for column, title, width in [
        ("file", "File", 130), ("request", "Request", 65), ("customer", "Customer", 90),
        ("provider", "Provider", 90), ("version", "Version", 60),
        ("status", "Decision", 110), ("uploaded", "Uploaded", 135),
    ]:
        admin_submission_tree.heading(column, text=title)
        admin_submission_tree.column(column, width=width, anchor="w")
    submission_scroll = ttk.Scrollbar(table_area, orient="vertical", command=admin_submission_tree.yview)
    admin_submission_tree.configure(yscrollcommand=submission_scroll.set)
    admin_submission_tree.pack(side="left", fill="both", expand=True)
    submission_scroll.pack(side="right", fill="y")
    admin_submission_tree.bind("<<TreeviewSelect>>", show_admin_submission_details)
    admin_submission_detail = tk.Text(main_area, height=6, wrap="word", font=("Consolas", 9), bg="white", fg=TEXT_COLOR, relief="flat", padx=10, pady=8, state="disabled")
    admin_submission_detail.pack(fill="x", pady=(10, 8))
    tk.Button(main_area, text="Save a Copy…", command=save_admin_submission_copy, bg=PRIMARY_COLOR, fg="white", relief="flat", padx=14, pady=6).pack(anchor="e")
    load_admin_submissions()


def load_admin_submissions():
    if not _admin_session_is_valid():
        return
    admin_submission_tree.delete(*admin_submission_tree.get_children())
    status = admin_submission_filter_var.get()
    search = f"%{admin_submission_search_var.get().strip()}%"
    connection = get_connection()
    try:
        rows = connection.execute("""
            SELECT ps.submission_id, ps.file_name, sr.request_id,
                   customer.username, provider.username, ps.revision_number,
                   ps.submission_status, ps.uploaded_at
            FROM project_submissions AS ps
            JOIN service_requests AS sr ON sr.request_id = ps.request_id
            JOIN users AS customer ON customer.user_id = sr.customer_id
            JOIN users AS provider ON provider.user_id = ps.provider_id
            WHERE (? = 'All statuses' OR ps.submission_status = ?)
              AND (ps.file_name LIKE ? OR customer.username LIKE ? OR provider.username LIKE ?
                   OR CAST(sr.request_id AS TEXT) LIKE ?)
            ORDER BY ps.submission_id DESC
        """, (status, status, search, search, search, search)).fetchall()
    finally:
        connection.close()
    for submission_id, file_name, request_id, customer, provider, version, decision, uploaded in rows:
        admin_submission_tree.insert("", "end", iid=str(submission_id), values=(file_name, f"#{request_id}", customer, provider, f"v{version}", decision, uploaded or ""))
    if rows:
        admin_submission_tree.selection_set(str(rows[0][0]))
        show_admin_submission_details()
    else:
        admin_submission_detail.configure(state="normal")
        admin_submission_detail.delete("1.0", tk.END)
        admin_submission_detail.insert("1.0", "No submissions match this search and status filter.")
        admin_submission_detail.configure(state="disabled")


def show_admin_submission_details(_event=None):
    if not _admin_session_is_valid():
        return
    selection = admin_submission_tree.selection()
    if not selection:
        return
    submission_id = int(selection[0])
    connection = get_connection()
    try:
        row = connection.execute("""
            SELECT ps.file_name, ps.submission_status, ps.revision_number,
                   ps.uploaded_at, ps.message, sr.request_id, services.title,
                   customer.username, provider.username, p.payment_status
            FROM project_submissions AS ps
            JOIN service_requests AS sr ON sr.request_id = ps.request_id
            JOIN services ON services.service_id = sr.service_id
            JOIN users AS customer ON customer.user_id = sr.customer_id
            JOIN users AS provider ON provider.user_id = ps.provider_id
            LEFT JOIN payments AS p ON p.request_id = sr.request_id
            WHERE ps.submission_id = ?
        """, (submission_id,)).fetchone()
    finally:
        connection.close()
    if not row:
        return
    file_name, decision, version, uploaded, message, request_id, title, customer, provider, payment_status = row
    details = (
        f"Submission #{submission_id} · {decision} · version {version} · uploaded {uploaded or '—'}\n"
        f"File: {file_name} · Request #{request_id}: {title}\n"
        f"Customer: {customer} · Provider: {provider} · Payment: {payment_status or 'Not recorded'}\n"
        f"Customer decision / note: {message or 'No note'}"
    )
    admin_submission_detail.configure(state="normal")
    admin_submission_detail.delete("1.0", tk.END)
    admin_submission_detail.insert("1.0", details)
    admin_submission_detail.configure(state="disabled")


def save_admin_submission_copy():
    if not _admin_session_is_valid():
        return
    selection = admin_submission_tree.selection()
    if not selection:
        messagebox.showwarning("Select a submission", "Select a submission row first.")
        return
    submission_id = int(selection[0])
    connection = get_connection()
    try:
        record = connection.execute(
            "SELECT file_name, file_path FROM project_submissions WHERE submission_id = ?",
            (submission_id,),
        ).fetchone()
    finally:
        connection.close()
    if not record:
        messagebox.showerror("Submission not found", "This submission record no longer exists.")
        return
    stored_path = Path(record[1]).resolve()
    submissions_root = SUBMISSIONS_DIR.resolve()
    if submissions_root not in stored_path.parents or not stored_path.is_file():
        messagebox.showerror("File unavailable", "The saved submission file is missing or outside the app's submissions folder.")
        return
    destination = filedialog.asksaveasfilename(
        title="Save a copy of submission",
        initialfile=record[0],
        defaultextension=Path(record[0]).suffix,
        filetypes=[("Original file type", f"*{Path(record[0]).suffix}"), ("All files", "*.*")],
    )
    if not destination:
        return
    try:
        shutil.copy2(stored_path, destination)
    except OSError as error:
        messagebox.showerror("Could not save copy", f"The submission could not be copied.\n\n{error}")
        return
    connection = get_connection()
    try:
        connection.execute("""
            INSERT INTO activity_logs (actor_type, actor_id, action, description, related_type, related_id)
            VALUES ('Admin', ?, 'SUBMISSION_COPIED', ?, 'Submission', ?)
        """, (current_admin[0], f"Saved a local copy of {record[0]} for review.", submission_id))
        connection.commit()
    finally:
        connection.close()
    messagebox.showinfo("Copy saved", f"A copy was saved to:\n{destination}")


def show_admin_settings_screen():
    global admin_commission_var
    if not _admin_session_is_valid():
        return
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT setting_value FROM platform_settings WHERE setting_key = 'commission_rate'"
        ).fetchone()
    finally:
        connection.close()
    current_rate = row[0] if row else "10"
    clear_window()

    shell = tk.Frame(app, bg=BG_COLOR)
    shell.pack(fill="both", expand=True)
    sidebar = tk.Frame(shell, bg="#0F172A", width=185)
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)
    tk.Label(sidebar, text="CampusGig\nADMIN", font=("Segoe UI", 17, "bold"), bg="#0F172A", fg="white", justify="left").pack(anchor="w", padx=18, pady=(22, 8))
    tk.Label(sidebar, text=current_admin[1], font=("Segoe UI", 9), bg="#0F172A", fg="#CBD5E1").pack(anchor="w", padx=18, pady=(0, 16))
    for section in ["Dashboard", "Users", "Services", "Requests", "Submissions", "Payments", "Payouts", "Reviews", "Activity Log", "Reports", "Settings"]:
        command = {
            "Dashboard": show_admin_home,
            "Users": show_admin_users_screen,
            "Services": show_admin_services_screen,
            "Requests": show_admin_requests_screen,
            "Submissions": show_admin_submissions_screen,
            "Payments": show_admin_payments_screen,
            "Payouts": show_admin_payouts_screen,
            "Reviews": show_admin_reviews_screen,
            "Activity Log": show_admin_activity_screen,
            "Reports": show_admin_reports_screen,
            "Settings": show_admin_settings_screen,
        }.get(section, lambda name=section: show_admin_placeholder(name))
        tk.Button(sidebar, text=section, command=command, anchor="w", bg="#1E293B" if section == "Settings" else "#0F172A", fg="white", activebackground="#334155", activeforeground="white", relief="flat", font=("Segoe UI", 9, "bold"), padx=18, pady=7).pack(fill="x")
    tk.Button(sidebar, text="Admin Logout", command=admin_logout, anchor="w", bg="#7F1D1D", fg="white", relief="flat", padx=18, pady=8).pack(side="bottom", fill="x", pady=12)

    main_area = tk.Frame(shell, bg=BG_COLOR, padx=40, pady=35)
    main_area.pack(side="left", fill="both", expand=True)
    tk.Label(main_area, text="Platform Settings", font=("Segoe UI", 22, "bold"), bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
    tk.Label(main_area, text="Choose the commission applied when a customer records a new demo payment.", font=("Segoe UI", 11), bg=BG_COLOR, fg="#64748B").pack(anchor="w", pady=(5, 24))
    card = tk.Frame(main_area, bg="white", padx=25, pady=22)
    card.pack(anchor="nw", fill="x")
    tk.Label(card, text="CampusGig commission", font=("Segoe UI", 14, "bold"), bg="white", fg=TEXT_COLOR).pack(anchor="w")
    tk.Label(card, text="Allowed range: 5% to 10%", font=("Segoe UI", 10), bg="white", fg="#64748B").pack(anchor="w", pady=(4, 15))
    entry_row = tk.Frame(card, bg="white")
    entry_row.pack(anchor="w")
    admin_commission_var = tk.StringVar(value=str(current_rate))
    tk.Entry(entry_row, textvariable=admin_commission_var, width=12, font=("Segoe UI", 12)).pack(side="left")
    tk.Label(entry_row, text="%", font=("Segoe UI", 12, "bold"), bg="white", fg=TEXT_COLOR).pack(side="left", padx=8)
    tk.Button(card, text="Save Commission", command=save_admin_commission, bg=PRIMARY_COLOR, fg="white", relief="flat", padx=16, pady=8).pack(anchor="w", pady=(18, 0))

    backup_card = tk.Frame(main_area, bg="white", padx=25, pady=20)
    backup_card.pack(anchor="nw", fill="x", pady=(16, 0))
    tk.Label(backup_card, text="Database backup", font=("Segoe UI", 14, "bold"), bg="white", fg=TEXT_COLOR).pack(anchor="w")
    tk.Label(backup_card, text="Save and verify a separate copy of the current CampusGig database.", font=("Segoe UI", 10), bg="white", fg="#64748B").pack(anchor="w", pady=(4, 12))
    tk.Button(backup_card, text="Create Database Backup…", command=admin_backup_database, bg="#0F766E", fg="white", relief="flat", padx=16, pady=8).pack(anchor="w")

    tk.Label(
        main_area,
        text="Changing this rate affects future payment records only. Existing payments retain the commission rate and amounts saved when they were created. Payments and payouts are demo records: this desktop app does not charge cards or transfer money.",
        font=("Segoe UI", 10), bg=BG_COLOR, fg="#7C2D12", wraplength=670, justify="left"
    ).pack(anchor="w", pady=(22, 0))


def save_admin_commission():
    if not _admin_session_is_valid():
        return
    raw_value = admin_commission_var.get().strip()
    try:
        new_rate = float(raw_value)
    except ValueError:
        messagebox.showerror("Invalid commission", "Enter a number between 5 and 10, such as 7.5.")
        return
    if not 5.0 <= new_rate <= 10.0:
        messagebox.showerror("Invalid commission", "Commission must be between 5% and 10%.")
        return
    new_value = f"{new_rate:g}"
    connection = get_connection()
    try:
        old_row = connection.execute(
            "SELECT setting_value FROM platform_settings WHERE setting_key = 'commission_rate'"
        ).fetchone()
        old_value = old_row[0] if old_row else "10"
        if old_value == new_value:
            messagebox.showinfo("No change", f"The commission is already {new_value}%.")
            return
        connection.execute("""
            INSERT INTO platform_settings (setting_key, setting_value, updated_at)
            VALUES ('commission_rate', ?, CURRENT_TIMESTAMP)
            ON CONFLICT(setting_key) DO UPDATE SET
                setting_value = excluded.setting_value,
                updated_at = CURRENT_TIMESTAMP
        """, (new_value,))
        connection.execute("""
            INSERT INTO activity_logs (actor_type, actor_id, action, description, related_type, related_id)
            VALUES ('Admin', ?, 'COMMISSION_RATE_CHANGED', ?, 'Setting', NULL)
        """, (current_admin[0], f"Changed commission from {old_value}% to {new_value}%; applies to future payments."))
        connection.commit()
    except sqlite3.Error as error:
        connection.rollback()
        messagebox.showerror("Could not save setting", f"The commission was not changed.\n\n{error}")
        return
    finally:
        connection.close()
    messagebox.showinfo("Commission updated", f"New demo payments will use a {new_value}% commission. Existing payments were not changed.")
    show_admin_settings_screen()


def admin_backup_database():
    if not _admin_session_is_valid():
        return
    default_name = f"campusgig_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    destination = filedialog.asksaveasfilename(
        title="Create a CampusGig database backup",
        initialdir=str(Path(__file__).resolve().parent),
        initialfile=default_name,
        defaultextension=".db",
        filetypes=[("SQLite database", "*.db *.sqlite *.sqlite3"), ("All files", "*.*")],
    )
    if not destination:
        return
    try:
        backup_path = create_database_backup(destination)
    except (OSError, sqlite3.Error, ValueError) as error:
        messagebox.showerror("Backup failed", f"Could not create a verified database copy.\n\n{error}")
        return

    _record_activity("Admin", current_admin[0], "DATABASE_BACKUP_CREATED", f"Created a verified database backup at {backup_path.name}.", "Database Backup", None)
    messagebox.showinfo("Backup complete", f"The backup passed integrity and foreign-key checks.\n\nSaved to:\n{backup_path}")


def _admin_report_date_range(show_error=True):
    start_date = admin_report_from_var.get().strip()
    end_date = admin_report_to_var.get().strip()
    try:
        parsed_start = datetime.strptime(start_date, "%d/%m/%Y").date() if start_date else None
        parsed_end = datetime.strptime(end_date, "%d/%m/%Y").date() if end_date else None
    except ValueError:
        if show_error:
            messagebox.showerror("Invalid date", "Enter dates in DD/MM/YYYY format, for example 06/10/2026, or leave a field blank.")
        return None
    if parsed_start and parsed_end and parsed_start > parsed_end:
        if show_error:
            messagebox.showerror("Invalid date range", "The start date must be on or before the end date.")
        return None
    return (
        parsed_start.isoformat() if parsed_start else "",
        parsed_end.isoformat() if parsed_end else "",
    )


def _get_admin_report_rows(start_date, end_date):
    connection = get_connection()
    try:
        def scalar(sql, parameters=()):
            return connection.execute(sql, parameters).fetchone()[0]

        def dated_count(table, date_column, extra_where="1=1", extra_parameters=()):
            sql = f"""SELECT COUNT(*) FROM {table}
                WHERE {extra_where}
                  AND (? = '' OR substr({date_column}, 1, 10) >= ?)
                  AND (? = '' OR substr({date_column}, 1, 10) <= ?)"""
            return scalar(sql, (*extra_parameters, start_date, start_date, end_date, end_date))

        def dated_sum(table, date_column, sum_column, extra_where="1=1", extra_parameters=()):
            sql = f"""SELECT COALESCE(SUM({sum_column}), 0) FROM {table}
                WHERE {extra_where}
                  AND (? = '' OR substr({date_column}, 1, 10) >= ?)
                  AND (? = '' OR substr({date_column}, 1, 10) <= ?)"""
            return scalar(sql, (*extra_parameters, start_date, start_date, end_date, end_date))

        completed_payment_count = dated_count("payments", "created_at", "payment_status = 'Completed'")
        gross_paid = dated_sum("payments", "created_at", "gross_amount", "payment_status = 'Completed'")
        commission = dated_sum("payments", "created_at", "commission_amount", "payment_status = 'Completed'")
        provider_net = dated_sum("payments", "created_at", "provider_amount", "payment_status = 'Completed'")
        pending_payout_count = dated_count("provider_payouts", "created_at", "payout_status = 'Pending'")
        pending_payout_amount = dated_sum("provider_payouts", "created_at", "amount", "payout_status = 'Pending'")
        processed_payout_count = dated_count("provider_payouts", "COALESCE(processed_at, created_at)", "payout_status = 'Processed'")
        processed_payout_amount = dated_sum("provider_payouts", "COALESCE(processed_at, created_at)", "amount", "payout_status = 'Processed'")
        avg_rating = scalar("""SELECT ROUND(AVG(rating), 2) FROM reviews
            WHERE moderation_status = 'Visible'
              AND (? = '' OR substr(created_at, 1, 10) >= ?)
              AND (? = '' OR substr(created_at, 1, 10) <= ?)""", (start_date, start_date, end_date, end_date))
        return [
            ("Accounts", "Total registrations", dated_count("users", "created_at")),
            ("Accounts", "Customers", dated_count("users", "created_at", "user_type = 'Customer'")),
            ("Accounts", "Providers", dated_count("users", "created_at", "user_type = 'Provider'")),
            ("Requests", "Requests created", dated_count("service_requests", "requested_at")),
            ("Requests", "Pending requests", dated_count("service_requests", "requested_at", "request_status = 'Pending'")),
            ("Requests", "Completed requests", dated_count("service_requests", "requested_at", "request_status = 'Completed'")),
            ("Submissions", "Files submitted", dated_count("project_submissions", "uploaded_at")),
            ("Reviews", "All reviews including hidden", dated_count("reviews", "created_at")),
            ("Reviews", "Visible reviews", dated_count("reviews", "created_at", "moderation_status = 'Visible'")),
            ("Reviews", "Hidden reviews", dated_count("reviews", "created_at", "moderation_status = 'Hidden'")),
            ("Reviews", "Average stars", f"{avg_rating:.2f}" if avg_rating is not None else "No ratings"),
            ("Payments", "Completed demo payments", completed_payment_count),
            ("Payments", "Customer gross paid (demo)", f"₹{gross_paid:.2f}"),
            ("Payments", "Platform commission (demo)", f"₹{commission:.2f}"),
            ("Payments", "Provider net amount (demo)", f"₹{provider_net:.2f}"),
            ("Payouts", "Pending payout count", pending_payout_count),
            ("Payouts", "Pending payout amount", f"₹{pending_payout_amount:.2f}"),
            ("Payouts", "Processed demo payout count", processed_payout_count),
            ("Payouts", "Processed demo payout amount", f"₹{processed_payout_amount:.2f}"),
            ("Activity", "Recorded events", dated_count("activity_logs", "created_at")),
        ]
    finally:
        connection.close()


def show_admin_reports_screen():
    global admin_report_tree, admin_report_from_var, admin_report_to_var
    global admin_report_rows
    if not _admin_session_is_valid():
        return
    clear_window()
    shell = tk.Frame(app, bg=BG_COLOR)
    shell.pack(fill="both", expand=True)
    sidebar = tk.Frame(shell, bg="#0F172A", width=185)
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)
    tk.Label(sidebar, text="CampusGig\nADMIN", font=("Segoe UI", 17, "bold"), bg="#0F172A", fg="white", justify="left").pack(anchor="w", padx=18, pady=(22, 8))
    tk.Label(sidebar, text=current_admin[1], font=("Segoe UI", 9), bg="#0F172A", fg="#CBD5E1").pack(anchor="w", padx=18, pady=(0, 16))
    for section in ["Dashboard", "Users", "Services", "Requests", "Submissions", "Payments", "Payouts", "Reviews", "Activity Log", "Reports", "Settings"]:
        command = {
            "Dashboard": show_admin_home,
            "Users": show_admin_users_screen,
            "Services": show_admin_services_screen,
            "Requests": show_admin_requests_screen,
            "Submissions": show_admin_submissions_screen,
            "Payments": show_admin_payments_screen,
            "Payouts": show_admin_payouts_screen,
            "Reviews": show_admin_reviews_screen,
            "Activity Log": show_admin_activity_screen,
            "Reports": show_admin_reports_screen,
            "Settings": show_admin_settings_screen,
        }.get(section, lambda name=section: show_admin_placeholder(name))
        tk.Button(sidebar, text=section, command=command, anchor="w", bg="#1E293B" if section == "Reports" else "#0F172A", fg="white", activebackground="#334155", activeforeground="white", relief="flat", font=("Segoe UI", 9, "bold"), padx=18, pady=7).pack(fill="x")
    tk.Button(sidebar, text="Admin Logout", command=admin_logout, anchor="w", bg="#7F1D1D", fg="white", relief="flat", padx=18, pady=8).pack(side="bottom", fill="x", pady=12)

    main_area = tk.Frame(shell, bg=BG_COLOR, padx=18, pady=16)
    main_area.pack(side="left", fill="both", expand=True)
    tk.Label(main_area, text="Platform Reports", font=("Segoe UI", 20, "bold"), bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
    tk.Label(main_area, text="Summaries use each record's creation date unless it is a processed payout. Blank dates include all available history. Financial figures are demo-ledger values, not real transfers.", font=("Segoe UI", 9), bg=BG_COLOR, fg="#64748B", wraplength=760, justify="left").pack(anchor="w", pady=(3, 12))
    controls = tk.Frame(main_area, bg=BG_COLOR)
    controls.pack(fill="x", pady=(0, 10))
    admin_report_from_var = tk.StringVar(value="")
    admin_report_to_var = tk.StringVar(value="")
    tk.Label(controls, text="From (DD/MM/YYYY)", bg=BG_COLOR, fg=TEXT_COLOR).pack(side="left")
    tk.Entry(controls, textvariable=admin_report_from_var, width=13).pack(side="left", padx=(6, 12))
    tk.Label(controls, text="To (DD/MM/YYYY)", bg=BG_COLOR, fg=TEXT_COLOR).pack(side="left")
    tk.Entry(controls, textvariable=admin_report_to_var, width=13).pack(side="left", padx=6)
    tk.Button(controls, text="Refresh", command=load_admin_reports, bg=PRIMARY_COLOR, fg="white", relief="flat", padx=12).pack(side="left", padx=6)
    tk.Button(controls, text="Export CSV…", command=export_admin_report_csv, bg="#0F766E", fg="white", relief="flat", padx=12).pack(side="left", padx=4)
    report_area = tk.Frame(main_area, bg="white")
    report_area.pack(fill="both", expand=True)
    admin_report_tree = ttk.Treeview(report_area, columns=("section", "metric", "value"), show="headings", height=19)
    for column, title, width in [("section", "Area", 130), ("metric", "Measure", 330), ("value", "Result", 220)]:
        admin_report_tree.heading(column, text=title)
        admin_report_tree.column(column, width=width, anchor="w")
    report_scroll = ttk.Scrollbar(report_area, orient="vertical", command=admin_report_tree.yview)
    admin_report_tree.configure(yscrollcommand=report_scroll.set)
    admin_report_tree.pack(side="left", fill="both", expand=True)
    report_scroll.pack(side="right", fill="y")
    load_admin_reports()


def load_admin_reports():
    global admin_report_rows
    if not _admin_session_is_valid():
        return
    date_range = _admin_report_date_range()
    if date_range is None:
        return
    admin_report_rows = _get_admin_report_rows(*date_range)
    admin_report_tree.delete(*admin_report_tree.get_children())
    for index, (section, metric, value) in enumerate(admin_report_rows):
        admin_report_tree.insert("", "end", iid=str(index), values=(section, metric, value))


def export_admin_report_csv():
    if not _admin_session_is_valid():
        return
    date_range = _admin_report_date_range()
    if date_range is None:
        return
    rows = _get_admin_report_rows(*date_range)
    destination = filedialog.asksaveasfilename(
        title="Export CampusGig report",
        defaultextension=".csv",
        initialfile="campusgig_report.csv",
        filetypes=[("CSV files", "*.csv")],
    )
    if not destination:
        return
    try:
        with open(destination, "w", newline="", encoding="utf-8-sig") as report_file:
            writer = csv.writer(report_file)
            writer.writerow(["CampusGig platform report"])
            writer.writerow(["Generated at", datetime.now().astimezone().isoformat(timespec="seconds")])
            writer.writerow([
                "From", datetime.strptime(date_range[0], "%Y-%m-%d").strftime("%d/%m/%Y") if date_range[0] else "All available history",
                "To", datetime.strptime(date_range[1], "%Y-%m-%d").strftime("%d/%m/%Y") if date_range[1] else "All available history",
            ])
            writer.writerow([])
            writer.writerow(["Area", "Measure", "Result"])
            writer.writerows(rows)
    except OSError as error:
        messagebox.showerror("Export failed", f"Could not write the CSV file.\n\n{error}")
        return
    _record_activity("Admin", current_admin[0], "REPORT_EXPORTED", f"Exported a report for {date_range[0] or 'all history'} through {date_range[1] or 'all history'}.", "Report", None)
    messagebox.showinfo("Report exported", f"Saved report to:\n{destination}")


def show_admin_activity_screen():
    global admin_activity_tree, admin_activity_detail
    global admin_activity_search_var, admin_activity_actor_var
    if not _admin_session_is_valid():
        return
    clear_window()
    shell = tk.Frame(app, bg=BG_COLOR)
    shell.pack(fill="both", expand=True)
    sidebar = tk.Frame(shell, bg="#0F172A", width=185)
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)
    tk.Label(sidebar, text="CampusGig\nADMIN", font=("Segoe UI", 17, "bold"), bg="#0F172A", fg="white", justify="left").pack(anchor="w", padx=18, pady=(22, 8))
    tk.Label(sidebar, text=current_admin[1], font=("Segoe UI", 9), bg="#0F172A", fg="#CBD5E1").pack(anchor="w", padx=18, pady=(0, 16))
    for section in ["Dashboard", "Users", "Services", "Requests", "Submissions", "Payments", "Payouts", "Reviews", "Activity Log", "Reports", "Settings"]:
        command = {
            "Dashboard": show_admin_home,
            "Users": show_admin_users_screen,
            "Services": show_admin_services_screen,
            "Requests": show_admin_requests_screen,
            "Submissions": show_admin_submissions_screen,
            "Payments": show_admin_payments_screen,
            "Payouts": show_admin_payouts_screen,
            "Reviews": show_admin_reviews_screen,
            "Activity Log": show_admin_activity_screen,
            "Reports": show_admin_reports_screen,
            "Settings": show_admin_settings_screen,
        }.get(section, lambda name=section: show_admin_placeholder(name))
        tk.Button(sidebar, text=section, command=command, anchor="w", bg="#1E293B" if section == "Activity Log" else "#0F172A", fg="white", activebackground="#334155", activeforeground="white", relief="flat", font=("Segoe UI", 9, "bold"), padx=18, pady=7).pack(fill="x")
    tk.Button(sidebar, text="Admin Logout", command=admin_logout, anchor="w", bg="#7F1D1D", fg="white", relief="flat", padx=18, pady=8).pack(side="bottom", fill="x", pady=12)

    main_area = tk.Frame(shell, bg=BG_COLOR, padx=18, pady=16)
    main_area.pack(side="left", fill="both", expand=True)
    tk.Label(main_area, text="Activity Log", font=("Segoe UI", 20, "bold"), bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
    tk.Label(main_area, text="Audit history of recorded user, admin, and system events. Entries are view-only and kept in the project database.", font=("Segoe UI", 9), bg=BG_COLOR, fg="#64748B", wraplength=760, justify="left").pack(anchor="w", pady=(3, 10))
    controls = tk.Frame(main_area, bg=BG_COLOR)
    controls.pack(fill="x", pady=(0, 8))
    admin_activity_search_var = tk.StringVar()
    admin_activity_actor_var = tk.StringVar(value="All actors")
    tk.Label(controls, text="Search", bg=BG_COLOR, fg=TEXT_COLOR).pack(side="left")
    search_entry = tk.Entry(controls, textvariable=admin_activity_search_var, width=34)
    search_entry.pack(side="left", padx=(6, 14))
    tk.Label(controls, text="Actor", bg=BG_COLOR, fg=TEXT_COLOR).pack(side="left")
    ttk.Combobox(controls, textvariable=admin_activity_actor_var, values=["All actors", "User", "Admin", "System"], state="readonly", width=13).pack(side="left", padx=6)
    tk.Button(controls, text="Apply", command=load_admin_activity, bg=PRIMARY_COLOR, fg="white", relief="flat", padx=12).pack(side="left", padx=4)
    search_entry.bind("<Return>", lambda _event: load_admin_activity())

    table_area = tk.Frame(main_area, bg="white")
    table_area.pack(fill="both", expand=True)
    columns = ("date", "actor_type", "actor", "action", "related")
    admin_activity_tree = ttk.Treeview(table_area, columns=columns, show="headings", height=11)
    for column, title, width in [
        ("date", "Date/time", 140), ("actor_type", "Type", 70),
        ("actor", "Actor", 115), ("action", "Action", 145), ("related", "Related record", 125),
    ]:
        admin_activity_tree.heading(column, text=title)
        admin_activity_tree.column(column, width=width, anchor="w")
    activity_scroll = ttk.Scrollbar(table_area, orient="vertical", command=admin_activity_tree.yview)
    admin_activity_tree.configure(yscrollcommand=activity_scroll.set)
    admin_activity_tree.pack(side="left", fill="both", expand=True)
    activity_scroll.pack(side="right", fill="y")
    admin_activity_tree.bind("<<TreeviewSelect>>", show_admin_activity_details)
    admin_activity_detail = tk.Text(main_area, height=7, wrap="word", font=("Segoe UI", 10), bg="white", fg=TEXT_COLOR, relief="flat", padx=10, pady=8, state="disabled")
    admin_activity_detail.pack(fill="x", pady=(10, 0))
    load_admin_activity()


def load_admin_activity():
    if not _admin_session_is_valid():
        return
    admin_activity_tree.delete(*admin_activity_tree.get_children())
    actor_filter = admin_activity_actor_var.get()
    search = f"%{admin_activity_search_var.get().strip()}%"
    connection = get_connection()
    try:
        rows = connection.execute("""
            SELECT a.activity_id, a.created_at, a.actor_type,
                   CASE a.actor_type
                       WHEN 'User' THEN COALESCE(u.username, 'Deleted user')
                       WHEN 'Admin' THEN COALESCE(ad.username, 'Deleted admin')
                       ELSE 'System'
                   END,
                   a.action, a.related_type, a.related_id, a.description
            FROM activity_logs AS a
            LEFT JOIN users AS u ON a.actor_type = 'User' AND u.user_id = a.actor_id
            LEFT JOIN admins AS ad ON a.actor_type = 'Admin' AND ad.admin_id = a.actor_id
            WHERE (? = 'All actors' OR a.actor_type = ?)
              AND (a.action LIKE ? OR COALESCE(a.description, '') LIKE ?
                   OR COALESCE(u.username, '') LIKE ? OR COALESCE(ad.username, '') LIKE ?
                   OR COALESCE(a.related_type, '') LIKE ? OR CAST(COALESCE(a.related_id, '') AS TEXT) LIKE ?)
            ORDER BY a.activity_id DESC
        """, (actor_filter, actor_filter, search, search, search, search, search, search)).fetchall()
    finally:
        connection.close()
    for activity_id, created, actor_type, actor, action, related_type, related_id, description in rows:
        related = f"{related_type or ''} {('#' + str(related_id)) if related_id is not None else ''}".strip() or "—"
        admin_activity_tree.insert("", "end", iid=str(activity_id), values=(created or "", actor_type, actor, action, related))
    if rows:
        admin_activity_tree.selection_set(str(rows[0][0]))
        show_admin_activity_details()
    else:
        admin_activity_detail.configure(state="normal")
        admin_activity_detail.delete("1.0", tk.END)
        admin_activity_detail.insert("1.0", "No activity entries match this search and actor filter.")
        admin_activity_detail.configure(state="disabled")


def show_admin_activity_details(_event=None):
    if not _admin_session_is_valid():
        return
    selection = admin_activity_tree.selection()
    if not selection:
        return
    activity_id = int(selection[0])
    connection = get_connection()
    try:
        row = connection.execute("""
            SELECT a.created_at, a.actor_type,
                   CASE a.actor_type
                       WHEN 'User' THEN COALESCE(u.username, 'Deleted user')
                       WHEN 'Admin' THEN COALESCE(ad.username, 'Deleted admin')
                       ELSE 'System'
                   END,
                   a.action, a.description, a.related_type, a.related_id
            FROM activity_logs AS a
            LEFT JOIN users AS u ON a.actor_type = 'User' AND u.user_id = a.actor_id
            LEFT JOIN admins AS ad ON a.actor_type = 'Admin' AND ad.admin_id = a.actor_id
            WHERE a.activity_id = ?
        """, (activity_id,)).fetchone()
    finally:
        connection.close()
    if not row:
        return
    created, actor_type, actor, action, description, related_type, related_id = row
    details = (
        f"Activity #{activity_id} · {created or '—'}\n"
        f"Actor: {actor_type} — {actor} · Action: {action}\n"
        f"Related: {related_type or '—'} {('#' + str(related_id)) if related_id is not None else ''}\n"
        f"Details: {description or 'No additional description'}"
    )
    admin_activity_detail.configure(state="normal")
    admin_activity_detail.delete("1.0", tk.END)
    admin_activity_detail.insert("1.0", details)
    admin_activity_detail.configure(state="disabled")


def show_admin_reviews_screen():
    global admin_review_tree, admin_review_detail, admin_review_search_var
    global admin_review_rating_var, admin_review_status_var, admin_review_summary
    if not _admin_session_is_valid():
        return
    clear_window()
    shell = tk.Frame(app, bg=BG_COLOR)
    shell.pack(fill="both", expand=True)
    sidebar = tk.Frame(shell, bg="#0F172A", width=185)
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)
    tk.Label(sidebar, text="CampusGig\nADMIN", font=("Segoe UI", 17, "bold"), bg="#0F172A", fg="white", justify="left").pack(anchor="w", padx=18, pady=(22, 8))
    tk.Label(sidebar, text=current_admin[1], font=("Segoe UI", 9), bg="#0F172A", fg="#CBD5E1").pack(anchor="w", padx=18, pady=(0, 16))
    for section in ["Dashboard", "Users", "Services", "Requests", "Submissions", "Payments", "Payouts", "Reviews", "Activity Log", "Reports", "Settings"]:
        command = {
            "Dashboard": show_admin_home,
            "Users": show_admin_users_screen,
            "Services": show_admin_services_screen,
            "Requests": show_admin_requests_screen,
            "Submissions": show_admin_submissions_screen,
            "Payments": show_admin_payments_screen,
            "Payouts": show_admin_payouts_screen,
            "Activity Log": show_admin_activity_screen,
            "Reports": show_admin_reports_screen,
            "Settings": show_admin_settings_screen,
            "Reviews": show_admin_reviews_screen,
        }.get(section, lambda name=section: show_admin_placeholder(name))
        tk.Button(sidebar, text=section, command=command, anchor="w", bg="#1E293B" if section == "Reviews" else "#0F172A", fg="white", activebackground="#334155", activeforeground="white", relief="flat", font=("Segoe UI", 9, "bold"), padx=18, pady=7).pack(fill="x")
    tk.Button(sidebar, text="Admin Logout", command=admin_logout, anchor="w", bg="#7F1D1D", fg="white", relief="flat", padx=18, pady=8).pack(side="bottom", fill="x", pady=12)

    main_area = tk.Frame(shell, bg=BG_COLOR, padx=18, pady=16)
    main_area.pack(side="left", fill="both", expand=True)
    tk.Label(main_area, text="Customer Reviews", font=("Segoe UI", 20, "bold"), bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
    tk.Label(main_area, text="Hide inappropriate reviews from public ratings without deleting the record. Admin actions require a reason and are recorded.", font=("Segoe UI", 9), bg=BG_COLOR, fg="#64748B", wraplength=760, justify="left").pack(anchor="w", pady=(3, 8))
    admin_review_summary = tk.Label(main_area, text="", font=("Segoe UI", 10, "bold"), bg=BG_COLOR, fg="#B45309")
    admin_review_summary.pack(anchor="w", pady=(0, 8))
    controls = tk.Frame(main_area, bg=BG_COLOR)
    controls.pack(fill="x", pady=(0, 8))
    admin_review_search_var = tk.StringVar()
    admin_review_rating_var = tk.StringVar(value="All ratings")
    admin_review_status_var = tk.StringVar(value="All visibility")
    tk.Label(controls, text="Search", bg=BG_COLOR, fg=TEXT_COLOR).pack(side="left")
    search_entry = tk.Entry(controls, textvariable=admin_review_search_var, width=32)
    search_entry.pack(side="left", padx=(6, 14))
    tk.Label(controls, text="Rating", bg=BG_COLOR, fg=TEXT_COLOR).pack(side="left")
    ttk.Combobox(controls, textvariable=admin_review_rating_var, values=["All ratings", "5", "4", "3", "2", "1"], state="readonly", width=12).pack(side="left", padx=6)
    tk.Label(controls, text="Visibility", bg=BG_COLOR, fg=TEXT_COLOR).pack(side="left")
    ttk.Combobox(controls, textvariable=admin_review_status_var, values=["All visibility", "Visible", "Hidden"], state="readonly", width=14).pack(side="left", padx=6)
    tk.Button(controls, text="Apply", command=load_admin_reviews, bg=PRIMARY_COLOR, fg="white", relief="flat", padx=12).pack(side="left", padx=4)
    search_entry.bind("<Return>", lambda _event: load_admin_reviews())

    table_area = tk.Frame(main_area, bg="white")
    table_area.pack(fill="both", expand=True)
    columns = ("rating", "visibility", "request", "service", "customer", "provider", "comment", "date")
    admin_review_tree = ttk.Treeview(table_area, columns=columns, show="headings", height=10)
    for column, title, width in [
        ("rating", "Rating", 55), ("visibility", "Visibility", 75), ("request", "Request", 65), ("service", "Service", 125),
        ("customer", "Customer", 90), ("provider", "Provider", 90),
        ("comment", "Comment preview", 190), ("date", "Date", 120),
    ]:
        admin_review_tree.heading(column, text=title)
        admin_review_tree.column(column, width=width, anchor="w")
    review_scroll = ttk.Scrollbar(table_area, orient="vertical", command=admin_review_tree.yview)
    admin_review_tree.configure(yscrollcommand=review_scroll.set)
    admin_review_tree.pack(side="left", fill="both", expand=True)
    review_scroll.pack(side="right", fill="y")
    admin_review_tree.bind("<<TreeviewSelect>>", show_admin_review_details)
    admin_review_detail = tk.Text(main_area, height=7, wrap="word", font=("Segoe UI", 10), bg="white", fg=TEXT_COLOR, relief="flat", padx=10, pady=8, state="disabled")
    admin_review_detail.pack(fill="x", pady=(10, 0))
    actions = tk.Frame(main_area, bg=BG_COLOR)
    actions.pack(fill="x", pady=(8, 0))
    tk.Button(actions, text="Hide from Public Ratings", command=lambda: moderate_admin_review("Hidden"), bg="#B91C1C", fg="white", relief="flat", padx=12, pady=6).pack(side="left", padx=(0, 8))
    tk.Button(actions, text="Restore to Public Ratings", command=lambda: moderate_admin_review("Visible"), bg="#0F766E", fg="white", relief="flat", padx=12, pady=6).pack(side="left")
    load_admin_reviews()


def load_admin_reviews():
    if not _admin_session_is_valid():
        return
    admin_review_tree.delete(*admin_review_tree.get_children())
    rating = admin_review_rating_var.get()
    visibility = admin_review_status_var.get()
    search = f"%{admin_review_search_var.get().strip()}%"
    connection = get_connection()
    try:
        summary = connection.execute("""
            SELECT COUNT(*),
                   SUM(CASE WHEN moderation_status='Visible' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN moderation_status='Hidden' THEN 1 ELSE 0 END),
                   ROUND(AVG(CASE WHEN moderation_status='Visible' THEN rating END), 2)
            FROM reviews
        """).fetchone()
        rows = connection.execute("""
            SELECT r.review_id, r.rating, sr.request_id, services.title,
                   customer.username, provider.username, r.review_text, r.created_at,
                   r.moderation_status
            FROM reviews AS r
            JOIN service_requests AS sr ON sr.request_id = r.request_id
            JOIN services ON services.service_id = sr.service_id
            JOIN users AS customer ON customer.user_id = r.reviewer_id
            JOIN users AS provider ON provider.user_id = r.provider_id
            WHERE (? = 'All ratings' OR CAST(r.rating AS TEXT) = ?)
              AND (? = 'All visibility' OR r.moderation_status = ?)
              AND (customer.username LIKE ? OR provider.username LIKE ? OR services.title LIKE ?
                   OR COALESCE(r.review_text, '') LIKE ? OR CAST(sr.request_id AS TEXT) LIKE ?)
            ORDER BY r.review_id DESC
        """, (rating, rating, visibility, visibility, search, search, search, search, search)).fetchall()
    finally:
        connection.close()
    admin_review_summary.configure(text=f"Visible: {summary[1] or 0}    Hidden: {summary[2] or 0}    Public average: {summary[3] if summary[3] is not None else '—'} ★")
    for review_id, stars, request_id, service, customer, provider, comment, created, visibility in rows:
        preview = (comment or "No comment").replace("\n", " ")
        if len(preview) > 56:
            preview = preview[:53] + "..."
        admin_review_tree.insert("", "end", iid=str(review_id), values=(f"{stars} ★", visibility, f"#{request_id}", service, customer, provider, preview, created or ""))
    if rows:
        admin_review_tree.selection_set(str(rows[0][0]))
        show_admin_review_details()
    else:
        admin_review_detail.configure(state="normal")
        admin_review_detail.delete("1.0", tk.END)
        admin_review_detail.insert("1.0", "No reviews match this search and selected filters.")
        admin_review_detail.configure(state="disabled")


def show_admin_review_details(_event=None):
    if not _admin_session_is_valid():
        return
    selection = admin_review_tree.selection()
    if not selection:
        return
    review_id = int(selection[0])
    connection = get_connection()
    try:
        row = connection.execute("""
            SELECT r.rating, r.review_text, r.created_at, sr.request_id,
                   services.title, customer.username, customer.email,
                   provider.username, provider.email, r.moderation_status,
                   r.moderation_note, r.moderated_at, admin.username
            FROM reviews AS r
            JOIN service_requests AS sr ON sr.request_id = r.request_id
            JOIN services ON services.service_id = sr.service_id
            JOIN users AS customer ON customer.user_id = r.reviewer_id
            JOIN users AS provider ON provider.user_id = r.provider_id
            LEFT JOIN admins AS admin ON admin.admin_id = r.moderated_by_admin_id
            WHERE r.review_id = ?
        """, (review_id,)).fetchone()
    finally:
        connection.close()
    if not row:
        return
    (stars, comment, created, request_id, service, customer, customer_email,
     provider, provider_email, visibility, moderation_note, moderated_at, moderator) = row
    detail = (
        f"Review #{review_id} · {stars} out of 5 stars · {created or '—'}\n"
        f"Request #{request_id}: {service}\n"
        f"Customer: {customer} ({customer_email}) · Provider: {provider} ({provider_email})\n"
        f"Visibility: {visibility} · Last moderated: {moderated_at or '—'} by {moderator or '—'}\n"
        f"Moderation reason: {moderation_note or '—'}\n"
        f"Full comment: {comment or 'No written comment'}"
    )
    admin_review_detail.configure(state="normal")
    admin_review_detail.delete("1.0", tk.END)
    admin_review_detail.insert("1.0", detail)
    admin_review_detail.configure(state="disabled")


def moderate_admin_review(new_status):
    if not _admin_session_is_valid():
        return
    selection = admin_review_tree.selection()
    if not selection:
        messagebox.showwarning("Select a review", "Select a review row first.")
        return
    review_id = int(selection[0])
    action_text = "hide" if new_status == "Hidden" else "restore"
    reason = simpledialog.askstring(
        f"{action_text.title()} review",
        f"Enter the reason to {action_text} this review:",
        parent=app,
    )
    if reason is None:
        return
    reason = reason.strip()
    if not reason:
        messagebox.showerror("Reason required", "Enter a reason for this moderation action.")
        return
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT moderation_status FROM reviews WHERE review_id = ?",
            (review_id,),
        ).fetchone()
        if not row:
            messagebox.showerror("Review not found", "This review no longer exists.")
            return
        old_status = row[0]
        if old_status == new_status:
            messagebox.showinfo("No change", f"This review is already {new_status.lower()}.")
            return
        connection.execute("""
            UPDATE reviews SET moderation_status = ?, moderation_note = ?,
                               moderated_by_admin_id = ?, moderated_at = CURRENT_TIMESTAMP
            WHERE review_id = ? AND moderation_status = ?
        """, (new_status, reason, current_admin[0], review_id, old_status))
        if connection.execute("SELECT changes()").fetchone()[0] != 1:
            messagebox.showerror("Review changed", "The review changed elsewhere. Refresh and try again.")
            return
        connection.execute("""
            INSERT INTO activity_logs (actor_type, actor_id, action, description, related_type, related_id)
            VALUES ('Admin', ?, ?, ?, 'Review', ?)
        """, (
            current_admin[0],
            "REVIEW_HIDDEN" if new_status == "Hidden" else "REVIEW_RESTORED",
            f"Changed review #{review_id} from {old_status} to {new_status}. Reason: {reason}",
            review_id,
        ))
        connection.commit()
    except sqlite3.Error as error:
        connection.rollback()
        messagebox.showerror("Moderation failed", f"Could not update the review.\n\n{error}")
        return
    finally:
        connection.close()
    load_admin_reviews()
    if str(review_id) in admin_review_tree.get_children():
        admin_review_tree.selection_set(str(review_id))
        show_admin_review_details()
    messagebox.showinfo("Review updated", f"Review #{review_id} is now {new_status.lower()}.")


def show_admin_payments_screen():
    global admin_payment_tree, admin_payment_detail, admin_payment_search_var, admin_payment_filter_var, admin_payment_summary
    if not _admin_session_is_valid():
        return
    clear_window()

    shell = tk.Frame(app, bg=BG_COLOR)
    shell.pack(fill="both", expand=True)
    sidebar = tk.Frame(shell, bg="#0F172A", width=185)
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)
    tk.Label(sidebar, text="CampusGig\nADMIN", font=("Segoe UI", 17, "bold"), bg="#0F172A", fg="white", justify="left").pack(anchor="w", padx=18, pady=(22, 8))
    tk.Label(sidebar, text=current_admin[1], font=("Segoe UI", 9), bg="#0F172A", fg="#CBD5E1").pack(anchor="w", padx=18, pady=(0, 16))
    for section in ["Dashboard", "Users", "Services", "Requests", "Submissions", "Payments", "Payouts", "Reviews", "Activity Log", "Reports", "Settings"]:
        command = {
            "Dashboard": show_admin_home,
            "Users": show_admin_users_screen,
            "Services": show_admin_services_screen,
            "Requests": show_admin_requests_screen,
            "Submissions": show_admin_submissions_screen,
            "Payments": show_admin_payments_screen,
            "Payouts": show_admin_payouts_screen,
            "Activity Log": show_admin_activity_screen,
            "Reports": show_admin_reports_screen,
            "Settings": show_admin_settings_screen,
        }.get(section, lambda name=section: show_admin_placeholder(name))
        tk.Button(sidebar, text=section, command=command, anchor="w", bg="#1E293B" if section == "Payments" else "#0F172A", fg="white", activebackground="#334155", activeforeground="white", relief="flat", font=("Segoe UI", 9, "bold"), padx=18, pady=7).pack(fill="x")
    tk.Button(sidebar, text="Admin Logout", command=admin_logout, anchor="w", bg="#7F1D1D", fg="white", relief="flat", padx=18, pady=8).pack(side="bottom", fill="x", pady=12)

    main_area = tk.Frame(shell, bg=BG_COLOR, padx=18, pady=16)
    main_area.pack(side="left", fill="both", expand=True)
    tk.Label(main_area, text="Customer Payments", font=("Segoe UI", 20, "bold"), bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
    tk.Label(main_area, text="Read-only transaction monitoring. Payment records show demo transactions and are not evidence of a real card charge.", font=("Segoe UI", 9), bg=BG_COLOR, fg="#64748B", wraplength=760, justify="left").pack(anchor="w", pady=(3, 10))
    admin_payment_summary = tk.Label(main_area, text="", font=("Segoe UI", 10, "bold"), bg=BG_COLOR, fg=PRIMARY_COLOR)
    admin_payment_summary.pack(anchor="w", pady=(0, 8))

    controls = tk.Frame(main_area, bg=BG_COLOR)
    controls.pack(fill="x", pady=(0, 8))
    admin_payment_search_var = tk.StringVar()
    admin_payment_filter_var = tk.StringVar(value="All statuses")
    tk.Label(controls, text="Search", bg=BG_COLOR, fg=TEXT_COLOR).pack(side="left")
    search_entry = tk.Entry(controls, textvariable=admin_payment_search_var, width=30)
    search_entry.pack(side="left", padx=(6, 14))
    tk.Label(controls, text="Status", bg=BG_COLOR, fg=TEXT_COLOR).pack(side="left")
    ttk.Combobox(controls, textvariable=admin_payment_filter_var, values=["All statuses", "Pending", "Completed", "Failed", "Refunded"], state="readonly", width=16).pack(side="left", padx=6)
    tk.Button(controls, text="Apply", command=load_admin_payments, bg=PRIMARY_COLOR, fg="white", relief="flat", padx=12).pack(side="left", padx=4)
    search_entry.bind("<Return>", lambda _event: load_admin_payments())

    table_area = tk.Frame(main_area, bg="white")
    table_area.pack(fill="both", expand=True)
    columns = ("reference", "customer", "provider", "request", "gross", "status", "payout")
    admin_payment_tree = ttk.Treeview(table_area, columns=columns, show="headings", height=9)
    for column, title, width in [
        ("reference", "Payment reference", 125), ("customer", "Customer", 90),
        ("provider", "Provider", 90), ("request", "Request", 65),
        ("gross", "Gross", 80), ("status", "Payment", 85), ("payout", "Payout", 80),
    ]:
        admin_payment_tree.heading(column, text=title)
        admin_payment_tree.column(column, width=width, anchor="w")
    payment_scroll = ttk.Scrollbar(table_area, orient="vertical", command=admin_payment_tree.yview)
    admin_payment_tree.configure(yscrollcommand=payment_scroll.set)
    admin_payment_tree.pack(side="left", fill="both", expand=True)
    payment_scroll.pack(side="right", fill="y")
    admin_payment_tree.bind("<<TreeviewSelect>>", show_admin_payment_details)
    admin_payment_detail = tk.Text(main_area, height=7, wrap="word", font=("Consolas", 9), bg="white", fg=TEXT_COLOR, relief="flat", padx=10, pady=8, state="disabled")
    admin_payment_detail.pack(fill="x", pady=(10, 0))
    load_admin_payments()


def load_admin_payments():
    if not _admin_session_is_valid():
        return
    admin_payment_tree.delete(*admin_payment_tree.get_children())
    status = admin_payment_filter_var.get()
    search = f"%{admin_payment_search_var.get().strip()}%"
    connection = get_connection()
    try:
        metrics = connection.execute("""
            SELECT COUNT(*), COALESCE(SUM(CASE WHEN payment_status='Completed' THEN gross_amount ELSE 0 END), 0),
                   COALESCE(SUM(CASE WHEN payment_status='Completed' THEN commission_amount ELSE 0 END), 0)
            FROM payments
        """).fetchone()
        rows = connection.execute("""
            SELECT p.payment_id, COALESCE(p.transaction_reference, 'No reference'),
                   customer.username, provider.username, sr.request_id, p.gross_amount,
                   p.payment_status, COALESCE(pp.payout_status, 'No payout')
            FROM payments AS p
            JOIN users AS customer ON customer.user_id = p.customer_id
            JOIN users AS provider ON provider.user_id = p.provider_id
            JOIN service_requests AS sr ON sr.request_id = p.request_id
            LEFT JOIN provider_payouts AS pp ON pp.payment_id = p.payment_id
            WHERE (? = 'All statuses' OR p.payment_status = ?)
              AND (COALESCE(p.transaction_reference, '') LIKE ? OR customer.username LIKE ?
                   OR provider.username LIKE ? OR CAST(sr.request_id AS TEXT) LIKE ?)
            ORDER BY p.payment_id DESC
        """, (status, status, search, search, search, search)).fetchall()
    finally:
        connection.close()
    admin_payment_summary.configure(text=f"Transactions: {metrics[0]}    Completed gross: ₹{metrics[1]:.2f}    Commission recorded: ₹{metrics[2]:.2f}")
    for payment_id, reference, customer, provider, request_id, gross, payment_status, payout_status in rows:
        admin_payment_tree.insert("", "end", iid=str(payment_id), values=(reference, customer, provider, f"#{request_id}", f"₹{gross:.2f}", payment_status, payout_status))
    if rows:
        admin_payment_tree.selection_set(str(rows[0][0]))
        show_admin_payment_details()
    else:
        admin_payment_detail.configure(state="normal")
        admin_payment_detail.delete("1.0", tk.END)
        admin_payment_detail.insert("1.0", "No payment records match this search and status filter.")
        admin_payment_detail.configure(state="disabled")


def show_admin_payment_details(_event=None):
    if not _admin_session_is_valid():
        return
    selection = admin_payment_tree.selection()
    if not selection:
        return
    payment_id = int(selection[0])
    connection = get_connection()
    try:
        row = connection.execute("""
            SELECT p.transaction_reference, p.payment_status, p.payment_mode,
                   p.gross_amount, p.commission_rate, p.commission_amount, p.provider_amount,
                   p.created_at, p.paid_at, customer.username, customer.email,
                   provider.username, provider.email, sr.request_id, services.title,
                   pp.payout_status, pp.payout_reference, pp.processed_at, admin.username
            FROM payments AS p
            JOIN users AS customer ON customer.user_id = p.customer_id
            JOIN users AS provider ON provider.user_id = p.provider_id
            JOIN service_requests AS sr ON sr.request_id = p.request_id
            JOIN services ON services.service_id = sr.service_id
            LEFT JOIN provider_payouts AS pp ON pp.payment_id = p.payment_id
            LEFT JOIN admins AS admin ON admin.admin_id = pp.processed_by_admin_id
            WHERE p.payment_id = ?
        """, (payment_id,)).fetchone()
    finally:
        connection.close()
    if not row:
        return
    (reference, status, mode, gross, rate, commission, provider_net, created, paid,
     customer, customer_email, provider, provider_email, request_id, title,
     payout_status, payout_reference, processed_at, processed_by) = row
    detail = (
        f"Payment #{payment_id} · {status} · Mode: {mode} · Reference: {reference or '—'}\n"
        f"Request #{request_id}: {title}\n"
        f"Customer: {customer} ({customer_email}) · Provider: {provider} ({provider_email})\n"
        f"Gross: ₹{gross:.2f} · Commission: {rate:g}% = ₹{commission:.2f} · Provider net: ₹{provider_net:.2f}\n"
        f"Recorded: {created or '—'} · Paid timestamp: {paid or '—'}\n"
        f"Provider payout: {payout_status or 'No payout'} · Reference: {payout_reference or '—'} · "
        f"Processed: {processed_at or '—'} by {processed_by or '—'}"
    )
    admin_payment_detail.configure(state="normal")
    admin_payment_detail.delete("1.0", tk.END)
    admin_payment_detail.insert("1.0", detail)
    admin_payment_detail.configure(state="disabled")


def show_admin_payouts_screen():
    global admin_payout_tree, admin_payout_detail, admin_payout_search_var, admin_payout_filter_var
    if not _admin_session_is_valid():
        return
    clear_window()

    shell = tk.Frame(app, bg=BG_COLOR)
    shell.pack(fill="both", expand=True)
    sidebar = tk.Frame(shell, bg="#0F172A", width=185)
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)
    tk.Label(sidebar, text="CampusGig\nADMIN", font=("Segoe UI", 17, "bold"), bg="#0F172A", fg="white", justify="left").pack(anchor="w", padx=18, pady=(22, 8))
    tk.Label(sidebar, text=current_admin[1], font=("Segoe UI", 9), bg="#0F172A", fg="#CBD5E1").pack(anchor="w", padx=18, pady=(0, 16))
    for section in ["Dashboard", "Users", "Services", "Requests", "Submissions", "Payments", "Payouts", "Reviews", "Activity Log", "Reports", "Settings"]:
        command = {
            "Dashboard": show_admin_home,
            "Users": show_admin_users_screen,
            "Services": show_admin_services_screen,
            "Requests": show_admin_requests_screen,
            "Submissions": show_admin_submissions_screen,
            "Reviews": show_admin_reviews_screen,
            "Payouts": show_admin_payouts_screen,
            "Activity Log": show_admin_activity_screen,
            "Reports": show_admin_reports_screen,
            "Settings": show_admin_settings_screen,
        }.get(section, lambda name=section: show_admin_placeholder(name))
        tk.Button(sidebar, text=section, command=command, anchor="w", bg="#1E293B" if section == "Payouts" else "#0F172A", fg="white", activebackground="#334155", activeforeground="white", relief="flat", font=("Segoe UI", 9, "bold"), padx=18, pady=7).pack(fill="x")
    tk.Button(sidebar, text="Admin Logout", command=admin_logout, anchor="w", bg="#7F1D1D", fg="white", relief="flat", padx=18, pady=8).pack(side="bottom", fill="x", pady=12)

    main_area = tk.Frame(shell, bg=BG_COLOR, padx=18, pady=16)
    main_area.pack(side="left", fill="both", expand=True)
    tk.Label(main_area, text="Provider Payouts", font=("Segoe UI", 20, "bold"), bg=BG_COLOR, fg=TEXT_COLOR).pack(anchor="w")
    tk.Label(main_area, text="Review the provider's net amount after commission. Processing here updates the demo ledger; it does not transfer money.", font=("Segoe UI", 9), bg=BG_COLOR, fg="#64748B", wraplength=760, justify="left").pack(anchor="w", pady=(3, 12))

    controls = tk.Frame(main_area, bg=BG_COLOR)
    controls.pack(fill="x", pady=(0, 8))
    admin_payout_search_var = tk.StringVar()
    admin_payout_filter_var = tk.StringVar(value="All statuses")
    tk.Label(controls, text="Search", bg=BG_COLOR, fg=TEXT_COLOR).pack(side="left")
    search_entry = tk.Entry(controls, textvariable=admin_payout_search_var, width=30)
    search_entry.pack(side="left", padx=(6, 14))
    tk.Label(controls, text="Status", bg=BG_COLOR, fg=TEXT_COLOR).pack(side="left")
    ttk.Combobox(controls, textvariable=admin_payout_filter_var, values=["All statuses", "Pending", "Approved", "Processed", "Failed"], state="readonly", width=16).pack(side="left", padx=6)
    tk.Button(controls, text="Apply", command=load_admin_payouts, bg=PRIMARY_COLOR, fg="white", relief="flat", padx=12).pack(side="left", padx=4)
    search_entry.bind("<Return>", lambda _event: load_admin_payouts())

    table_area = tk.Frame(main_area, bg="white")
    table_area.pack(fill="both", expand=True)
    columns = ("reference", "provider", "request", "amount", "status", "created")
    admin_payout_tree = ttk.Treeview(table_area, columns=columns, show="headings", height=10)
    for column, title, width in [
        ("reference", "Payout reference", 135), ("provider", "Provider", 120),
        ("request", "Request", 70), ("amount", "Net amount", 100),
        ("status", "Status", 90), ("created", "Created", 135),
    ]:
        admin_payout_tree.heading(column, text=title)
        admin_payout_tree.column(column, width=width, anchor="w")
    payout_scroll = ttk.Scrollbar(table_area, orient="vertical", command=admin_payout_tree.yview)
    admin_payout_tree.configure(yscrollcommand=payout_scroll.set)
    admin_payout_tree.pack(side="left", fill="both", expand=True)
    payout_scroll.pack(side="right", fill="y")
    admin_payout_tree.bind("<<TreeviewSelect>>", show_admin_payout_details)

    admin_payout_detail = tk.Text(main_area, height=6, wrap="word", font=("Consolas", 9), bg="white", fg=TEXT_COLOR, relief="flat", padx=10, pady=8, state="disabled")
    admin_payout_detail.pack(fill="x", pady=(10, 8))
    actions = tk.Frame(main_area, bg=BG_COLOR)
    actions.pack(fill="x")
    tk.Button(actions, text="Approve Payout", command=lambda: change_admin_payout_status("Approved"), bg="#2563EB", fg="white", relief="flat", padx=12, pady=6).pack(side="left", padx=(0, 8))
    tk.Button(actions, text="Mark Demo Processed", command=lambda: change_admin_payout_status("Processed"), bg="#16A34A", fg="white", relief="flat", padx=12, pady=6).pack(side="left", padx=(0, 8))
    tk.Button(actions, text="Mark Failed", command=lambda: change_admin_payout_status("Failed"), bg="#DC2626", fg="white", relief="flat", padx=12, pady=6).pack(side="left", padx=(0, 8))
    tk.Button(actions, text="Retry Failed Payout", command=lambda: change_admin_payout_status("Approved"), bg="#F59E0B", fg="white", relief="flat", padx=12, pady=6).pack(side="left")
    load_admin_payouts()


def load_admin_payouts():
    if not _admin_session_is_valid():
        return
    admin_payout_tree.delete(*admin_payout_tree.get_children())
    status = admin_payout_filter_var.get()
    search = f"%{admin_payout_search_var.get().strip()}%"
    query = """
        SELECT pp.payout_id, COALESCE(pp.payout_reference, 'Not processed'),
               provider.username, sr.request_id, pp.amount, pp.payout_status, pp.created_at
        FROM provider_payouts AS pp
        JOIN users AS provider ON provider.user_id = pp.provider_id
        JOIN payments AS p ON p.payment_id = pp.payment_id
        JOIN service_requests AS sr ON sr.request_id = p.request_id
        WHERE (? = 'All statuses' OR pp.payout_status = ?)
          AND (provider.username LIKE ? OR CAST(sr.request_id AS TEXT) LIKE ?
               OR COALESCE(pp.payout_reference, '') LIKE ? OR p.transaction_reference LIKE ?)
        ORDER BY CASE pp.payout_status WHEN 'Pending' THEN 0 WHEN 'Failed' THEN 1 WHEN 'Approved' THEN 2 ELSE 3 END,
                 pp.payout_id DESC
    """
    connection = get_connection()
    try:
        rows = connection.execute(query, (status, status, search, search, search, search)).fetchall()
    finally:
        connection.close()
    for payout_id, reference, provider, request_id, amount, payout_status, created_at in rows:
        admin_payout_tree.insert("", "end", iid=str(payout_id), values=(reference, provider, f"#{request_id}", f"₹{amount:.2f}", payout_status, created_at or ""))
    if rows:
        admin_payout_tree.selection_set(str(rows[0][0]))
        show_admin_payout_details()
    else:
        admin_payout_detail.configure(state="normal")
        admin_payout_detail.delete("1.0", tk.END)
        admin_payout_detail.insert("1.0", "No payouts match the current search and status filter.")
        admin_payout_detail.configure(state="disabled")


def show_admin_payout_details(_event=None):
    if not _admin_session_is_valid():
        return
    selection = admin_payout_tree.selection()
    if not selection:
        return
    payout_id = int(selection[0])
    connection = get_connection()
    try:
        row = connection.execute("""
            SELECT pp.payout_status, pp.amount, pp.payout_reference, pp.created_at,
                   pp.processed_at, provider.username, provider.email,
                   sr.request_id, customer.username, p.transaction_reference,
                   p.gross_amount, p.commission_rate, p.commission_amount,
                   p.payment_mode, admin.username
            FROM provider_payouts AS pp
            JOIN payments AS p ON p.payment_id = pp.payment_id
            JOIN users AS provider ON provider.user_id = pp.provider_id
            JOIN users AS customer ON customer.user_id = p.customer_id
            JOIN service_requests AS sr ON sr.request_id = p.request_id
            LEFT JOIN admins AS admin ON admin.admin_id = pp.processed_by_admin_id
            WHERE pp.payout_id = ?
        """, (payout_id,)).fetchone()
        events = connection.execute("""
            SELECT created_at, action, description FROM activity_logs
            WHERE related_type = 'Payout' AND related_id = ? ORDER BY activity_id
        """, (payout_id,)).fetchall()
    finally:
        connection.close()
    if not row:
        return
    (status, amount, payout_reference, created_at, processed_at, provider, provider_email,
     request_id, customer, payment_reference, gross, rate, commission, payment_mode, processed_by) = row
    text = (
        f"Payout #{payout_id} · {status} · Provider: {provider} ({provider_email})\n"
        f"Request #{request_id} · Customer: {customer} · Payment: {payment_reference or '—'} ({payment_mode})\n"
        f"Gross: ₹{gross:.2f} · Commission: {rate:g}% = ₹{commission:.2f} · Provider net: ₹{amount:.2f}\n"
        f"Payout reference: {payout_reference or 'Not processed'} · Created: {created_at or '—'}\n"
        f"Processed: {processed_at or 'Not yet'} · Admin: {processed_by or 'Not yet'}\n"
        "History: " + (" | ".join(f"{event[0]} {event[1]} — {event[2]}" for event in events) if events else "No admin actions yet.")
    )
    admin_payout_detail.configure(state="normal")
    admin_payout_detail.delete("1.0", tk.END)
    admin_payout_detail.insert("1.0", text)
    admin_payout_detail.configure(state="disabled")


def change_admin_payout_status(new_status):
    if not _admin_session_is_valid():
        return
    selection = admin_payout_tree.selection()
    if not selection:
        messagebox.showwarning("Select a payout", "Select a payout row first.")
        return
    payout_id = int(selection[0])
    reason = ""
    if new_status == "Failed":
        reason = simpledialog.askstring("Payout failed", "Enter the reason this payout failed:", parent=app)
        if reason is None:
            return
        reason = reason.strip()
        if not reason:
            messagebox.showerror("Reason required", "Enter a reason before marking the payout failed.")
            return

    connection = get_connection()
    try:
        record = connection.execute("""
            SELECT pp.payout_status, pp.amount, p.payment_status
            FROM provider_payouts AS pp JOIN payments AS p ON p.payment_id = pp.payment_id
            WHERE pp.payout_id = ?
        """, (payout_id,)).fetchone()
        if not record:
            messagebox.showerror("Payout not found", "This payout no longer exists.")
            return
        old_status, amount, payment_status = record
        transitions = {
            "Pending": {"Approved", "Failed"},
            "Approved": {"Processed", "Failed"},
            "Failed": {"Approved"},
            "Processed": set(),
        }
        if new_status not in transitions.get(old_status, set()):
            messagebox.showerror("Payout status cannot change", f"A payout in {old_status} status cannot be changed to {new_status}.")
            return
        if payment_status != "Completed":
            messagebox.showerror("Payment not completed", "Only a completed customer payment can be paid out.")
            return
        if new_status == "Processed" and not messagebox.askyesno(
            "Mark demo payout processed?",
            f"Record ₹{amount:.2f} as processed in the demo ledger? No money will be transferred.",
        ):
            return
        payout_reference = f"DEMO-PAYOUT-{uuid.uuid4().hex[:10].upper()}" if new_status == "Processed" else None
        processed_at = datetime.now().astimezone().isoformat(timespec="seconds") if new_status == "Processed" else None
        connection.execute("""
            UPDATE provider_payouts
            SET payout_status = ?,
                payout_reference = COALESCE(?, payout_reference),
                processed_at = COALESCE(?, processed_at),
                processed_by_admin_id = CASE WHEN ? = 'Processed' THEN ? ELSE processed_by_admin_id END
            WHERE payout_id = ? AND payout_status = ?
        """, (new_status, payout_reference, processed_at, new_status, current_admin[0], payout_id, old_status))
        if connection.execute("SELECT changes()").fetchone()[0] != 1:
            messagebox.showerror("Payout changed", "The payout was updated elsewhere. Refresh the list and try again.")
            return
        action = f"PAYOUT_{new_status.upper().replace(' ', '_')}"
        description = f"Changed payout #{payout_id} from {old_status} to {new_status}."
        if reason:
            description += f" Reason: {reason}"
        if payout_reference:
            description += f" Demo reference: {payout_reference}. No money transferred."
        connection.execute("""
            INSERT INTO activity_logs (actor_type, actor_id, action, description, related_type, related_id)
            VALUES ('Admin', ?, ?, ?, 'Payout', ?)
        """, (current_admin[0], action, description, payout_id))
        connection.commit()
    except sqlite3.Error as error:
        connection.rollback()
        messagebox.showerror("Payout update failed", f"Could not update the payout.\n\n{error}")
        return
    finally:
        connection.close()
    load_admin_payouts()
    messagebox.showinfo("Payout updated", f"Payout #{payout_id} is now {new_status} in the demo ledger.")


def show_admin_requests_screen():
    global admin_request_tree, admin_request_search_var, admin_request_status_var
    global admin_request_detail_text, admin_request_new_status_var
    global admin_request_reason_entry

    if not _admin_session_is_valid():
        return
    clear_window()

    shell = tk.Frame(app, bg=BG_COLOR)
    shell.pack(fill="both", expand=True)
    sidebar = tk.Frame(shell, bg="#0F172A", width=185)
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)
    tk.Label(
        sidebar,
        text="CampusGig\nADMIN",
        font=("Segoe UI", 17, "bold"),
        bg="#0F172A",
        fg="white",
        justify="left"
    ).pack(anchor="w", padx=18, pady=(22, 8))
    tk.Label(
        sidebar,
        text=current_admin[1],
        font=("Segoe UI", 9),
        bg="#0F172A",
        fg="#CBD5E1"
    ).pack(anchor="w", padx=18, pady=(0, 16))

    navigation = [
        "Dashboard", "Users", "Services", "Requests", "Submissions",
        "Payments", "Payouts", "Reviews", "Activity Log", "Reports", "Settings"
    ]
    for section in navigation:
        if section == "Dashboard":
            command = show_admin_home
        elif section == "Users":
            command = show_admin_users_screen
        elif section == "Services":
            command = show_admin_services_screen
        elif section == "Requests":
            command = show_admin_requests_screen
        elif section == "Submissions":
            command = show_admin_submissions_screen
        elif section == "Reviews":
            command = show_admin_reviews_screen
        elif section == "Activity Log":
            command = show_admin_activity_screen
        elif section == "Reports":
            command = show_admin_reports_screen
        elif section == "Settings":
            command = show_admin_settings_screen
        elif section == "Payments":
            command = show_admin_payments_screen
        elif section == "Payouts":
            command = show_admin_payouts_screen
        else:
            command = lambda name=section: show_admin_placeholder(name)
        tk.Button(
            sidebar,
            text=section,
            command=command,
            anchor="w",
            bg="#1E293B" if section == "Requests" else "#0F172A",
            fg="white",
            activebackground="#334155",
            activeforeground="white",
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            padx=18,
            pady=7
        ).pack(fill="x")
    tk.Button(
        sidebar,
        text="Admin Logout",
        command=admin_logout,
        anchor="w",
        bg="#7F1D1D",
        fg="white",
        activebackground="#991B1B",
        activeforeground="white",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=18,
        pady=8
    ).pack(side="bottom", fill="x", pady=12)

    main_area = tk.Frame(shell, bg=BG_COLOR)
    main_area.pack(side="left", fill="both", expand=True)
    header = tk.Frame(main_area, bg="white", padx=18, pady=10)
    header.pack(fill="x")
    tk.Label(
        header,
        text="Service Request Management",
        font=("Segoe UI", 18, "bold"),
        bg="white",
        fg=TEXT_COLOR
    ).pack(anchor="w")
    tk.Label(
        header,
        text="Inspect each request and record controlled, auditable status changes.",
        font=("Segoe UI", 9),
        bg="white",
        fg="#64748B"
    ).pack(anchor="w", pady=(2, 0))

    filters = tk.Frame(main_area, bg=BG_COLOR, padx=12, pady=8)
    filters.pack(fill="x")
    admin_request_search_var = tk.StringVar()
    admin_request_status_var = tk.StringVar(value="All statuses")
    tk.Entry(
        filters,
        textvariable=admin_request_search_var,
        width=36,
        font=("Segoe UI", 9)
    ).pack(side="left", padx=(0, 7))
    ttk.Combobox(
        filters,
        textvariable=admin_request_status_var,
        values=["All statuses", "Pending", "Accepted", "Rejected", "Completed"],
        state="readonly",
        width=16
    ).pack(side="left", padx=(0, 7))
    tk.Button(
        filters,
        text="Search / Filter",
        command=load_admin_requests,
        bg=PRIMARY_COLOR,
        fg="white",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=10,
        pady=4
    ).pack(side="left")

    request_list = tk.Frame(main_area, bg=BG_COLOR, padx=12)
    request_list.pack(fill="x")
    columns = ("service", "customer", "provider", "status", "price", "requested")
    admin_request_tree = ttk.Treeview(
        request_list,
        columns=columns,
        show="headings",
        height=10,
        selectmode="browse"
    )
    for column, heading, width in [
        ("service", "Service", 155),
        ("customer", "Customer", 105),
        ("provider", "Provider", 105),
        ("status", "Status", 90),
        ("price", "Price", 75),
        ("requested", "Requested", 125),
    ]:
        admin_request_tree.heading(column, text=heading)
        admin_request_tree.column(column, width=width, anchor="w")
    request_scroll = ttk.Scrollbar(
        request_list,
        orient="vertical",
        command=admin_request_tree.yview
    )
    admin_request_tree.configure(yscrollcommand=request_scroll.set)
    admin_request_tree.pack(side="left", fill="x", expand=True)
    request_scroll.pack(side="right", fill="y")
    admin_request_tree.bind("<<TreeviewSelect>>", show_admin_request_details)

    details = tk.Frame(main_area, bg="white", padx=12, pady=8)
    details.pack(fill="both", expand=True, padx=12, pady=(5, 4))
    admin_request_detail_text = tk.Text(
        details,
        height=7,
        wrap="word",
        relief="flat",
        font=("Segoe UI", 9),
        padx=5,
        pady=4
    )
    admin_request_detail_text.pack(fill="both", expand=True)
    admin_request_detail_text.insert("1.0", "Select a request above to inspect its details.")
    admin_request_detail_text.configure(state="disabled")

    actions = tk.Frame(main_area, bg=BG_COLOR, padx=12, pady=7)
    actions.pack(fill="x")
    tk.Label(actions, text="Set status:", bg=BG_COLOR, fg=TEXT_COLOR).pack(side="left", padx=(0, 5))
    admin_request_new_status_var = tk.StringVar(value="Accepted")
    ttk.Combobox(
        actions,
        textvariable=admin_request_new_status_var,
        values=["Pending", "Accepted", "Rejected", "Completed"],
        state="readonly",
        width=13
    ).pack(side="left", padx=(0, 7))
    tk.Label(actions, text="Reason:", bg=BG_COLOR, fg=TEXT_COLOR).pack(side="left", padx=(0, 5))
    admin_request_reason_entry = tk.Entry(actions, width=29, font=("Segoe UI", 9))
    admin_request_reason_entry.pack(side="left", padx=(0, 7))
    tk.Button(
        actions,
        text="Apply Change",
        command=update_admin_request_status,
        bg=PRIMARY_COLOR,
        fg="white",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
        padx=10,
        pady=5
    ).pack(side="left")

    load_admin_requests()


def load_admin_requests():
    if not _admin_session_is_valid():
        return
    search_text = admin_request_search_var.get().strip()
    status = admin_request_status_var.get()
    query = """
        SELECT service_requests.request_id, services.title,
               customer.username, provider.username,
               service_requests.request_status, services.price,
               service_requests.requested_at
        FROM service_requests
        JOIN services ON service_requests.service_id = services.service_id
        JOIN users AS customer ON service_requests.customer_id = customer.user_id
        JOIN users AS provider ON service_requests.provider_id = provider.user_id
        LEFT JOIN profiles AS customer_profile ON customer.user_id = customer_profile.user_id
        LEFT JOIN profiles AS provider_profile ON provider.user_id = provider_profile.user_id
        WHERE 1 = 1
    """
    values = []
    if search_text:
        query += " AND (CAST(service_requests.request_id AS TEXT) LIKE ? OR services.title LIKE ? OR service_requests.message LIKE ? OR customer.username LIKE ? OR customer.email LIKE ? OR customer_profile.full_name LIKE ? OR provider.username LIKE ? OR provider.email LIKE ? OR provider_profile.full_name LIKE ?)"
        values.extend([f"%{search_text}%"] * 9)
    if status != "All statuses":
        query += " AND service_requests.request_status = ?"
        values.append(status)
    query += " ORDER BY service_requests.request_id DESC"

    connection = get_connection()
    try:
        rows = connection.execute(query, values).fetchall()
    finally:
        connection.close()
    for item in admin_request_tree.get_children():
        admin_request_tree.delete(item)
    for request_id, title, customer, provider, request_status, price, requested_at in rows:
        admin_request_tree.insert(
            "",
            "end",
            iid=str(request_id),
            values=(title, customer, provider, request_status, f"₹{price:.2f}", requested_at or ""),
        )


def show_admin_request_details(_event=None):
    if not _admin_session_is_valid():
        return
    selection = admin_request_tree.selection()
    if not selection:
        return
    request_id = int(selection[0])
    connection = get_connection()
    try:
        request = connection.execute("""
            SELECT services.title, services.category, services.price,
                   service_requests.request_status, service_requests.message,
                   service_requests.requested_at,
                   customer.username, customer.email, customer_profile.full_name,
                   customer_profile.phone,
                   provider.username, provider.email, provider_profile.full_name,
                   provider_profile.phone
            FROM service_requests
            JOIN services ON service_requests.service_id = services.service_id
            JOIN users AS customer ON service_requests.customer_id = customer.user_id
            LEFT JOIN profiles AS customer_profile ON customer.user_id = customer_profile.user_id
            JOIN users AS provider ON service_requests.provider_id = provider.user_id
            LEFT JOIN profiles AS provider_profile ON provider.user_id = provider_profile.user_id
            WHERE service_requests.request_id = ?
        """, (request_id,)).fetchone()
        review_count = connection.execute(
            "SELECT COUNT(*) FROM reviews WHERE request_id = ?", (request_id,)
        ).fetchone()[0]
        submission_count = connection.execute(
            "SELECT COUNT(*) FROM project_submissions WHERE request_id = ?", (request_id,)
        ).fetchone()[0]
        payment_count = connection.execute(
            "SELECT COUNT(*) FROM payments WHERE request_id = ?", (request_id,)
        ).fetchone()[0]
    finally:
        connection.close()
    if request is None:
        return

    (title, category, price, status, message, requested_at,
     customer_username, customer_email, customer_name, customer_phone,
     provider_username, provider_email, provider_name, provider_phone) = request
    detail = (
        f"Request ID: {request_id}    Status: {status}    Requested: {requested_at}\n"
        f"Service: {title} ({category})    Listed price: ₹{price:.2f}\n"
        f"Customer: {customer_name or customer_username} (@{customer_username})    "
        f"Email: {customer_email}    Phone: {customer_phone or 'Not provided'}\n"
        f"Provider: {provider_name or provider_username} (@{provider_username})    "
        f"Email: {provider_email}    Phone: {provider_phone or 'Not provided'}\n"
        f"Message: {message or 'No message'}\n"
        f"Linked records — submissions: {submission_count}, payments: {payment_count}, reviews: {review_count}"
    )
    admin_request_detail_text.configure(state="normal")
    admin_request_detail_text.delete("1.0", tk.END)
    admin_request_detail_text.insert("1.0", detail)
    admin_request_detail_text.configure(state="disabled")


def update_admin_request_status():
    if not _admin_session_is_valid():
        return
    selection = admin_request_tree.selection()
    if not selection:
        messagebox.showwarning("Select a request", "Select a request row first.")
        return
    request_id = int(selection[0])
    new_status = admin_request_new_status_var.get()
    reason = admin_request_reason_entry.get().strip()
    allowed_statuses = {"Pending", "Accepted", "Rejected", "Completed"}
    if new_status not in allowed_statuses:
        messagebox.showerror("Invalid status", "That request status is not allowed.")
        return
    if not reason:
        messagebox.showerror("Reason required", "Enter a reason for this admin status change.")
        return

    connection = get_connection()
    try:
        current_row = connection.execute(
            "SELECT request_status FROM service_requests WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if current_row is None:
            messagebox.showerror("Request not found", "This request no longer exists.")
            return
        old_status = current_row[0]
        if old_status == new_status:
            messagebox.showinfo("No change", "The request already has that status.")
            return

        linked_records = connection.execute("""
            SELECT
                (SELECT COUNT(*) FROM project_submissions WHERE request_id = ?) +
                (SELECT COUNT(*) FROM payments WHERE request_id = ?) +
                (SELECT COUNT(*) FROM reviews WHERE request_id = ?)
        """, (request_id, request_id, request_id)).fetchone()[0]
        if linked_records:
            messagebox.showwarning(
                "Request has downstream records",
                "This request has a submission, payment, or review. Its status is locked to preserve that history."
            )
            return

        transitions = {
            "Pending": {"Accepted", "Rejected"},
            "Accepted": {"Pending", "Rejected", "Completed"},
            "Rejected": {"Pending"},
            "Completed": set(),
        }
        if new_status not in transitions.get(old_status, set()):
            messagebox.showerror(
                "Invalid transition",
                f"The admin cannot change a request from {old_status} to {new_status}."
            )
            return

        warning = ""
        if new_status == "Completed":
            warning = " In the current workflow, this also allows the customer to leave a review."
        if not messagebox.askyesno(
            "Confirm request status change",
            f"Change request {request_id} from {old_status} to {new_status}?{warning}"
        ):
            return

        connection.execute(
            "UPDATE service_requests SET request_status = ? WHERE request_id = ?",
            (new_status, request_id),
        )
        connection.execute("""
            INSERT INTO activity_logs (actor_type, actor_id, action, description, related_type, related_id)
            VALUES ('Admin', ?, 'REQUEST_STATUS_CHANGED', ?, 'Service Request', ?)
        """, (
            current_admin[0],
            f"Changed request {request_id} from {old_status} to {new_status}. Reason: {reason}",
            request_id,
        ))
        connection.commit()
    finally:
        connection.close()

    load_admin_requests()
    if str(request_id) in admin_request_tree.get_children():
        admin_request_tree.selection_set(str(request_id))
        admin_request_tree.focus(str(request_id))
        show_admin_request_details()
    messagebox.showinfo("Request updated", f"Request {request_id} is now {new_status}.")


app = tk.Tk()
app.title("CampusGig - Student Skill Marketplace")
app.geometry("1000x650")
app.configure(bg=BG_COLOR)
app.resizable(False, False)

# Shared visual defaults keep classic Tk widgets consistent across existing pages.
app.option_add("*Font", ("Segoe UI", 10))
app.option_add("*Button.Cursor", "hand2")
app.option_add("*Entry.Background", "#FFFFFF")
app.option_add("*Entry.Foreground", TEXT_COLOR)
app.option_add("*Entry.Relief", "solid")
app.option_add("*Entry.BorderWidth", 1)
app.option_add("*Entry.HighlightThickness", 1)
app.option_add("*Entry.HighlightBackground", "#E2E8F0")
app.option_add("*Entry.HighlightColor", PRIMARY_COLOR)
app.option_add("*Entry.InsertBackground", TEXT_COLOR)
app.option_add("*Text.Background", "#FFFFFF")
app.option_add("*Text.Foreground", TEXT_COLOR)
app.option_add("*Text.HighlightThickness", 1)
app.option_add("*Text.HighlightBackground", "#E2E8F0")
app.option_add("*Text.HighlightColor", PRIMARY_COLOR)

ui_style = ttk.Style(app)
try:
    ui_style.theme_use("clam")
except tk.TclError:
    pass
ui_style.configure(
    "Treeview",
    background="#FFFFFF",
    fieldbackground="#FFFFFF",
    foreground=TEXT_COLOR,
    rowheight=28,
    bordercolor="#E2E8F0",
    borderwidth=1,
    font=("Segoe UI", 10),
)
ui_style.configure(
    "Treeview.Heading",
    background="#F1F5F9",
    foreground=TEXT_COLOR,
    font=("Segoe UI", 10, "bold"),
    relief="flat",
    padding=(8, 6),
)
ui_style.map(
    "Treeview",
    background=[("selected", PRIMARY_COLOR)],
    foreground=[("selected", "#FFFFFF")],
)
ui_style.configure(
    "TCombobox",
    fieldbackground="#FFFFFF",
    background="#FFFFFF",
    foreground=TEXT_COLOR,
    padding=5,
    arrowsize=12,
)
ui_style.configure("TButton", font=("Segoe UI", 10), padding=(10, 6))

show_login_screen()

app.mainloop()
