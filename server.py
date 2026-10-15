import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
DATABASE = ROOT / "accounts.db"
HOST = "127.0.0.1"
PORT = int(os.environ.get("PORT", "8000"))
PASSWORD_ITERATIONS = 310_000
SESSION_DAYS = 7
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")


def connect_db():
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_db():
    with connect_db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash BLOB NOT NULL,
                password_salt BLOB NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash BLOB PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL
            )
            """
        )


def derive_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )


class AppHandler(BaseHTTPRequestHandler):
    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'; object-src 'none'",
        )
        super().end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/me":
            self.handle_me()
            return
        if path.startswith("/api/"):
            self.send_json(404, {"error": "Endpoint not found."})
            return
        static_files = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/index.html": ("index.html", "text/html; charset=utf-8"),
            "/styles.css": ("styles.css", "text/css; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
        }
        entry = static_files.get(path)
        if entry is None:
            self.send_json(404, {"error": "Not found."})
            return
        filename, content_type = entry
        body = (ROOT / filename).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_error(404, "Not found.")

    def do_POST(self):
        path = urlparse(self.path).path
        routes = {
            "/api/signup": self.handle_signup,
            "/api/login": self.handle_login,
            "/api/logout": self.handle_logout,
        }
        handler = routes.get(path)
        if handler is None:
            self.send_json(404, {"error": "Endpoint not found."})
            return
        handler()

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 1 or length > 8192:
            return None
        try:
            payload = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def send_json(self, status, payload, cookie=None, clear_cookie=False):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header(
                "Set-Cookie",
                f"session={cookie}; HttpOnly; SameSite=Strict; Path=/; Max-Age="
                f"{SESSION_DAYS * 24 * 60 * 60}",
            )
        elif clear_cookie:
            self.send_header(
                "Set-Cookie",
                "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
            )
        self.end_headers()
        self.wfile.write(body)

    def create_session(self, user_id):
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("ascii")).digest()
        expires = datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)
        with connect_db() as connection:
            connection.execute(
                "DELETE FROM sessions WHERE expires_at <= ?",
                (datetime.now(timezone.utc).isoformat(),),
            )
            connection.execute(
                "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (token_hash, user_id, expires.isoformat()),
            )
        return token

    def current_user(self):
        cookie_header = self.headers.get("Cookie", "")
        token = None
        for part in cookie_header.split(";"):
            key, separator, value = part.strip().partition("=")
            if separator and key == "session":
                token = value
                break
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode("utf-8")).digest()
        now = datetime.now(timezone.utc).isoformat()
        with connect_db() as connection:
            return connection.execute(
                """
                SELECT users.id, users.name, users.email
                FROM sessions JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ? AND sessions.expires_at > ?
                """,
                (token_hash, now),
            ).fetchone()

    def handle_signup(self):
        payload = self.read_json()
        if payload is None:
            self.send_json(400, {"error": "Please submit valid form details."})
            return
        name = payload.get("name", "")
        email = payload.get("email", "")
        password = payload.get("password", "")
        if not all(isinstance(value, str) for value in (name, email, password)):
            self.send_json(400, {"error": "Please submit valid form details."})
            return
        name = name.strip()
        email = email.strip().lower()
        if not 2 <= len(name) <= 60:
            self.send_json(400, {"error": "Name must be between 2 and 60 characters."})
            return
        if len(email) > 320 or not EMAIL_PATTERN.fullmatch(email):
            self.send_json(400, {"error": "Enter a valid email address."})
            return
        if not 10 <= len(password) <= 128:
            self.send_json(400, {"error": "Password must be between 10 and 128 characters."})
            return
        salt = secrets.token_bytes(16)
        password_hash = derive_password(password, salt)
        try:
            with connect_db() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO users (name, email, password_hash, password_salt, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        name,
                        email,
                        password_hash,
                        salt,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                user_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "An account with that email already exists."})
            return
        token = self.create_session(user_id)
        self.send_json(201, {"message": "Your account is ready.", "name": name}, cookie=token)

    def handle_login(self):
        payload = self.read_json()
        if payload is None:
            self.send_json(400, {"error": "Please submit valid login details."})
            return
        email = payload.get("email", "")
        password = payload.get("password", "")
        if not isinstance(email, str) or not isinstance(password, str):
            self.send_json(400, {"error": "Please submit valid login details."})
            return
        email = email.strip().lower()
        if len(email) > 320 or not email or not 1 <= len(password) <= 128:
            self.send_json(400, {"error": "Please enter your email and password."})
            return
        with connect_db() as connection:
            user = connection.execute(
                "SELECT id, name, password_hash, password_salt FROM users WHERE email = ?",
                (email,),
            ).fetchone()
        if user is None or not hmac.compare_digest(
            derive_password(password, user["password_salt"]), user["password_hash"]
        ):
            self.send_json(401, {"error": "Email or password is incorrect."})
            return
        token = self.create_session(user["id"])
        self.send_json(
            200,
            {"message": "You’re logged in successfully.", "name": user["name"]},
            cookie=token,
        )

    def handle_me(self):
        user = self.current_user()
        if user is None:
            self.send_json(401, {"error": "You’re not signed in."})
            return
        self.send_json(200, {"name": user["name"], "email": user["email"]})

    def handle_logout(self):
        cookie_header = self.headers.get("Cookie", "")
        token = None
        for part in cookie_header.split(";"):
            key, separator, value = part.strip().partition("=")
            if separator and key == "session":
                token = value
                break
        if token:
            token_hash = hashlib.sha256(token.encode("utf-8")).digest()
            with connect_db() as connection:
                connection.execute(
                    "DELETE FROM sessions WHERE token_hash = ?", (token_hash,)
                )
        self.send_json(200, {"message": "You’ve been signed out."}, clear_cookie=True)

    def log_message(self, format, *args):
        if self.path.startswith("/api/"):
            return
        super().log_message(format, *args)


if __name__ == "__main__":
    initialize_db()
    print(f"Cloudlet is running at http://{HOST}:{PORT}")
    print(f"Local account database: {DATABASE}")
    try:
        ThreadingHTTPServer((HOST, PORT), AppHandler).serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
