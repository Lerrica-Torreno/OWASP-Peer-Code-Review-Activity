import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
import time
 
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
 
# --- app + secure configuration --------------------------------------------
 
app = FastAPI(title="SecureNotes API", version="1.0")
 
# A02: Secret key comes from the environment.
# A random temporary key is used for local lab runs if none is set.
SECRET_KEY = os.environ.get("SECURENOTES_SECRET_KEY") or secrets.token_urlsafe(48)
 
TOKEN_LIFETIME_SECONDS = 30 * 60
 
# A02: Restrict CORS to trusted origins.
allowed_origins = [
    origin.strip()
    for origin in os.environ.get(
        "SECURENOTES_ALLOWED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
    if origin.strip()
]
 
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
 
 
# --- password helpers (A04) ------------------------------------------------
 
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600_000
    )
    return f"{salt.hex()}${password_hash.hex()}"
 
 
def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, hash_hex = stored_hash.split("$")
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hash_hex)
 
        actual_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            600_000
        )
 
        return hmac.compare_digest(actual_hash, expected_hash)
 
    except (ValueError, AttributeError):
        return False
 
 
# --- database ---------------------------------------------------------------
 
db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row
 
 
def init_db():
    db.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );
 
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        );
        """
    )
 
    # A04: Seeded passwords are hashed.
    # Sample accounts are for laboratory testing only.
    for username, password, is_admin in (
        ("admin", "admin123", 1),
        ("alice", "alicepass", 0),
        ("bob", "bobpass", 0),
    ):
        db.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
            (username, hash_password(password), is_admin),
        )
 
    db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (2, "Alice diary", "Alice secret note"),
    )
 
    db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (3, "Bob plans", "Bob secret note"),
    )
 
    db.commit()
 
 
init_db()
 
 
# --- request models ---------------------------------------------------------
 
class Credentials(BaseModel):
    username: str
    password: str
 
 
class NewNote(BaseModel):
    title: str
    body: str
 
 
# --- authentication (A07) --------------------------------------------------
 
def make_token(user_id: int) -> str:
    expires_at = int(time.time()) + TOKEN_LIFETIME_SECONDS
    nonce = secrets.token_urlsafe(16)
 
    message = f"{user_id}:{expires_at}:{nonce}"
 
    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
 
    return f"{message}:{signature}"
 
 
def current_user(authorization: str = Header(default=None)):
    unauthorized = HTTPException(
        status_code=401,
        detail="Invalid or expired token"
    )
 
    if not authorization:
        raise unauthorized
 
    scheme, separator, token = authorization.partition(" ")
 
    if (
        scheme.lower() != "bearer"
        or not separator
        or not token
        or len(token) > 512
    ):
        raise unauthorized
 
    try:
        user_id_text, expires_text, nonce, signature = token.split(":")
 
        user_id = int(user_id_text)
        expires_at = int(expires_text)
 
        if user_id <= 0 or expires_at <= int(time.time()) or not nonce:
            raise ValueError("Invalid token")
 
        message = f"{user_id_text}:{expires_text}:{nonce}"
 
        expected_signature = hmac.new(
            SECRET_KEY.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
 
        if not hmac.compare_digest(signature, expected_signature):
            raise unauthorized
 
    except (ValueError, TypeError):
        raise unauthorized
 
    user = db.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
 
    if user is None:
        raise unauthorized
 
    return user
 
 
# --- error handling (A02) --------------------------------------------------
 
@app.exception_handler(Exception)
async def handle_everything(request: Request, exc: Exception):
    logging.exception("Unhandled API error")
 
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )
 
 
# --- routes -----------------------------------------------------------------
 
@app.post("/register")
def register(creds: Credentials):
    try:
        db.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
            (creds.username, hash_password(creds.password)),
        )
        db.commit()
 
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="Username already exists"
        )
 
    return {"message": f"user {creds.username} created"}
 
 
# A05: Parameterized SQL prevents SQL injection.
# A07: Generic errors and secure tokens.
 
@app.post("/login")
def login(creds: Credentials):
    row = db.execute(
        "SELECT id, password FROM users WHERE username = ?",
        (creds.username,),
    ).fetchone()
 
    if row is None or not verify_password(
        creds.password, row["password"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )
 
    return {"token": make_token(row["id"])}
 
 
@app.get("/notes")
def list_my_notes(authorization: str = Header(default=None)):
    user = current_user(authorization)
 
    rows = db.execute(
        "SELECT * FROM notes WHERE owner_id = ?",
        (user["id"],)
    ).fetchall()
 
    return [dict(row) for row in rows]
 
 
# A01: Users can only access their own notes.
 
@app.get("/notes/{note_id}")
def get_note(note_id: int, authorization: str = Header(default=None)):
    user = current_user(authorization)
 
    row = db.execute(
        "SELECT * FROM notes WHERE id = ? AND owner_id = ?",
        (note_id, user["id"]),
    ).fetchone()
 
    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Note not found"
        )
 
    return dict(row)
 
 
@app.post("/notes")
def create_note(
    note: NewNote,
    authorization: str = Header(default=None)
):
    user = current_user(authorization)
 
    cursor = db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (user["id"], note.title, note.body),
    )
 
    db.commit()
 
    return {
        "id": cursor.lastrowid,
        "title": note.title
    }
 
 
# A10: Permission checks fail closed.
# A04: Password hashes are never included in responses.
 
@app.get("/admin/users")
def list_all_users(authorization: str = Header(default=None)):
    user = current_user(authorization)
 
    if not user["is_admin"]:
        raise HTTPException(
            status_code=403,
            detail="Admins only"
        )
 
    rows = db.execute(
        "SELECT id, username, is_admin FROM users"
    ).fetchall()
 
    return [dict(row) for row in rows]
 
 
@app.get("/")
def home():
    return {
        "service": "SecureNotes API",
        "docs": "/docs"
    }