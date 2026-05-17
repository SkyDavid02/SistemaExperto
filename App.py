from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import html
import json
import mimetypes
import os
from pathlib import Path
import re
import secrets
import sqlite3
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlparse


APP_TITLE = "Gmail SE"
HOST = "127.0.0.1"
DEFAULT_PORT = 5000
DB_PATH = Path(__file__).with_name("correo_spam.db")
LOG_PATH = Path(__file__).with_name("server.log")
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_ATTACHMENT_BYTES = 2 * 1024 * 1024
SESSIONS: dict[str, int] = {}
BOX_LABELS = {"inbox": "Recibidos", "spam": "Spam", "sent": "Enviados"}


def now_text() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def safe_log(message: str) -> None:
    try:
        with LOG_PATH.open("a", encoding="utf-8") as log_file:
            log_file.write(f"[{now_text()}] {message}\n")
    except OSError:
        pass


def db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS inbox_emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_id INTEGER NOT NULL,
                sender_id INTEGER NOT NULL,
                sender_email TEXT NOT NULL,
                recipient_email TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                expert_score INTEGER NOT NULL,
                expert_reasons TEXT NOT NULL,
                attachment_name TEXT,
                attachment_mime TEXT,
                attachment_data TEXT,
                FOREIGN KEY (recipient_id) REFERENCES users(id),
                FOREIGN KEY (sender_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS spam_emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_id INTEGER NOT NULL,
                sender_id INTEGER NOT NULL,
                sender_email TEXT NOT NULL,
                recipient_email TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                expert_score INTEGER NOT NULL,
                expert_reasons TEXT NOT NULL,
                attachment_name TEXT,
                attachment_mime TEXT,
                attachment_data TEXT,
                FOREIGN KEY (recipient_id) REFERENCES users(id),
                FOREIGN KEY (sender_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS sent_emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL,
                sender_email TEXT NOT NULL,
                recipient_email TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                classified_as TEXT NOT NULL,
                expert_score INTEGER NOT NULL,
                expert_reasons TEXT NOT NULL,
                created_at TEXT NOT NULL,
                attachment_name TEXT,
                attachment_mime TEXT,
                attachment_data TEXT,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (recipient_id) REFERENCES users(id)
            );
            """
        )
        sent_columns = {row["name"] for row in connection.execute("PRAGMA table_info(sent_emails)")}
        if "attachment_data" not in sent_columns:
            connection.execute("ALTER TABLE sent_emails ADD COLUMN attachment_data TEXT")


def escape(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def truncate(value: str, limit: int = 130) -> str:
    value = " ".join((value or "").split())
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "..."


def nice_date(value: str) -> str:
    try:
        stamp = dt.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return escape(value)
    today = dt.datetime.now().date()
    if stamp.date() == today:
        return stamp.strftime("%H:%M")
    return stamp.strftime("%d %b")


def password_hash(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), 150_000)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, digest = stored_hash.split("$", 1)
    except ValueError:
        return False
    check = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), 150_000).hex()
    return hmac.compare_digest(check, digest)


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = user_id
    return token


def valid_email(email: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", email or ""))


def get_user_by_email(email: str) -> sqlite3.Row | None:
    with db() as connection:
        return connection.execute("SELECT * FROM users WHERE lower(email) = lower(?)", (email.strip(),)).fetchone()


def get_user_by_id(user_id: int) -> sqlite3.Row | None:
    with db() as connection:
        return connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def expert_system(subject: str, body: str, attachment_name: str = "") -> tuple[bool, int, list[str]]:
    text = f"{subject} {body}".strip()
    lower = text.lower()
    score = 0
    reasons: list[str] = []

    spam_keywords = [
        "premio",
        "ganador",
        "felicidades",
        "gratis",
        "oferta",
        "promocion",
        "promoción",
        "loteria",
        "lotería",
        "herencia",
        "bitcoin",
        "cripto",
        "prestamo",
        "préstamo",
        "gana dinero",
        "multiplica tus ingresos",
        "haz clic",
        "clic aqui",
        "clic aquí",
        "compra ahora",
        "sin costo",
    ]
    matched_keywords = [word for word in spam_keywords if word in lower]
    if matched_keywords:
        points = min(6, len(matched_keywords) * 2)
        score += points
        reasons.append(f"Palabras clave sospechosas ({', '.join(matched_keywords[:4])}) +{points}")

    urgent_phrases = [
        "urgente",
        "actua ahora",
        "actúa ahora",
        "responde ahora",
        "ultimo aviso",
        "último aviso",
        "tiempo limitado",
        "solo hoy",
        "vence hoy",
    ]
    urgent_matches = [phrase for phrase in urgent_phrases if phrase in lower]
    if urgent_matches:
        score += 2
        reasons.append(f"Lenguaje de urgencia ({urgent_matches[0]}) +2")

    phishing_phrases = [
        "verifica tu cuenta",
        "cuenta suspendida",
        "cuenta bloqueada",
        "confirma tu contraseña",
        "actualiza tu tarjeta",
        "datos bancarios",
        "inicia sesion para evitar",
        "inicia sesión para evitar",
    ]
    phishing_matches = [phrase for phrase in phishing_phrases if phrase in lower]
    if phishing_matches:
        score += 4
        reasons.append(f"Posible suplantacion de identidad ({phishing_matches[0]}) +4")

    links = re.findall(r"(https?://[^\s]+|www\.[^\s]+)", lower)
    if links:
        score += 2
        reasons.append("Contiene enlaces externos +2")
        if any(shortener in link for link in links for shortener in ("bit.ly", "tinyurl", "t.co/", "cutt.ly", "is.gd")):
            score += 2
            reasons.append("Usa acortador de enlaces +2")
        if any(re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", link) for link in links):
            score += 3
            reasons.append("Enlace con direccion IP directa +3")

    if re.search(r"(\$\s?\d+|\b\d{2,3}\s?%|descuento|transferencia|deposito|depósito)", lower):
        score += 2
        reasons.append("Promesas de dinero, descuento o transferencia +2")

    exclamations = text.count("!")
    if exclamations >= 3:
        score += 2
        reasons.append("Demasiados signos de exclamacion +2")

    if re.search(r"([!?])\1{2,}", text):
        score += 2
        reasons.append("Puntuacion repetida de forma agresiva +2")

    letters = [char for char in text if char.isalpha()]
    if len(letters) >= 25:
        uppercase_ratio = sum(1 for char in letters if char.isupper()) / len(letters)
        if uppercase_ratio >= 0.45:
            score += 3
            reasons.append("Uso excesivo de mayusculas +3")

    subject_letters = [char for char in subject if char.isalpha()]
    if len(subject_letters) >= 8 and all(char.isupper() for char in subject_letters):
        score += 2
        reasons.append("Asunto escrito completamente en mayusculas +2")

    if re.search(r"([A-Za-zÁÉÍÓÚÜÑáéíóúüñ])\1{3,}", text):
        score += 1
        reasons.append("Caracteres repetidos de forma sospechosa +1")

    if len(body.strip()) < 35 and links:
        score += 2
        reasons.append("Mensaje muy corto que empuja a abrir un enlace +2")

    if attachment_name:
        ext = Path(attachment_name).suffix.lower()
        if ext in {".exe", ".bat", ".cmd", ".scr", ".js", ".vbs", ".jar", ".msi"}:
            score += 5
            reasons.append(f"Archivo adjunto ejecutable ({ext}) +5")
        elif ext in {".zip", ".rar", ".7z"}:
            score += 2
            reasons.append(f"Archivo comprimido adjunto ({ext}) +2")

    if not subject.strip():
        score += 1
        reasons.append("Asunto vacio +1")

    is_spam = score >= 5
    if not reasons:
        reasons.append("No se activo ninguna regla de spam; el correo parece normal")
    return is_spam, score, reasons


def store_mail(
    sender: sqlite3.Row,
    recipient: sqlite3.Row,
    subject: str,
    body: str,
    attachment_name: str = "",
    attachment_mime: str = "",
    attachment_data: str = "",
) -> tuple[str, int, list[str]]:
    is_spam, score, reasons = expert_system(subject, body, attachment_name)
    table = "spam_emails" if is_spam else "inbox_emails"
    destination = "spam" if is_spam else "inbox"
    reasons_json = json.dumps(reasons, ensure_ascii=False)
    created_at = now_text()

    with db() as connection:
        connection.execute(
            f"""
            INSERT INTO {table}
            (recipient_id, sender_id, sender_email, recipient_email, subject, body, is_read, created_at,
             expert_score, expert_reasons, attachment_name, attachment_mime, attachment_data)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)
            """,
            (
                recipient["id"],
                sender["id"],
                sender["email"],
                recipient["email"],
                subject,
                body,
                created_at,
                score,
                reasons_json,
                attachment_name or None,
                attachment_mime or None,
                attachment_data or None,
            ),
        )
        connection.execute(
            """
            INSERT INTO sent_emails
            (sender_id, recipient_id, sender_email, recipient_email, subject, body, classified_as,
             expert_score, expert_reasons, created_at, attachment_name, attachment_mime, attachment_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sender["id"],
                recipient["id"],
                sender["email"],
                recipient["email"],
                subject,
                body,
                destination,
                score,
                reasons_json,
                created_at,
                attachment_name or None,
                attachment_mime or None,
                attachment_data or None,
            ),
        )

    return destination, score, reasons


def shared_styles() -> str:
    return """
    <style>
        :root {
            --bg: #f6f8fc;
            --surface: #ffffff;
            --surface-soft: #f1f3f4;
            --line: #e0e4ea;
            --text: #202124;
            --muted: #5f6368;
            --blue: #1a73e8;
            --blue-soft: #d3e3fd;
            --red: #d93025;
            --red-soft: #fce8e6;
            --compose: #c2e7ff;
            --shadow: 0 14px 40px rgba(60, 64, 67, .22);
            font-family: Arial, Helvetica, sans-serif;
        }

        * { box-sizing: border-box; }
        body { margin: 0; min-height: 100vh; color: var(--text); background: var(--bg); }
        button, input, textarea { font: inherit; }
        a { color: inherit; text-decoration: none; }
        .icon { width: 20px; height: 20px; flex: 0 0 20px; }
        .muted { color: var(--muted); }
        .hide { display: none !important; }

        .auth-page {
            min-height: 100vh;
            display: grid;
            grid-template-columns: minmax(320px, 520px) minmax(320px, 1fr);
            background: linear-gradient(120deg, #f6f8fc 0%, #eaf1fb 100%);
        }

        .auth-brand {
            padding: 56px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            min-height: 100vh;
        }

        .brand-row { display: flex; align-items: center; gap: 12px; font-size: 24px; color: #3c4043; }
        .gmail-mark {
            width: 38px; height: 28px; position: relative; border-radius: 4px;
            background:
                linear-gradient(135deg, transparent 0 29%, #ea4335 30% 44%, transparent 45%),
                linear-gradient(225deg, transparent 0 29%, #4285f4 30% 44%, transparent 45%),
                linear-gradient(90deg, #34a853 0 18%, transparent 18% 82%, #fbbc04 82% 100%);
            border: 3px solid transparent;
        }

        .auth-copy h1 { font-size: 52px; line-height: 1.05; margin: 0 0 18px; letter-spacing: 0; }
        .auth-copy p { max-width: 420px; color: var(--muted); font-size: 18px; line-height: 1.55; }
        .auth-panel-wrap { display: grid; place-items: center; padding: 38px; }
        .auth-panel {
            width: min(440px, 100%);
            background: var(--surface);
            border-radius: 8px;
            box-shadow: var(--shadow);
            padding: 30px;
        }

        .tabs { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 22px; }
        .tab {
            border: 1px solid var(--line);
            background: var(--surface);
            border-radius: 8px;
            padding: 10px 12px;
            cursor: pointer;
            color: var(--muted);
        }
        .tab.active { background: var(--blue-soft); color: #0b57d0; border-color: var(--blue-soft); font-weight: 700; }
        .auth-form { display: grid; gap: 14px; }
        .auth-form h2 { margin: 0 0 4px; font-size: 24px; }
        .field { display: grid; gap: 6px; }
        .field label { font-size: 13px; color: var(--muted); }
        .field input {
            border: 1px solid #c7cdd6;
            border-radius: 8px;
            padding: 12px 13px;
            outline: none;
            background: #fff;
        }
        .field input:focus { border-color: var(--blue); box-shadow: 0 0 0 3px rgba(26, 115, 232, .12); }
        .primary-button {
            border: 0;
            border-radius: 8px;
            background: var(--blue);
            color: #fff;
            font-weight: 700;
            padding: 12px 16px;
            cursor: pointer;
        }
        .alert {
            border-radius: 8px;
            padding: 12px 14px;
            font-size: 14px;
            line-height: 1.35;
            border: 1px solid transparent;
        }
        .alert.error { background: var(--red-soft); color: #a50e0e; border-color: #fad2cf; }
        .alert.ok { background: #e6f4ea; color: #137333; border-color: #ceead6; }

        .topbar {
            height: 64px;
            display: grid;
            grid-template-columns: 235px minmax(240px, 720px) 1fr auto;
            gap: 18px;
            align-items: center;
            padding: 8px 18px 8px 24px;
            background: var(--bg);
        }
        .brand { display: flex; align-items: center; gap: 12px; color: #3c4043; font-size: 22px; min-width: 0; }
        .round-icon {
            width: 40px; height: 40px; border: 0; border-radius: 50%;
            display: inline-grid; place-items: center; background: transparent; color: #444746; cursor: pointer;
        }
        .round-icon:hover { background: #e8eaed; }
        .search {
            min-width: 0;
            background: #eaf1fb;
            height: 48px;
            border-radius: 24px;
            display: flex;
            align-items: center;
            padding: 0 18px;
            gap: 12px;
        }
        .search input { width: 100%; border: 0; outline: 0; background: transparent; font-size: 16px; }
        .top-actions { display: flex; justify-content: flex-end; align-items: center; gap: 8px; }
        .account { position: relative; }
        .avatar {
            width: 40px; height: 40px; border-radius: 50%;
            border: 0; background: #f4511e; color: #fff; font-weight: 700;
            display: grid; place-items: center; cursor: pointer;
        }
        .account-menu {
            position: absolute; right: 0; top: 50px; z-index: 30;
            width: 280px; background: var(--surface); border: 1px solid var(--line);
            border-radius: 8px; box-shadow: var(--shadow); padding: 18px;
        }
        .account-menu strong { display: block; margin-bottom: 4px; word-break: break-word; }
        .account-menu a {
            margin-top: 16px; display: inline-flex; align-items: center; gap: 8px;
            color: #0b57d0; font-weight: 700;
        }

        .mail-shell {
            display: grid;
            grid-template-columns: 256px minmax(0, 1fr);
            min-height: calc(100vh - 64px);
        }
        .sidebar { padding: 10px 12px; }
        .compose-button {
            min-width: 142px;
            height: 56px;
            border: 0;
            border-radius: 16px;
            background: var(--compose);
            color: #001d35;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 0 1px 2px rgba(60, 64, 67, .2);
            margin-bottom: 14px;
        }
        .compose-button:hover { box-shadow: 0 3px 7px rgba(60, 64, 67, .25); }
        .nav-list { display: grid; gap: 2px; }
        .nav-item {
            min-height: 34px;
            display: grid;
            grid-template-columns: 28px 1fr auto;
            align-items: center;
            gap: 10px;
            padding: 0 12px 0 18px;
            border-radius: 0 18px 18px 0;
            color: #3c4043;
        }
        .nav-item:hover { background: #edf2fa; }
        .nav-item.active { background: var(--blue-soft); color: #001d35; font-weight: 700; }
        .badge {
            min-width: 30px;
            text-align: right;
            font-size: 12px;
            color: inherit;
            font-weight: 700;
        }

        .mail-area {
            background: var(--surface);
            border-radius: 18px 0 0 0;
            overflow: hidden;
            min-width: 0;
            border-left: 1px solid rgba(0, 0, 0, .02);
        }
        .mail-toolbar {
            min-height: 58px;
            padding: 0 18px;
            border-bottom: 1px solid var(--line);
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 14px;
        }
        .mail-toolbar h1 { margin: 0; font-size: 18px; font-weight: 700; }
        .list-count { color: var(--muted); font-size: 13px; white-space: nowrap; }
        .mail-notice { margin: 14px 18px 0; }
        .mail-list { border-top: 1px solid #f1f3f4; }
        .mail-row {
            display: grid;
            grid-template-columns: 40px minmax(120px, 210px) minmax(0, 1fr) 88px;
            gap: 12px;
            align-items: center;
            min-height: 42px;
            padding: 0 18px;
            border-bottom: 1px solid #edf0f2;
            background: #fff;
            color: #202124;
        }
        .mail-row:hover { box-shadow: inset 1px 0 #dadce0, inset -1px 0 #dadce0, 0 1px 2px rgba(60, 64, 67, .18); z-index: 2; position: relative; }
        .mail-row.unread { background: #f2f6fc; font-weight: 700; }
        .mail-check {
            width: 14px; height: 14px; border: 2px solid #c4c7c5; border-radius: 2px;
        }
        .sender, .subject-line, .date { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .snippet { color: var(--muted); font-weight: 400; }
        .date { text-align: right; font-size: 12px; color: #3c4043; }
        .empty-state {
            min-height: 320px;
            display: grid;
            place-items: center;
            text-align: center;
            color: var(--muted);
            padding: 34px;
        }
        .empty-state h2 { color: var(--text); margin: 0 0 8px; font-size: 22px; }

        .message-panel {
            border-top: 1px solid var(--line);
            padding: 28px min(64px, 6vw) 48px;
            background: #fff;
            position: relative;
        }
        .message-header {
            display: grid;
            grid-template-columns: minmax(0, 1fr) 40px;
            gap: 16px;
            align-items: start;
            margin-bottom: 18px;
        }
        .message-panel h2 { margin: 0; font-size: 28px; letter-spacing: 0; padding-right: 8px; }
        .message-close {
            width: 36px;
            height: 36px;
            border-radius: 50%;
            display: inline-grid;
            place-items: center;
            color: #444746;
            justify-self: end;
        }
        .message-close:hover { background: #f1f3f4; }
        .message-meta {
            display: grid;
            grid-template-columns: 44px 1fr auto;
            gap: 12px;
            align-items: center;
            color: #3c4043;
            margin-bottom: 22px;
        }
        .sender-avatar {
            width: 40px; height: 40px; border-radius: 50%; background: #1a73e8; color: #fff;
            display: grid; place-items: center; font-weight: 700;
        }
        .message-body {
            white-space: pre-wrap;
            line-height: 1.58;
            max-width: 920px;
            margin-left: 56px;
        }
        .expert-box {
            margin: 22px 0 0 56px;
            max-width: 920px;
            border: 1px solid var(--line);
            background: #f8fafd;
            border-radius: 8px;
            padding: 14px 16px;
        }
        .expert-box strong { display: block; margin-bottom: 8px; }
        .expert-box ul { margin: 8px 0 0; padding-left: 20px; }
        .attachment {
            margin: 22px 0 0 56px;
            max-width: 520px;
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 12px;
            display: grid;
            gap: 10px;
            background: #fff;
        }
        .attachment img { max-width: 100%; border-radius: 6px; border: 1px solid var(--line); }
        .attachment a { color: #0b57d0; font-weight: 700; }
        .message-actions {
            margin: 28px 0 0 56px;
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }
        .reply-button {
            height: 38px;
            border: 1px solid #dadce0;
            border-radius: 20px;
            background: #fff;
            color: #3c4043;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 0 16px;
            cursor: pointer;
            font-weight: 700;
        }
        .reply-button:hover { background: #f7f8f8; border-color: #c4c7c5; }

        .compose-window {
            position: fixed;
            right: 28px;
            bottom: 0;
            z-index: 40;
            width: min(620px, calc(100vw - 28px));
            height: min(620px, calc(100vh - 90px));
            background: #fff;
            border-radius: 8px 8px 0 0;
            box-shadow: var(--shadow);
            display: grid;
            grid-template-rows: 40px auto;
            overflow: hidden;
        }
        .compose-title {
            background: #f2f6fc;
            color: #041e49;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 12px 0 16px;
            font-size: 14px;
            font-weight: 700;
        }
        .compose-title button { border: 0; background: transparent; cursor: pointer; color: #444746; padding: 6px; }
        .compose-form { display: grid; grid-template-rows: auto auto 1fr auto; min-height: 0; }
        .compose-form input, .compose-form textarea {
            border: 0;
            border-bottom: 1px solid var(--line);
            outline: 0;
            padding: 12px 16px;
            width: 100%;
            resize: none;
        }
        .compose-form textarea { border-bottom: 0; min-height: 220px; }
        .compose-actions {
            border-top: 1px solid var(--line);
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 12px 16px;
        }
        .send-button {
            min-width: 96px;
            border: 0;
            border-radius: 999px;
            padding: 10px 18px;
            background: #0b57d0;
            color: #fff;
            font-weight: 700;
            cursor: pointer;
        }
        .tool-button {
            width: 34px; height: 34px;
            border: 0;
            border-radius: 50%;
            background: transparent;
            color: #444746;
            display: grid;
            place-items: center;
            cursor: pointer;
        }
        .tool-button:hover { background: #f1f3f4; }
        .file-name { color: var(--muted); font-size: 13px; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .compose-error { color: #a50e0e; font-size: 13px; margin-left: auto; }

        @media (max-width: 860px) {
            .auth-page { grid-template-columns: 1fr; }
            .auth-brand { min-height: auto; padding: 28px; gap: 32px; }
            .auth-copy h1 { font-size: 38px; }
            .auth-panel-wrap { padding: 0 18px 28px; }
            .topbar { grid-template-columns: auto 1fr auto; padding-left: 12px; gap: 10px; }
            .topbar .brand span { display: none; }
            .search { grid-column: 1 / -1; order: 2; height: 42px; }
            .mail-shell { grid-template-columns: 82px minmax(0, 1fr); min-height: calc(100vh - 116px); }
            .sidebar { padding: 8px; }
            .compose-button { width: 58px; min-width: 58px; border-radius: 18px; }
            .compose-button span, .nav-item span.label { display: none; }
            .nav-item { grid-template-columns: 28px; justify-content: center; border-radius: 18px; padding: 0; }
            .badge { position: absolute; transform: translate(18px, -10px); background: #0b57d0; color: #fff; border-radius: 10px; padding: 1px 5px; min-width: auto; }
            .mail-row { grid-template-columns: minmax(96px, 35%) minmax(0, 1fr) 54px; padding: 0 10px; gap: 8px; }
            .mail-check { display: none; }
            .message-meta { grid-template-columns: 40px 1fr; }
            .message-meta .date { grid-column: 2; text-align: left; }
            .message-body, .expert-box, .attachment, .message-actions { margin-left: 0; }
            .compose-window { right: 8px; width: calc(100vw - 16px); }
        }
    </style>
    """


def icon(name: str) -> str:
    paths = {
        "menu": '<path d="M4 6h16M4 12h16M4 18h16"/>',
        "search": '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
        "settings": '<path d="M12 15.5A3.5 3.5 0 1 0 12 8a3.5 3.5 0 0 0 0 7.5Z"/><path d="M19.4 15a1.8 1.8 0 0 0 .36 1.98l.05.05a2.1 2.1 0 0 1-2.97 2.97l-.05-.05a1.8 1.8 0 0 0-1.98-.36 1.8 1.8 0 0 0-1.08 1.65V21a2.1 2.1 0 0 1-4.2 0v-.08a1.8 1.8 0 0 0-1.08-1.65 1.8 1.8 0 0 0-1.98.36l-.05.05a2.1 2.1 0 0 1-2.97-2.97l.05-.05A1.8 1.8 0 0 0 4.6 15a1.8 1.8 0 0 0-1.65-1.08H3a2.1 2.1 0 0 1 0-4.2h.08A1.8 1.8 0 0 0 4.73 8.64a1.8 1.8 0 0 0-.36-1.98l-.05-.05a2.1 2.1 0 0 1 2.97-2.97l.05.05a1.8 1.8 0 0 0 1.98.36H9.4A1.8 1.8 0 0 0 10.5 2.4V2a2.1 2.1 0 0 1 4.2 0v.08a1.8 1.8 0 0 0 1.08 1.65h.08a1.8 1.8 0 0 0 1.98-.36l.05-.05a2.1 2.1 0 0 1 2.97 2.97l-.05.05a1.8 1.8 0 0 0-.36 1.98v.08a1.8 1.8 0 0 0 1.65 1.08H21a2.1 2.1 0 0 1 0 4.2h-.08A1.8 1.8 0 0 0 19.4 15Z"/>',
        "pencil": '<path d="M18.5 2.5a2.1 2.1 0 0 1 3 3L8 19l-4 1 1-4L18.5 2.5Z"/><path d="m15 6 3 3"/>',
        "inbox": '<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="m5.5 4-3 8v7a2 2 0 0 0 2 2h15a2 2 0 0 0 2-2v-7l-3-8Z"/>',
        "sent": '<path d="m22 2-7 20-4-9-9-4 20-7Z"/><path d="M22 2 11 13"/>',
        "spam": '<path d="M12 2 2 8.5v7L12 22l10-6.5v-7L12 2Z"/><path d="M12 8v5"/><path d="M12 17h.01"/>',
        "reply": '<path d="m9 17-5-5 5-5"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/>',
        "logout": '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/>',
        "paperclip": '<path d="m21.4 11.6-8.5 8.5a6 6 0 0 1-8.5-8.5l9.2-9.2a4 4 0 0 1 5.7 5.7l-9.2 9.2a2 2 0 1 1-2.8-2.8l8.5-8.5"/>',
        "close": '<path d="M18 6 6 18M6 6l12 12"/>',
        "help": '<circle cx="12" cy="12" r="10"/><path d="M9.1 9a3 3 0 1 1 5.1 2.1c-.9.9-2.2 1.3-2.2 2.9"/><path d="M12 17h.01"/>',
    }
    return (
        '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        f"{paths.get(name, '')}</svg>"
    )


def auth_page(error: str = "") -> str:
    alert = f'<div class="alert error">{escape(error)}</div>' if error else ""
    return f"""<!doctype html>
    <html lang="es">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{APP_TITLE} - Sistema experto</title>
        {shared_styles()}
    </head>
    <body>
        <main class="auth-page">
            <section class="auth-brand">
                <div class="brand-row"><span class="gmail-mark"></span><strong>{APP_TITLE}</strong></div>
                <div class="auth-copy">
                    <h1>Correo con filtro experto de spam</h1>
                    <p>Inicia sesion, envia mensajes entre usuarios y deja que el motor de reglas decida si llegan a Recibidos o a Spam.</p>
                </div>
                <p class="muted">SQLite guarda usuarios, bandejas y resultados del sistema experto.</p>
            </section>

            <section class="auth-panel-wrap">
                <div class="auth-panel">
                    <div class="tabs" role="tablist">
                        <button class="tab active" type="button" data-tab="login">Iniciar sesion</button>
                        <button class="tab" type="button" data-tab="register">Crear cuenta</button>
                    </div>
                    {alert}
                    <form class="auth-form" id="login" method="post" action="/login">
                        <h2>Bienvenido</h2>
                        <div class="field">
                            <label for="login-email">Correo</label>
                            <input id="login-email" name="email" type="text" inputmode="email" autocomplete="email" required placeholder="usuario@correo.com">
                        </div>
                        <div class="field">
                            <label for="login-password">Contrasena</label>
                            <input id="login-password" name="password" type="password" autocomplete="current-password" required minlength="4">
                        </div>
                        <button class="primary-button" type="submit">Entrar</button>
                    </form>

                    <form class="auth-form hide" id="register" method="post" action="/register">
                        <h2>Crear usuario</h2>
                        <div class="field">
                            <label for="register-email">Correo</label>
                            <input id="register-email" name="email" type="text" inputmode="email" autocomplete="email" required placeholder="nuevo@correo.com">
                        </div>
                        <div class="field">
                            <label for="register-password">Contrasena</label>
                            <input id="register-password" name="password" type="password" autocomplete="new-password" required minlength="4">
                        </div>
                        <button class="primary-button" type="submit">Crear y entrar</button>
                    </form>
                </div>
            </section>
        </main>
        <script>
            const tabs = document.querySelectorAll('.tab');
            const forms = {{
                login: document.getElementById('login'),
                register: document.getElementById('register')
            }};
            tabs.forEach(tab => tab.addEventListener('click', () => {{
                tabs.forEach(item => item.classList.remove('active'));
                tab.classList.add('active');
                Object.values(forms).forEach(form => form.classList.add('hide'));
                forms[tab.dataset.tab].classList.remove('hide');
            }}));
        </script>
    </body>
    </html>"""


def get_mail_counts(user_id: int) -> tuple[int, int]:
    with db() as connection:
        inbox_count = connection.execute(
            "SELECT COUNT(*) FROM inbox_emails WHERE recipient_id = ? AND is_read = 0", (user_id,)
        ).fetchone()[0]
        spam_count = connection.execute(
            "SELECT COUNT(*) FROM spam_emails WHERE recipient_id = ? AND is_read = 0", (user_id,)
        ).fetchone()[0]
    return inbox_count, spam_count


def mark_read(user_id: int, box: str, message_id: int) -> None:
    if box == "sent":
        return
    table = "spam_emails" if box == "spam" else "inbox_emails"
    with db() as connection:
        connection.execute(
            f"UPDATE {table} SET is_read = 1 WHERE id = ? AND recipient_id = ?",
            (message_id, user_id),
        )


def fetch_message(user_id: int, box: str, message_id: int) -> sqlite3.Row | None:
    table = "sent_emails" if box == "sent" else "spam_emails" if box == "spam" else "inbox_emails"
    owner_column = "sender_id" if box == "sent" else "recipient_id"
    with db() as connection:
        return connection.execute(
            f"SELECT * FROM {table} WHERE id = ? AND {owner_column} = ?",
            (message_id, user_id),
        ).fetchone()


def fetch_messages(user_id: int, box: str) -> list[sqlite3.Row]:
    table = "sent_emails" if box == "sent" else "spam_emails" if box == "spam" else "inbox_emails"
    owner_column = "sender_id" if box == "sent" else "recipient_id"
    with db() as connection:
        return list(
            connection.execute(
                f"SELECT * FROM {table} WHERE {owner_column} = ? ORDER BY datetime(created_at) DESC, id DESC",
                (user_id,),
            )
        )


def flash_from_query(query: dict[str, list[str]]) -> str:
    if query.get("sent") == ["1"]:
        return '<div class="alert ok mail-notice">Correo enviado. El sistema experto ya lo clasifico para el destinatario.</div>'
    if "error" in query:
        return f'<div class="alert error mail-notice">{escape(query["error"][0])}</div>'
    return ""


def mail_rows(messages: list[sqlite3.Row], box: str) -> str:
    if not messages:
        title = "No hay correos en Recibidos" if box == "inbox" else "No hay correos en Spam"
        copy = "Cuando otro usuario te escriba, apareceran aqui los mensajes normales." if box == "inbox" else "Aqui veras los mensajes que activen las reglas del sistema experto."
        return f"""
        <div class="empty-state">
            <div>
                <h2>{title}</h2>
                <p>{copy}</p>
            </div>
        </div>
        """

    rows = []
    for message in messages:
        unread = " unread" if not message["is_read"] else ""
        subject = escape(message["subject"] or "(Sin asunto)")
        snippet = escape(truncate(message["body"]))
        attachment = " · Adjunto" if message["attachment_name"] else ""
        rows.append(
            f"""
            <a class="mail-row{unread}" href="/mail?box={box}&message={message['id']}" data-search="{escape((message['sender_email'] + ' ' + message['subject'] + ' ' + message['body']).lower())}">
                <span class="mail-check" aria-hidden="true"></span>
                <span class="sender">{escape(message['sender_email'])}</span>
                <span class="subject-line">{subject} <span class="snippet">- {snippet}{attachment}</span></span>
                <span class="date">{nice_date(message['created_at'])}</span>
            </a>
            """
        )
    return "".join(rows)


def message_detail(message: sqlite3.Row | None, box: str) -> str:
    if not message:
        return ""
    reasons = json.loads(message["expert_reasons"] or "[]")
    score_label = f"Puntaje experto: {message['expert_score']}"
    box_label = "Spam" if box == "spam" else "Recibidos"
    initials = escape(message["sender_email"][:1].upper())
    reasons_html = "".join(f"<li>{escape(reason)}</li>" for reason in reasons)
    attachment_html = ""
    if message["attachment_name"]:
        if (message["attachment_mime"] or "").startswith("image/") and message["attachment_data"]:
            attachment_html = f"""
            <div class="attachment">
                <strong>{escape(message['attachment_name'])}</strong>
                <img src="data:{escape(message['attachment_mime'])};base64,{message['attachment_data']}" alt="{escape(message['attachment_name'])}">
                <a href="/attachment?box={box}&id={message['id']}">Descargar archivo</a>
            </div>
            """
        else:
            attachment_html = f"""
            <div class="attachment">
                <strong>{escape(message['attachment_name'])}</strong>
                <a href="/attachment?box={box}&id={message['id']}">Descargar archivo</a>
            </div>
            """

    return f"""
    <article class="message-panel">
        <h2>{escape(message['subject'] or '(Sin asunto)')}</h2>
        <div class="message-meta">
            <span class="sender-avatar">{initials}</span>
            <div>
                <strong>{escape(message['sender_email'])}</strong>
                <div class="muted">para {escape(message['recipient_email'])}</div>
            </div>
            <div class="date">{escape(message['created_at'])}</div>
        </div>
        <div class="message-body">{escape(message['body'])}</div>
        {attachment_html}
        <div class="expert-box">
            <strong>{score_label} · Guardado en {box_label}</strong>
            <span class="muted">Reglas activadas al recibir este correo:</span>
            <ul>{reasons_html}</ul>
        </div>
    </article>
    """


def mail_page(user: sqlite3.Row, box: str, query: dict[str, list[str]], selected: sqlite3.Row | None = None) -> str:
    inbox_unread, spam_unread = get_mail_counts(user["id"])
    messages = fetch_messages(user["id"], box)
    current_label = BOX_LABELS.get(box, "Recibidos")
    total = len(messages)
    notice = flash_from_query(query)
    initial = escape(user["email"][:1].upper())
    inbox_badge = f"+{inbox_unread}" if inbox_unread else ""
    spam_badge = f"+{spam_unread}" if spam_unread else ""
    return f"""<!doctype html>
    <html lang="es">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{current_label} - {APP_TITLE}</title>
        {shared_styles()}
    </head>
    <body>
        <header class="topbar">
            <div class="brand">
                <button class="round-icon" type="button" aria-label="Menu">{icon('menu')}</button>
                <span class="gmail-mark"></span>
                <span>{APP_TITLE}</span>
            </div>
            <label class="search" aria-label="Buscar correos">
                {icon('search')}
                <input id="searchBox" type="search" placeholder="Buscar en el correo electronico">
            </label>
            <div class="top-actions">
                <button class="round-icon" type="button" title="Ayuda">{icon('help')}</button>
                <button class="round-icon" type="button" title="Configuracion">{icon('settings')}</button>
            </div>
            <div class="account">
                <button class="avatar" id="accountButton" type="button" aria-label="Cuenta">{initial}</button>
                <div class="account-menu hide" id="accountMenu">
                    <strong>{escape(user['email'])}</strong>
                    <span class="muted">Sesion activa</span>
                    <a href="/logout">{icon('logout')} Cerrar sesion</a>
                </div>
            </div>
        </header>

        <main class="mail-shell">
            <aside class="sidebar">
                <button class="compose-button" id="composeOpen" type="button">{icon('pencil')}<span>Redactar</span></button>
                <nav class="nav-list" aria-label="Carpetas">
                    <a class="nav-item {'active' if box == 'inbox' else ''}" href="/mail?box=inbox">
                        {icon('inbox')}<span class="label">Recibidos</span><span class="badge">{inbox_badge}</span>
                    </a>
                    <a class="nav-item {'active' if box == 'sent' else ''}" href="/mail?box=sent">
                        {icon('sent')}<span class="label">Enviados</span><span class="badge"></span>
                    </a>
                    <a class="nav-item {'active' if box == 'spam' else ''}" href="/mail?box=spam">
                        {icon('spam')}<span class="label">Spam</span><span class="badge">{spam_badge}</span>
                    </a>
                </nav>
            </aside>

            <section class="mail-area">
                <div class="mail-toolbar">
                    <h1>{current_label}</h1>
                    <span class="list-count">{'0' if total == 0 else '1-' + str(total)} de {total}</span>
                </div>
                {notice}
                <div class="mail-list" id="mailList">{mail_rows(messages, box)}</div>
                {message_detail(selected, box)}
            </section>
        </main>

        <section class="compose-window hide" id="composeWindow" aria-label="Mensaje nuevo">
            <div class="compose-title">
                <span>Mensaje nuevo</span>
                <button type="button" id="composeClose" aria-label="Cerrar">{icon('close')}</button>
            </div>
            <form class="compose-form" id="composeForm">
                <input name="recipient" type="text" inputmode="email" placeholder="Destinatarios" autocomplete="off" required>
                <input name="subject" type="text" placeholder="Asunto" maxlength="160">
                <textarea name="body" placeholder="" required></textarea>
                <div class="compose-actions">
                    <button class="send-button" type="submit">Enviar</button>
                    <label class="tool-button" title="Adjuntar archivo">
                        {icon('paperclip')}
                        <input id="fileInput" type="file" hidden>
                    </label>
                    <span class="file-name" id="fileName"></span>
                    <span class="compose-error" id="composeError"></span>
                </div>
            </form>
        </section>

        <script>
            const currentBox = "{box}";
            const accountButton = document.getElementById('accountButton');
            const accountMenu = document.getElementById('accountMenu');
            accountButton.addEventListener('click', () => accountMenu.classList.toggle('hide'));
            document.addEventListener('click', (event) => {{
                if (!event.target.closest('.account')) accountMenu.classList.add('hide');
            }});

            const composeWindow = document.getElementById('composeWindow');
            const composeOpen = document.getElementById('composeOpen');
            const composeClose = document.getElementById('composeClose');
            const composeForm = document.getElementById('composeForm');
            const composeError = document.getElementById('composeError');
            const fileInput = document.getElementById('fileInput');
            const fileName = document.getElementById('fileName');
            composeOpen.addEventListener('click', () => {{
                composeWindow.classList.remove('hide');
                composeForm.recipient.focus();
            }});
            composeClose.addEventListener('click', () => composeWindow.classList.add('hide'));
            function replySubject(subject) {{
                const clean = (subject || '').trim();
                if (!clean) return 'Re: (Sin asunto)';
                return clean.toLowerCase().startsWith('re:') ? clean : `Re: ${{clean}}`;
            }}
            document.querySelectorAll('.reply-button').forEach(button => {{
                button.addEventListener('click', () => {{
                    composeWindow.classList.remove('hide');
                    composeForm.recipient.value = button.dataset.replyTo || '';
                    composeForm.subject.value = replySubject(button.dataset.replySubject || '');
                    composeForm.body.value = '';
                    composeForm.body.focus();
                }});
            }});
            fileInput.addEventListener('change', () => {{
                fileName.textContent = fileInput.files[0] ? fileInput.files[0].name : '';
            }});

            function readAttachment(file) {{
                return new Promise((resolve, reject) => {{
                    if (!file) return resolve(null);
                    if (file.size > {MAX_ATTACHMENT_BYTES}) {{
                        reject(new Error('El archivo no puede pesar mas de 2 MB.'));
                        return;
                    }}
                    const reader = new FileReader();
                    reader.onload = () => resolve({{
                        name: file.name,
                        mime: file.type || 'application/octet-stream',
                        data: String(reader.result).split(',')[1] || ''
                    }});
                    reader.onerror = () => reject(new Error('No se pudo leer el archivo.'));
                    reader.readAsDataURL(file);
                }});
            }}

            composeForm.addEventListener('submit', async (event) => {{
                event.preventDefault();
                composeError.textContent = '';
                const button = composeForm.querySelector('.send-button');
                button.disabled = true;
                button.textContent = 'Enviando';
                try {{
                    const attachment = await readAttachment(fileInput.files[0]);
                    const response = await fetch('/api/send', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{
                            recipient: composeForm.recipient.value,
                            subject: composeForm.subject.value,
                            body: composeForm.body.value,
                            attachment
                        }})
                    }});
                    const data = await response.json();
                    if (!response.ok) throw new Error(data.error || 'No se pudo enviar el correo.');
                    window.location.href = `/mail?box=${{currentBox}}&sent=1`;
                }} catch (error) {{
                    composeError.textContent = error.message;
                }} finally {{
                    button.disabled = false;
                    button.textContent = 'Enviar';
                }}
            }});

            const searchBox = document.getElementById('searchBox');
            searchBox.addEventListener('input', () => {{
                const term = searchBox.value.trim().toLowerCase();
                document.querySelectorAll('.mail-row').forEach(row => {{
                    row.style.display = row.dataset.search.includes(term) ? '' : 'none';
                }});
            }});
        </script>
    </body>
    </html>"""


def mail_rows(messages: list[sqlite3.Row], box: str) -> str:
    if not messages:
        if box == "sent":
            title = "No hay correos enviados"
            copy = "Cuando redactes y envies un correo, aparecera aqui como en Gmail."
        elif box == "spam":
            title = "No hay correos en Spam"
            copy = "Aqui veras los mensajes que activen las reglas del sistema experto."
        else:
            title = "No hay correos en Recibidos"
            copy = "Cuando otro usuario te escriba, apareceran aqui los mensajes normales."
        return f"""
        <div class="empty-state">
            <div>
                <h2>{title}</h2>
                <p>{copy}</p>
            </div>
        </div>
        """

    rows = []
    for message in messages:
        unread = "" if box == "sent" else " unread" if not message["is_read"] else ""
        person = message["recipient_email"] if box == "sent" else message["sender_email"]
        person_label = f"Para: {person}" if box == "sent" else person
        subject = escape(message["subject"] or "(Sin asunto)")
        snippet = escape(truncate(message["body"]))
        attachment = " - Adjunto" if message["attachment_name"] else ""
        search_text = f"{person} {message['subject']} {message['body']}".lower()
        rows.append(
            f"""
            <a class="mail-row{unread}" href="/mail?box={box}&message={message['id']}" data-search="{escape(search_text)}">
                <span class="mail-check" aria-hidden="true"></span>
                <span class="sender">{escape(person_label)}</span>
                <span class="subject-line">{subject} <span class="snippet">- {snippet}{attachment}</span></span>
                <span class="date">{nice_date(message['created_at'])}</span>
            </a>
            """
        )
    return "".join(rows)


def message_detail(message: sqlite3.Row | None, box: str) -> str:
    if not message:
        return ""
    reasons = json.loads(message["expert_reasons"] or "[]")
    score_label = f"Puntaje experto: {message['expert_score']}"
    subject = message["subject"] or "(Sin asunto)"
    close_url = f"/mail?box={box}"
    if box == "sent":
        destination = "Spam" if message["classified_as"] == "spam" else "Recibidos"
        expert_title = f"{score_label} - El destinatario lo recibio en {destination}"
        expert_intro = "Reglas aplicadas al enviar este correo:"
        initials = escape(message["recipient_email"][:1].upper())
        primary = "Tu"
        secondary = f"para {message['recipient_email']}"
        reply_html = ""
    else:
        box_label = "Spam" if box == "spam" else "Recibidos"
        expert_title = f"{score_label} - Guardado en {box_label}"
        expert_intro = "Reglas activadas al recibir este correo:"
        initials = escape(message["sender_email"][:1].upper())
        primary = message["sender_email"]
        secondary = f"para {message['recipient_email']}"
        reply_subject = subject if subject != "(Sin asunto)" else ""
        reply_html = f"""
        <div class="message-actions">
            <button class="reply-button" type="button" data-reply-to="{escape(message['sender_email'])}" data-reply-subject="{escape(reply_subject)}">
                {icon('reply')} Responder
            </button>
        </div>
        """

    reasons_html = "".join(f"<li>{escape(reason)}</li>" for reason in reasons)
    attachment_html = ""
    if message["attachment_name"]:
        if message["attachment_data"] and (message["attachment_mime"] or "").startswith("image/"):
            attachment_html = f"""
            <div class="attachment">
                <strong>{escape(message['attachment_name'])}</strong>
                <img src="data:{escape(message['attachment_mime'])};base64,{message['attachment_data']}" alt="{escape(message['attachment_name'])}">
                <a href="/attachment?box={box}&id={message['id']}">Descargar archivo</a>
            </div>
            """
        elif message["attachment_data"]:
            attachment_html = f"""
            <div class="attachment">
                <strong>{escape(message['attachment_name'])}</strong>
                <a href="/attachment?box={box}&id={message['id']}">Descargar archivo</a>
            </div>
            """
        else:
            attachment_html = f"""
            <div class="attachment">
                <strong>{escape(message['attachment_name'])}</strong>
                <span class="muted">Archivo adjunto registrado.</span>
            </div>
            """

    return f"""
    <article class="message-panel">
        <div class="message-header">
            <h2>{escape(subject)}</h2>
            <a class="message-close" href="{close_url}" aria-label="Cerrar correo" title="Cerrar correo">{icon('close')}</a>
        </div>
        <div class="message-meta">
            <span class="sender-avatar">{initials}</span>
            <div>
                <strong>{escape(primary)}</strong>
                <div class="muted">{escape(secondary)}</div>
            </div>
            <div class="date">{escape(message['created_at'])}</div>
        </div>
        <div class="message-body">{escape(message['body'])}</div>
        {attachment_html}
        {reply_html}
        <div class="expert-box">
            <strong>{expert_title}</strong>
            <span class="muted">{expert_intro}</span>
            <ul>{reasons_html}</ul>
        </div>
    </article>
    """


class MailHandler(BaseHTTPRequestHandler):
    server_version = "GmailSE/1.0"

    def log_message(self, format: str, *args: object) -> None:
        safe_log(f"{self.address_string()} - {format % args}")

    def send_html(self, content: str, status: int = 200, extra_headers: dict[str, str] | None = None) -> None:
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, payload: dict[str, object], status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location: str, headers: dict[str, str] | None = None) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()

    def current_user(self) -> sqlite3.Row | None:
        header = self.headers.get("Cookie")
        if not header:
            return None
        jar = cookies.SimpleCookie()
        try:
            jar.load(header)
        except cookies.CookieError:
            return None
        token = jar.get("session")
        if not token:
            return None
        user_id = SESSIONS.get(token.value)
        if not user_id:
            return None
        return get_user_by_id(user_id)

    def require_user(self) -> sqlite3.Row | None:
        user = self.current_user()
        if not user:
            self.redirect("/")
            return None
        return user

    def read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(length)

    def read_form(self) -> dict[str, str]:
        body = self.read_body().decode("utf-8")
        parsed = parse_qs(body)
        return {key: values[0] if values else "" for key, values in parsed.items()}

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == "/":
            user = self.current_user()
            if user:
                self.redirect("/mail?box=inbox")
            else:
                self.send_html(auth_page())
            return

        if parsed.path == "/logout":
            token = None
            header = self.headers.get("Cookie")
            if header:
                jar = cookies.SimpleCookie()
                jar.load(header)
                if "session" in jar:
                    token = jar["session"].value
            if token:
                SESSIONS.pop(token, None)
            expired = "session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
            self.redirect("/", {"Set-Cookie": expired})
            return

        if parsed.path == "/mail":
            user = self.require_user()
            if not user:
                return
            box = query.get("box", ["inbox"])[0]
            if box not in {"inbox", "spam", "sent"}:
                box = "inbox"
            selected = None
            if "message" in query:
                try:
                    message_id = int(query["message"][0])
                except (ValueError, TypeError):
                    message_id = 0
                if message_id:
                    mark_read(user["id"], box, message_id)
                    selected = fetch_message(user["id"], box, message_id)
            self.send_html(mail_page(user, box, query, selected))
            return

        if parsed.path == "/attachment":
            user = self.require_user()
            if not user:
                return
            box = query.get("box", ["inbox"])[0]
            if box not in {"inbox", "spam", "sent"}:
                box = "inbox"
            try:
                message_id = int(query.get("id", ["0"])[0])
            except ValueError:
                message_id = 0
            message = fetch_message(user["id"], box, message_id)
            if not message or not message["attachment_data"]:
                self.send_html(auth_page("Archivo no encontrado."), 404)
                return
            data = base64.b64decode(message["attachment_data"])
            mime = message["attachment_mime"] or mimetypes.guess_type(message["attachment_name"] or "")[0] or "application/octet-stream"
            filename = quote(message["attachment_name"] or "archivo")
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{filename}")
            self.end_headers()
            self.wfile.write(data)
            return

        self.send_html(auth_page("Ruta no encontrada."), 404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/register":
            form = self.read_form()
            email = (form.get("email") or "").strip().lower()
            password = form.get("password") or ""
            if not valid_email(email):
                self.send_html(auth_page("Escribe un correo valido."), 400)
                return
            if len(password) < 4:
                self.send_html(auth_page("La contrasena debe tener al menos 4 caracteres."), 400)
                return
            try:
                with db() as connection:
                    cursor = connection.execute(
                        "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                        (email, password_hash(password), now_text()),
                    )
                    user_id = cursor.lastrowid
            except sqlite3.IntegrityError:
                self.send_html(auth_page("Ese correo ya existe. Inicia sesion."), 409)
                return
            token = create_session(int(user_id))
            self.redirect("/mail?box=inbox", {"Set-Cookie": f"session={token}; Path=/; HttpOnly; SameSite=Lax"})
            return

        if parsed.path == "/login":
            form = self.read_form()
            email = (form.get("email") or "").strip().lower()
            password = form.get("password") or ""
            user = get_user_by_email(email)
            if not user or not verify_password(password, user["password_hash"]):
                self.send_html(auth_page("Correo o contrasena incorrectos."), 401)
                return
            token = create_session(int(user["id"]))
            self.redirect("/mail?box=inbox", {"Set-Cookie": f"session={token}; Path=/; HttpOnly; SameSite=Lax"})
            return

        if parsed.path == "/api/send":
            user = self.require_user()
            if not user:
                return
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length > MAX_JSON_BYTES:
                self.send_json({"error": "El mensaje es demasiado grande."}, 413)
                return
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
            except json.JSONDecodeError:
                self.send_json({"error": "Solicitud invalida."}, 400)
                return

            recipient_email = (payload.get("recipient") or "").strip().lower()
            subject = (payload.get("subject") or "").strip()
            body = (payload.get("body") or "").strip()
            attachment = payload.get("attachment") or {}

            if not valid_email(recipient_email):
                self.send_json({"error": "Escribe un destinatario valido."}, 400)
                return
            if not body:
                self.send_json({"error": "El mensaje no puede estar vacio."}, 400)
                return
            recipient = get_user_by_email(recipient_email)
            if not recipient:
                self.send_json({"error": "El destinatario no existe. Primero crea ese usuario."}, 404)
                return

            attachment_name = ""
            attachment_mime = ""
            attachment_data = ""
            if isinstance(attachment, dict) and attachment.get("data"):
                attachment_name = str(attachment.get("name") or "archivo").strip()[:160]
                attachment_mime = str(attachment.get("mime") or "application/octet-stream").strip()[:120]
                attachment_data = str(attachment.get("data") or "")
                try:
                    decoded_size = len(base64.b64decode(attachment_data, validate=True))
                except ValueError:
                    self.send_json({"error": "El archivo adjunto no es valido."}, 400)
                    return
                if decoded_size > MAX_ATTACHMENT_BYTES:
                    self.send_json({"error": "El archivo no puede pesar mas de 2 MB."}, 413)
                    return

            destination, score, reasons = store_mail(
                user,
                recipient,
                subject,
                body,
                attachment_name,
                attachment_mime,
                attachment_data,
            )
            self.send_json({"ok": True, "destination": destination, "score": score, "reasons": reasons})
            return

        self.send_json({"error": "Ruta no encontrada."}, 404)


def run_server(port: int) -> None:
    init_db()
    server = ThreadingHTTPServer((HOST, port), MailHandler)
    safe_log(f"{APP_TITLE} listo en http://{HOST}:{port}")
    safe_log(f"Base de datos: {DB_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        safe_log("Servidor detenido.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sistema experto de filtrado de spam con SQLite.")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", DEFAULT_PORT)))
    args = parser.parse_args()
    run_server(args.port)
