import hashlib
import hmac
import mimetypes
import os
import secrets
import uuid
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Optional

import phonenumbers
from boto3 import client as boto3_client
from botocore.client import Config as BotoConfig
from dotenv import load_dotenv
from flask import Flask, g, jsonify, redirect, render_template, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, join_room
from sqlalchemy import func
from werkzeug.utils import secure_filename

try:
    from twilio.rest import Client as TwilioClient
except Exception:  # pragma: no cover
    TwilioClient = None


load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

db = SQLAlchemy()
socketio = SocketIO(async_mode="threading", cors_allowed_origins=[], manage_session=False)


def utcnow() -> datetime:
    return datetime.utcnow()


def new_uuid() -> str:
    return str(uuid.uuid4())


def get_database_uri() -> str:
    database_url = os.getenv("DATABASE_URL", "").strip()
    if database_url:
        if database_url.startswith("postgresql://"):
            database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)
        return database_url
    return f"sqlite:///{BASE_DIR / 'messenger.db'}"


def hash_secret(value: str) -> str:
    secret = os.getenv("SECRET_KEY", "change-me")
    return hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def json_error(message: str, status: int = 400):
    return jsonify({"ok": False, "error": message}), status


def parse_phone(phone_raw: str) -> str:
    phone_raw = (phone_raw or "").strip()
    if not phone_raw:
        raise ValueError("Укажите номер телефона.")
    try:
        parsed = phonenumbers.parse(phone_raw, None)
    except phonenumbers.NumberParseException as exc:
        raise ValueError("Некорректный номер телефона.") from exc
    if not phonenumbers.is_valid_number(parsed):
        raise ValueError("Некорректный номер телефона.")
    return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)


def client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def allowed_file(filename: str) -> bool:
    ext = Path(filename).suffix.lower()
    return ext in {
        ".png", ".jpg", ".jpeg", ".gif", ".webp",
        ".mp4", ".webm", ".mov", ".m4v",
        ".mp3", ".wav", ".ogg", ".m4a",
        ".pdf", ".txt", ".zip",
    }


def attachment_kind_from_mime(mime_type: str, filename: str) -> str:
    mime_type = mime_type or mimetypes.guess_type(filename)[0] or "application/octet-stream"
    if mime_type.startswith("image/"):
        return "image"
    if mime_type.startswith("video/"):
        return "video"
    if mime_type.startswith("audio/"):
        return "audio"
    return "file"


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = get_database_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "connect_args": {
            "prepare_threshold": None,
        },
    }

    SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "ume_session")
    SESSION_COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0") == "1"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "Lax")

    APP_NAME = os.getenv("APP_NAME", "UMe")
    APP_ENV = os.getenv("APP_ENV", "development")
    MEDIA_BASE_URL = os.getenv("MEDIA_BASE_URL", "")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(25 * 1024 * 1024)))
    AUTH_CODE_TTL_SECONDS = int(os.getenv("AUTH_CODE_TTL_SECONDS", "300"))
    AUTH_CODE_MAX_ATTEMPTS = int(os.getenv("AUTH_CODE_MAX_ATTEMPTS", "5"))
    AUTH_CODE_RESEND_WINDOW_SECONDS = int(os.getenv("AUTH_CODE_RESEND_WINDOW_SECONDS", "60"))
    AUTH_CODE_RATE_LIMIT_PER_15M = int(os.getenv("AUTH_CODE_RATE_LIMIT_PER_15M", "5"))
    VERIFY_RATE_LIMIT_PER_15M = int(os.getenv("VERIFY_RATE_LIMIT_PER_15M", "10"))
    SESSION_TTL_DAYS = int(os.getenv("SESSION_TTL_DAYS", "30"))
    USE_SMS_STUB = os.getenv("USE_SMS_STUB", "1") == "1"
    DEBUG_RETURN_SMS_CODE = os.getenv("DEBUG_RETURN_SMS_CODE", "0") == "1"

    STORAGE_MODE = os.getenv("STORAGE_MODE", "local")  # local or s3
    S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "")
    S3_REGION = os.getenv("S3_REGION", "auto")
    S3_ENDPOINT_URL = os.getenv("S3_ENDPOINT_URL", "")
    S3_ACCESS_KEY_ID = os.getenv("S3_ACCESS_KEY_ID", "")
    S3_SECRET_ACCESS_KEY = os.getenv("S3_SECRET_ACCESS_KEY", "")
    S3_SIGNED_URL_TTL = int(os.getenv("S3_SIGNED_URL_TTL", "600"))

    SMS_PROVIDER = os.getenv("SMS_PROVIDER", "stub")  # stub or twilio_verify
    TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
    TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
    TWILIO_VERIFY_SERVICE_SID = os.getenv("TWILIO_VERIFY_SERVICE_SID", "")


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.String(36), primary_key=True, default=new_uuid)
    phone_e164 = db.Column(db.String(32), nullable=False, unique=True, index=True)
    nickname = db.Column(db.String(32), nullable=True, unique=True, index=True)
    avatar_attachment_id = db.Column(db.String(36), db.ForeignKey("attachments.id"), nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)

    def to_public_dict(self):
        return {
            "id": self.id,
            "nickname": self.nickname,
            "avatar_url": f"/api/attachments/{self.avatar_attachment_id}/download" if self.avatar_attachment_id else "",
        }

    def to_dict(self):
        return {
            **self.to_public_dict(),
            "phone_e164": self.phone_e164,
        }


class AuthCode(db.Model):
    __tablename__ = "auth_codes"

    id = db.Column(db.String(36), primary_key=True, default=new_uuid)
    phone_e164 = db.Column(db.String(32), nullable=False, index=True)
    code_hash = db.Column(db.String(64), nullable=True)
    provider = db.Column(db.String(32), nullable=False, default="stub")
    ip_address = db.Column(db.String(64), nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    consumed_at = db.Column(db.DateTime, nullable=True)


class UserSession(db.Model):
    __tablename__ = "sessions"

    id = db.Column(db.String(36), primary_key=True, default=new_uuid)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    session_token_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    csrf_token = db.Column(db.String(64), nullable=False)
    ip_address = db.Column(db.String(64), nullable=False)
    user_agent = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_seen_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True)


class Chat(db.Model):
    __tablename__ = "chats"

    id = db.Column(db.String(36), primary_key=True, default=new_uuid)
    title = db.Column(db.String(120), nullable=True)
    is_group = db.Column(db.Boolean, nullable=False, default=False)
    created_by_user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class ChatMember(db.Model):
    __tablename__ = "chat_members"

    id = db.Column(db.String(36), primary_key=True, default=new_uuid)
    chat_id = db.Column(db.String(36), db.ForeignKey("chats.id"), nullable=False, index=True)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    joined_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    pinned = db.Column(db.Boolean, nullable=False, default=False)
    hidden = db.Column(db.Boolean, nullable=False, default=False)
    last_read_at = db.Column(db.DateTime, nullable=True)

    __table_args__ = (
        db.UniqueConstraint("chat_id", "user_id", name="uq_chat_member"),
    )


class Message(db.Model):
    __tablename__ = "messages"

    id = db.Column(db.String(36), primary_key=True, default=new_uuid)
    chat_id = db.Column(db.String(36), db.ForeignKey("chats.id"), nullable=False, index=True)
    sender_user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    text = db.Column(db.Text, nullable=True)
    message_type = db.Column(db.String(32), nullable=False, default="text")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    edited_at = db.Column(db.DateTime, nullable=True)


class Attachment(db.Model):
    __tablename__ = "attachments"

    id = db.Column(db.String(36), primary_key=True, default=new_uuid)
    owner_user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    message_id = db.Column(db.String(36), db.ForeignKey("messages.id"), nullable=True, index=True)
    purpose = db.Column(db.String(32), nullable=False, default="message")
    storage_key = db.Column(db.String(255), nullable=False, unique=True)
    original_name = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(255), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    kind = db.Column(db.String(32), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class UserSetting(db.Model):
    __tablename__ = "user_settings"

    id = db.Column(db.String(36), primary_key=True, default=new_uuid)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, unique=True)
    theme = db.Column(db.String(16), nullable=False, default="dark")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)


def s3_client():
    if app.config["STORAGE_MODE"] != "s3":
        return None
    return boto3_client(
        "s3",
        region_name=app.config["S3_REGION"],
        endpoint_url=app.config["S3_ENDPOINT_URL"] or None,
        aws_access_key_id=app.config["S3_ACCESS_KEY_ID"],
        aws_secret_access_key=app.config["S3_SECRET_ACCESS_KEY"],
        config=BotoConfig(signature_version="s3v4"),
    )


def verify_csrf() -> bool:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return True
    cookie_value = request.cookies.get("csrf_token", "")
    header_value = request.headers.get("X-CSRF-Token", "")
    return bool(cookie_value and header_value and hmac.compare_digest(cookie_value, header_value))


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not g.current_user:
            return json_error("Требуется авторизация.", 401)
        if request.method not in {"GET", "HEAD", "OPTIONS"} and not verify_csrf():
            return json_error("CSRF-проверка не пройдена.", 403)
        return view(*args, **kwargs)
    return wrapper


def create_session_response(user: User):
    raw_session_token = secrets.token_urlsafe(48)
    csrf_token = secrets.token_urlsafe(32)
    session_row = UserSession(
        user_id=user.id,
        session_token_hash=hash_secret(raw_session_token),
        csrf_token=csrf_token,
        ip_address=client_ip(),
        user_agent=(request.headers.get("User-Agent", "")[:255]),
        expires_at=utcnow() + timedelta(days=app.config["SESSION_TTL_DAYS"]),
    )
    db.session.add(session_row)
    user.last_login_at = utcnow()
    if not UserSetting.query.filter_by(user_id=user.id).first():
        db.session.add(UserSetting(user_id=user.id, theme="dark"))
    db.session.commit()

    response = jsonify({
        "ok": True,
        "user": serialize_me(user),
        "needs_profile": not bool(user.nickname),
        "csrf_token": csrf_token,
        "sms_stub": app.config["USE_SMS_STUB"],
    })
    response.set_cookie(
        app.config["SESSION_COOKIE_NAME"],
        raw_session_token,
        max_age=app.config["SESSION_TTL_DAYS"] * 24 * 3600,
        httponly=True,
        secure=app.config["SESSION_COOKIE_SECURE"],
        samesite=app.config["SESSION_COOKIE_SAMESITE"],
    )
    response.set_cookie(
        "csrf_token",
        csrf_token,
        max_age=app.config["SESSION_TTL_DAYS"] * 24 * 3600,
        httponly=False,
        secure=app.config["SESSION_COOKIE_SECURE"],
        samesite=app.config["SESSION_COOKIE_SAMESITE"],
    )
    return response


def revoke_current_session(response):
    if g.current_session:
        g.current_session.revoked_at = utcnow()
        db.session.commit()
    response.set_cookie(app.config["SESSION_COOKIE_NAME"], "", expires=0)
    response.set_cookie("csrf_token", "", expires=0)
    return response


def serialize_attachment(attachment: Attachment):
    return {
        "id": attachment.id,
        "original_name": attachment.original_name,
        "mime_type": attachment.mime_type,
        "size_bytes": attachment.size_bytes,
        "kind": attachment.kind,
        "url": f"/api/attachments/{attachment.id}/download",
    }


def message_status_for_user(message: Message, current_user_id: str) -> str:
    if message.sender_user_id != current_user_id:
        return "received"
    other_members = ChatMember.query.filter(
        ChatMember.chat_id == message.chat_id,
        ChatMember.user_id != current_user_id,
    ).all()
    if not other_members:
        return "sent"
    if all(member.last_read_at and member.last_read_at >= message.created_at for member in other_members):
        return "read"
    return "delivered"


def serialize_message(message: Message, current_user_id: str):
    attachments = Attachment.query.filter_by(message_id=message.id).order_by(Attachment.created_at.asc()).all()
    sender = db.session.get(User, message.sender_user_id)
    return {
        "id": message.id,
        "chat_id": message.chat_id,
        "sender_user_id": message.sender_user_id,
        "sender_nickname": sender.nickname if sender else "Unknown",
        "text": message.text or "",
        "message_type": message.message_type,
        "created_at": message.created_at.isoformat() + "Z",
        "attachments": [serialize_attachment(item) for item in attachments],
        "status": message_status_for_user(message, current_user_id),
        "is_mine": message.sender_user_id == current_user_id,
    }


def chat_members(chat_id: str):
    return ChatMember.query.filter_by(chat_id=chat_id).all()


def serialize_chat(chat: Chat, current_user_id: str):
    members = chat_members(chat.id)
    member_map = {m.user_id: m for m in members}
    current_member = member_map.get(current_user_id)
    other_user_ids = [m.user_id for m in members if m.user_id != current_user_id]
    other_users = [db.session.get(User, user_id) for user_id in other_user_ids]

    last_message = Message.query.filter_by(chat_id=chat.id).order_by(Message.created_at.desc()).first()
    unread_q = Message.query.filter(
        Message.chat_id == chat.id,
        Message.sender_user_id != current_user_id,
    )
    if current_member and current_member.last_read_at:
        unread_q = unread_q.filter(Message.created_at > current_member.last_read_at)
    unread_count = unread_q.count()

    if chat.is_group:
        title = chat.title or "Новая группа"
        avatar_url = ""
    else:
        peer = next((user for user in other_users if user), None)
        title = peer.nickname if peer and peer.nickname else "Диалог"
        avatar_url = f"/api/attachments/{peer.avatar_attachment_id}/download" if peer and peer.avatar_attachment_id else ""

    return {
        "id": chat.id,
        "title": title,
        "is_group": chat.is_group,
        "updated_at": chat.updated_at.isoformat() + "Z",
        "pinned": bool(current_member and current_member.pinned),
        "hidden": bool(current_member and current_member.hidden),
        "unread_count": unread_count,
        "last_message_preview": (last_message.text[:100] if last_message and last_message.text else ("🎙 Голосовое" if last_message and last_message.message_type == "voice" else ("📎 Вложение" if last_message else ""))),
        "last_message_at": last_message.created_at.isoformat() + "Z" if last_message else None,
        "avatar_url": avatar_url,
    }


def serialize_me(user: User):
    settings = UserSetting.query.filter_by(user_id=user.id).first()
    return {
        **user.to_dict(),
        "settings": {
            "theme": settings.theme if settings else "dark",
        },
    }


def ensure_chat_access(chat_id: str, user_id: str) -> Optional[ChatMember]:
    return ChatMember.query.filter_by(chat_id=chat_id, user_id=user_id).first()


def upload_bytes_to_storage(data: bytes, storage_key: str, mime_type: str):
    if app.config["STORAGE_MODE"] == "s3":
        client = s3_client()
        client.put_object(
            Bucket=app.config["S3_BUCKET_NAME"],
            Key=storage_key,
            Body=data,
            ContentType=mime_type,
        )
        return
    local_path = UPLOAD_DIR / storage_key
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(data)


def generate_download_url(storage_key: str) -> Optional[str]:
    if app.config["STORAGE_MODE"] != "s3":
        return None
    client = s3_client()
    return client.generate_presigned_url(
        "get_object",
        Params={"Bucket": app.config["S3_BUCKET_NAME"], "Key": storage_key},
        ExpiresIn=app.config["S3_SIGNED_URL_TTL"],
    )


def send_verification_code(phone_e164: str, code: str):
    if app.config["SMS_PROVIDER"] == "twilio_verify" and TwilioClient and app.config["TWILIO_VERIFY_SERVICE_SID"]:
        twilio_client = TwilioClient(app.config["TWILIO_ACCOUNT_SID"], app.config["TWILIO_AUTH_TOKEN"])
        twilio_client.verify.v2.services(app.config["TWILIO_VERIFY_SERVICE_SID"]).verifications.create(
            to=phone_e164,
            channel="sms",
        )
        return
    print(f"[SMS-STUB] send code {code} to {phone_e164}")


def check_twilio_verification(phone_e164: str, code: str) -> bool:
    if not (TwilioClient and app.config["TWILIO_VERIFY_SERVICE_SID"]):
        return False
    twilio_client = TwilioClient(app.config["TWILIO_ACCOUNT_SID"], app.config["TWILIO_AUTH_TOKEN"])
    result = twilio_client.verify.v2.services(app.config["TWILIO_VERIFY_SERVICE_SID"]).verification_checks.create(
        to=phone_e164,
        code=code,
    )
    return getattr(result, "status", "") == "approved"


def create_or_get_user_by_phone(phone_e164: str) -> User:
    user = User.query.filter_by(phone_e164=phone_e164).first()
    if user:
        return user
    user = User(phone_e164=phone_e164)
    db.session.add(user)
    db.session.commit()
    return user


def auth_rate_limited(phone_e164: str) -> bool:
    cutoff = utcnow() - timedelta(minutes=15)
    phone_count = AuthCode.query.filter(
        AuthCode.phone_e164 == phone_e164,
        AuthCode.created_at >= cutoff,
    ).count()
    ip_count = AuthCode.query.filter(
        AuthCode.ip_address == client_ip(),
        AuthCode.created_at >= cutoff,
    ).count()
    return phone_count >= app.config["AUTH_CODE_RATE_LIMIT_PER_15M"] or ip_count >= 20


def verify_rate_limited(phone_e164: str) -> bool:
    cutoff = utcnow() - timedelta(minutes=15)
    attempts_sum = db.session.query(func.coalesce(func.sum(AuthCode.attempts), 0)).filter(
        AuthCode.phone_e164 == phone_e164,
        AuthCode.created_at >= cutoff,
    ).scalar()
    return attempts_sum >= app.config["VERIFY_RATE_LIMIT_PER_15M"]


def latest_active_code(phone_e164: str) -> Optional[AuthCode]:
    return AuthCode.query.filter(
        AuthCode.phone_e164 == phone_e164,
        AuthCode.consumed_at.is_(None),
        AuthCode.expires_at > utcnow(),
    ).order_by(AuthCode.created_at.desc()).first()


def get_or_create_direct_chat(current_user: User, other_user: User) -> Chat:
    my_memberships = ChatMember.query.filter_by(user_id=current_user.id).all()
    my_chat_ids = [item.chat_id for item in my_memberships]
    if my_chat_ids:
        direct_chats = Chat.query.filter(Chat.id.in_(my_chat_ids), Chat.is_group.is_(False)).all()
        for chat in direct_chats:
            members = ChatMember.query.filter_by(chat_id=chat.id).all()
            member_ids = {item.user_id for item in members}
            if member_ids == {current_user.id, other_user.id}:
                return chat

    chat = Chat(
        title=None,
        is_group=False,
        created_by_user_id=current_user.id,
    )
    db.session.add(chat)
    db.session.flush()
    db.session.add(ChatMember(chat_id=chat.id, user_id=current_user.id))
    db.session.add(ChatMember(chat_id=chat.id, user_id=other_user.id))
    db.session.commit()
    return chat


def register_routes(flask_app: Flask):
    @flask_app.before_request
    def load_current_session():
        g.current_user = None
        g.current_session = None

        if request.path.startswith("/static/"):
            return

        raw_token = request.cookies.get(flask_app.config["SESSION_COOKIE_NAME"], "")
        if not raw_token:
            return

        token_hash = hash_secret(raw_token)
        session_row = UserSession.query.filter_by(session_token_hash=token_hash, revoked_at=None).first()
        if not session_row:
            return
        if session_row.expires_at <= utcnow():
            return
        user = db.session.get(User, session_row.user_id)
        if not user or not user.is_active:
            return
        session_row.last_seen_at = utcnow()
        db.session.commit()
        g.current_user = user
        g.current_session = session_row

    @flask_app.get("/")
    def index():
        return render_template("index.html", app_name=flask_app.config["APP_NAME"])

    @flask_app.get("/health")
    def health():
        return jsonify({"ok": True, "time": utcnow().isoformat() + "Z"})

    @flask_app.get("/api/me")
    def api_me():
        if not g.current_user:
            return json_error("Не авторизован.", 401)
        return jsonify({"ok": True, "user": serialize_me(g.current_user)})

    @flask_app.get("/api/users/search")
    @login_required
    def api_users_search():
        query = (request.args.get("q", "") or "").strip().lower()
        if len(query) < 2:
            return jsonify({"ok": True, "users": []})
        users = User.query.filter(
            User.id != g.current_user.id,
            User.nickname.isnot(None),
            func.lower(User.nickname).like(f"%{query}%"),
        ).order_by(User.nickname.asc()).limit(12).all()
        return jsonify({"ok": True, "users": [user.to_public_dict() for user in users]})

    @flask_app.post("/api/auth/send-code")
    def api_auth_send_code():
        payload = request.get_json(silent=True) or {}
        try:
            phone_e164 = parse_phone(payload.get("phone", ""))
        except ValueError as exc:
            return json_error(str(exc), 400)

        if auth_rate_limited(phone_e164):
            return json_error("Слишком много запросов. Попробуйте позже.", 429)

        current_code = latest_active_code(phone_e164)
        if current_code and (utcnow() - current_code.created_at).total_seconds() < flask_app.config["AUTH_CODE_RESEND_WINDOW_SECONDS"]:
            return json_error("Повторная отправка пока недоступна. Подождите немного.", 429)

        code = "".join(secrets.choice("0123456789") for _ in range(6))
        provider = "stub" if flask_app.config["USE_SMS_STUB"] else flask_app.config["SMS_PROVIDER"]
        auth_code = AuthCode(
            phone_e164=phone_e164,
            code_hash=(hash_secret(f"{phone_e164}:{code}") if provider == "stub" else None),
            provider=provider,
            ip_address=client_ip(),
            expires_at=utcnow() + timedelta(seconds=flask_app.config["AUTH_CODE_TTL_SECONDS"]),
        )
        db.session.add(auth_code)
        db.session.commit()

        send_verification_code(phone_e164, code)
        response = {
            "ok": True,
            "ttl_seconds": flask_app.config["AUTH_CODE_TTL_SECONDS"],
            "sms_stub": flask_app.config["USE_SMS_STUB"],
        }
        if flask_app.config["USE_SMS_STUB"] and flask_app.config["DEBUG_RETURN_SMS_CODE"]:
            response["debug_code"] = code
        return jsonify(response)

    @flask_app.post("/api/auth/verify-code")
    def api_auth_verify_code():
        payload = request.get_json(silent=True) or {}
        try:
            phone_e164 = parse_phone(payload.get("phone", ""))
        except ValueError as exc:
            return json_error(str(exc), 400)

        code = str(payload.get("code", "")).strip()
        if len(code) != 6 or not code.isdigit():
            return json_error("Введите 6-значный код.", 400)

        if verify_rate_limited(phone_e164):
            return json_error("Слишком много попыток. Попробуйте позже.", 429)

        auth_code = latest_active_code(phone_e164)
        if not auth_code:
            return json_error("Код не найден или истёк.", 400)
        if auth_code.attempts >= flask_app.config["AUTH_CODE_MAX_ATTEMPTS"]:
            return json_error("Лимит попыток исчерпан. Запросите новый код.", 429)

        is_valid = False
        if auth_code.provider == "twilio_verify":
            is_valid = check_twilio_verification(phone_e164, code)
        else:
            expected = hash_secret(f"{phone_e164}:{code}")
            is_valid = bool(auth_code.code_hash and hmac.compare_digest(auth_code.code_hash, expected))

        if not is_valid:
            auth_code.attempts += 1
            db.session.commit()
            return json_error("Неверный код.", 400)

        auth_code.consumed_at = utcnow()
        user = create_or_get_user_by_phone(phone_e164)
        db.session.commit()
        return create_session_response(user)

    @flask_app.post("/api/auth/logout")
    @login_required
    def api_auth_logout():
        response = jsonify({"ok": True})
        return revoke_current_session(response)

    @flask_app.post("/api/profile/update")
    @login_required
    def api_profile_update():
        payload = request.get_json(silent=True) or {}
        nickname = (payload.get("nickname", "") or "").strip()
        if not nickname or len(nickname) < 3 or len(nickname) > 32:
            return json_error("Никнейм должен быть длиной от 3 до 32 символов.", 400)

        if not all(ch.isalnum() or ch in "._-" for ch in nickname):
            return json_error("Никнейм может содержать буквы, цифры, точку, дефис и подчёркивание.", 400)

        existing = User.query.filter(User.nickname == nickname, User.id != g.current_user.id).first()
        if existing:
            return json_error("Такой никнейм уже занят.", 409)

        avatar_attachment_id = payload.get("avatar_attachment_id")
        if avatar_attachment_id:
            attachment = db.session.get(Attachment, avatar_attachment_id)
            if not attachment or attachment.owner_user_id != g.current_user.id or attachment.purpose != "avatar":
                return json_error("Некорректный аватар.", 400)
            g.current_user.avatar_attachment_id = attachment.id

        g.current_user.nickname = nickname
        db.session.commit()
        return jsonify({"ok": True, "user": serialize_me(g.current_user)})

    @flask_app.post("/api/settings/theme")
    @login_required
    def api_settings_theme():
        payload = request.get_json(silent=True) or {}
        theme = (payload.get("theme", "") or "").strip().lower()
        if theme not in {"light", "dark", "system"}:
            return json_error("Неизвестная тема.", 400)
        settings = UserSetting.query.filter_by(user_id=g.current_user.id).first()
        if not settings:
            settings = UserSetting(user_id=g.current_user.id, theme=theme)
            db.session.add(settings)
        else:
            settings.theme = theme
        db.session.commit()
        return jsonify({"ok": True, "settings": {"theme": theme}})

    @flask_app.get("/api/chats")
    @login_required
    def api_chats_list():
        memberships = ChatMember.query.filter_by(user_id=g.current_user.id, hidden=False).all()
        chats = [db.session.get(Chat, membership.chat_id) for membership in memberships]
        chats = [chat for chat in chats if chat]
        chats.sort(
            key=lambda chat: (
                0 if ChatMember.query.filter_by(chat_id=chat.id, user_id=g.current_user.id).first().pinned else 1,
                -(chat.updated_at.timestamp() if chat.updated_at else 0),
            )
        )
        return jsonify({"ok": True, "chats": [serialize_chat(chat, g.current_user.id) for chat in chats]})

    @flask_app.post("/api/chats/direct")
    @login_required
    def api_chats_direct():
        payload = request.get_json(silent=True) or {}
        nickname = (payload.get("nickname", "") or "").strip()
        if len(nickname) < 2:
            return json_error("Укажи никнейм собеседника.", 400)
        other_user = User.query.filter(func.lower(User.nickname) == nickname.lower(), User.id != g.current_user.id).first()
        if not other_user:
            return json_error("Пользователь с таким никнеймом не найден.", 404)

        chat = get_or_create_direct_chat(g.current_user, other_user)
        socketio.emit("chat:new", {"chat": serialize_chat(chat, other_user.id)}, room=f"user:{other_user.id}")
        return jsonify({"ok": True, "chat": serialize_chat(chat, g.current_user.id)})

    @flask_app.post("/api/chats")
    @login_required
    def api_chats_create():
        payload = request.get_json(silent=True) or {}
        participant_nickname = (payload.get("participant_nickname", "") or "").strip()
        participant_phone = (payload.get("participant_phone", "") or "").strip()
        title = (payload.get("title", "") or "").strip()

        if participant_nickname and not title:
            other_user = User.query.filter(func.lower(User.nickname) == participant_nickname.lower(), User.id != g.current_user.id).first()
            if not other_user:
                return json_error("Пользователь с таким никнеймом не найден.", 404)
            chat = get_or_create_direct_chat(g.current_user, other_user)
            return jsonify({"ok": True, "chat": serialize_chat(chat, g.current_user.id)})

        other_user = None
        if participant_phone:
            try:
                phone_e164 = parse_phone(participant_phone)
            except ValueError as exc:
                return json_error(str(exc), 400)
            other_user = User.query.filter_by(phone_e164=phone_e164).first()
            if not other_user:
                return json_error("Пользователь с таким номером ещё не зарегистрирован.", 404)

        chat = Chat(
            title=title or None,
            is_group=bool(title),
            created_by_user_id=g.current_user.id,
        )
        db.session.add(chat)
        db.session.flush()
        db.session.add(ChatMember(chat_id=chat.id, user_id=g.current_user.id))
        if other_user:
            db.session.add(ChatMember(chat_id=chat.id, user_id=other_user.id))
        db.session.commit()

        if other_user:
            socketio.emit("chat:new", {"chat": serialize_chat(chat, other_user.id)}, room=f"user:{other_user.id}")
        return jsonify({"ok": True, "chat": serialize_chat(chat, g.current_user.id)})

    @flask_app.post("/api/chats/<chat_id>/pin")
    @login_required
    def api_chats_pin(chat_id: str):
        payload = request.get_json(silent=True) or {}
        member = ensure_chat_access(chat_id, g.current_user.id)
        if not member:
            return json_error("Чат не найден.", 404)
        member.pinned = bool(payload.get("pinned", True))
        db.session.commit()
        return jsonify({"ok": True})

    @flask_app.post("/api/chats/<chat_id>/hide")
    @login_required
    def api_chats_hide(chat_id: str):
        payload = request.get_json(silent=True) or {}
        member = ensure_chat_access(chat_id, g.current_user.id)
        if not member:
            return json_error("Чат не найден.", 404)
        member.hidden = bool(payload.get("hidden", True))
        db.session.commit()
        return jsonify({"ok": True})

    @flask_app.get("/api/chats/<chat_id>/messages")
    @login_required
    def api_messages_list(chat_id: str):
        member = ensure_chat_access(chat_id, g.current_user.id)
        if not member:
            return json_error("Доступ запрещён.", 403)

        limit = min(int(request.args.get("limit", 50)), 200)
        messages = Message.query.filter_by(chat_id=chat_id).order_by(Message.created_at.asc()).limit(limit).all()
        return jsonify({"ok": True, "messages": [serialize_message(msg, g.current_user.id) for msg in messages]})

    @flask_app.post("/api/chats/<chat_id>/messages")
    @login_required
    def api_messages_send(chat_id: str):
        member = ensure_chat_access(chat_id, g.current_user.id)
        if not member:
            return json_error("Доступ запрещён.", 403)

        payload = request.get_json(silent=True) or {}
        text = (payload.get("text", "") or "").strip()
        attachment_ids = payload.get("attachment_ids", []) or []
        if not isinstance(attachment_ids, list):
            return json_error("attachment_ids должен быть массивом.", 400)
        if not text and not attachment_ids:
            return json_error("Нельзя отправить пустое сообщение.", 400)
        if len(text) > 4000:
            return json_error("Сообщение слишком длинное.", 400)

        attachments = []
        for attachment_id in attachment_ids:
            attachment = db.session.get(Attachment, attachment_id)
            if not attachment or attachment.owner_user_id != g.current_user.id or attachment.message_id is not None:
                return json_error("Некорректное вложение.", 400)
            attachments.append(attachment)

        message_type = "text"
        if attachments and not text:
            kinds = {item.kind for item in attachments}
            if len(kinds) == 1:
                kind = next(iter(kinds))
                if kind == "audio" and any(item.original_name.startswith("voice-") for item in attachments):
                    message_type = "voice"
                else:
                    message_type = kind
            else:
                message_type = "file"

        message = Message(
            chat_id=chat_id,
            sender_user_id=g.current_user.id,
            text=text,
            message_type=message_type,
        )
        db.session.add(message)
        db.session.flush()

        for attachment in attachments:
            attachment.message_id = message.id

        chat = db.session.get(Chat, chat_id)
        chat.updated_at = utcnow()
        db.session.commit()

        payload_out = {"message": serialize_message(message, g.current_user.id), "chat": serialize_chat(chat, g.current_user.id)}
        socketio.emit("message:new", payload_out, room=f"chat:{chat_id}")
        return jsonify({"ok": True, **payload_out})

    @flask_app.post("/api/chats/<chat_id>/read")
    @login_required
    def api_chats_read(chat_id: str):
        member = ensure_chat_access(chat_id, g.current_user.id)
        if not member:
            return json_error("Доступ запрещён.", 403)
        latest_msg = Message.query.filter(
            Message.chat_id == chat_id,
            Message.sender_user_id != g.current_user.id,
        ).order_by(Message.created_at.desc()).first()
        member.last_read_at = latest_msg.created_at if latest_msg else utcnow()
        db.session.commit()
        socketio.emit(
            "chat:read",
            {"chat_id": chat_id, "user_id": g.current_user.id, "read_at": member.last_read_at.isoformat() + "Z"},
            room=f"chat:{chat_id}",
        )
        return jsonify({"ok": True})

    @flask_app.post("/api/attachments/upload")
    @login_required
    def api_attachments_upload():
        upload = request.files.get("file")
        purpose = (request.form.get("purpose", "message") or "message").strip().lower()
        if purpose not in {"message", "avatar"}:
            return json_error("Некорректное назначение файла.", 400)
        if not upload:
            return json_error("Файл не найден.", 400)
        if not upload.filename:
            return json_error("Имя файла отсутствует.", 400)

        safe_name = secure_filename(upload.filename)
        if not safe_name or not allowed_file(safe_name):
            return json_error("Формат файла не разрешён.", 400)

        raw_bytes = upload.read()
        if not raw_bytes:
            return json_error("Файл пустой.", 400)
        if len(raw_bytes) > flask_app.config["MAX_CONTENT_LENGTH"]:
            return json_error("Файл слишком большой.", 413)

        mime_type = upload.mimetype or mimetypes.guess_type(safe_name)[0] or "application/octet-stream"
        kind = "avatar" if purpose == "avatar" else attachment_kind_from_mime(mime_type, safe_name)
        ext = Path(safe_name).suffix.lower()
        storage_key = f"{purpose}/{g.current_user.id}/{utcnow().strftime('%Y/%m/%d')}/{new_uuid()}{ext}"

        upload_bytes_to_storage(raw_bytes, storage_key, mime_type)

        attachment = Attachment(
            owner_user_id=g.current_user.id,
            purpose=purpose,
            storage_key=storage_key,
            original_name=safe_name,
            mime_type=mime_type,
            size_bytes=len(raw_bytes),
            kind=kind,
        )
        db.session.add(attachment)
        db.session.commit()

        return jsonify({"ok": True, "attachment": serialize_attachment(attachment)})

    @flask_app.get("/api/attachments/<attachment_id>/download")
    @login_required
    def api_attachments_download(attachment_id: str):
        attachment = db.session.get(Attachment, attachment_id)
        if not attachment:
            return json_error("Файл не найден.", 404)

        if attachment.message_id:
            message = db.session.get(Message, attachment.message_id)
            if not message or not ensure_chat_access(message.chat_id, g.current_user.id):
                return json_error("Доступ запрещён.", 403)
        elif attachment.purpose == "avatar":
            pass
        elif attachment.owner_user_id != g.current_user.id:
            return json_error("Доступ запрещён.", 403)

        if flask_app.config["STORAGE_MODE"] == "s3":
            url = generate_download_url(attachment.storage_key)
            return redirect(url, code=302)

        local_path = UPLOAD_DIR / attachment.storage_key
        if not local_path.exists():
            return json_error("Файл не найден в хранилище.", 404)

        download = request.args.get("download", "0") == "1"
        return send_file(
            local_path,
            mimetype=attachment.mime_type,
            as_attachment=download,
            download_name=attachment.original_name,
            conditional=True,
            etag=True,
            max_age=3600,
        )


def create_app():
    flask_app = Flask(__name__, static_folder="static", template_folder="templates")
    flask_app.config.from_object(Config)
    db.init_app(flask_app)
    socketio.init_app(flask_app)
    register_routes(flask_app)

    with flask_app.app_context():
        db.create_all()

    return flask_app


app = create_app()


def get_user_from_session_cookie():
    raw_token = request.cookies.get(app.config["SESSION_COOKIE_NAME"], "")
    if not raw_token:
        return None
    token_hash = hash_secret(raw_token)
    session_row = UserSession.query.filter_by(session_token_hash=token_hash, revoked_at=None).first()
    if not session_row or session_row.expires_at <= utcnow():
        return None
    return db.session.get(User, session_row.user_id)


@socketio.on("connect")
def socket_connect():
    user = get_user_from_session_cookie()
    if not user:
        return False
    join_room(f"user:{user.id}")
    memberships = ChatMember.query.filter_by(user_id=user.id).all()
    for membership in memberships:
        join_room(f"chat:{membership.chat_id}")


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=os.getenv("APP_ENV", "development") == "development")
