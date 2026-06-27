import os
import uuid
import json
import hashlib
import secrets
import mimetypes
import asyncio
import urllib.request
import urllib.error
from urllib.parse import quote
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Set

import asyncpg
from argon2 import PasswordHasher
from dotenv import load_dotenv
from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    Request,
    WebSocket,
    WebSocketDisconnect,
    UploadFile,
    File,
    Form,
    Response,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from jose import jwt, JWTError
from pydantic import BaseModel, Field

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-change-me")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "43200"))

ONESIGNAL_APP_ID = os.getenv("ONESIGNAL_APP_ID")
ONESIGNAL_REST_API_KEY = os.getenv("ONESIGNAL_REST_API_KEY")
ONESIGNAL_API_URL = "https://api.onesignal.com/notifications"

DEVELOPER_USER_ID = os.getenv("DEVELOPER_USER_ID")
DEVELOPER_USERNAME = os.getenv("DEVELOPER_USERNAME")


if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required in .env")

app = FastAPI(title="UMe Messenger API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")

security = HTTPBearer()
password_hasher = PasswordHasher()
db_pool: Optional[asyncpg.Pool] = None


class ConnectionManager:
    def __init__(self):
        self.connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, user_id: str, websocket: WebSocket):
        await websocket.accept()
        self.connections.setdefault(user_id, set()).add(websocket)

    def is_online(self, user_id: str) -> bool:
        return bool(self.connections.get(user_id))

    def disconnect(self, user_id: str, websocket: WebSocket):
        if user_id in self.connections:
            self.connections[user_id].discard(websocket)

            if not self.connections[user_id]:
                del self.connections[user_id]

    async def send_to_user(self, user_id: str, payload: dict):
        sockets = list(self.connections.get(user_id, []))

        for socket in sockets:
            try:
                await socket.send_text(json.dumps(payload))
            except Exception:
                self.disconnect(user_id, socket)

    async def broadcast_to_chat(
        self,
        chat_id: str,
        payload: dict,
        exclude_user_id: Optional[str] = None,
    ):
        async with db_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT user_id
                FROM public.chat_members
                WHERE chat_id = $1
                  AND hidden = false
                  AND left_at IS NULL
                """,
                chat_id,
            )

        for row in rows:
            target_user_id = row["user_id"]

            if exclude_user_id and target_user_id == exclude_user_id:
                continue

            await self.send_to_user(target_user_id, payload)


manager = ConnectionManager()


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=6, max_length=128)
    nickname: str = Field(min_length=2, max_length=64)


class LoginIn(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=6, max_length=128)


class ProfileIn(BaseModel):
    nickname: Optional[str] = Field(default=None, min_length=2, max_length=64)
    display_name: Optional[str] = Field(default=None, min_length=2, max_length=64)


class ThemeIn(BaseModel):
    theme: str


class ChatAppearanceIn(BaseModel):
    accent_color: Optional[str] = None
    chat_wallpaper: Optional[str] = None
    bubble_style: Optional[str] = None


class DirectChatCreateIn(BaseModel):
    user_id: str


class SupportDeveloperChatIn(BaseModel):
    message: Optional[str] = Field(default=None, max_length=5000)


class GroupChatCreateIn(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    member_user_ids: list[str] = Field(default_factory=list)


class GroupMembersAddIn(BaseModel):
    user_ids: list[str] = Field(default_factory=list)


class ChatTitleUpdateIn(BaseModel):
    title: str = Field(min_length=1, max_length=120)


class ChatRequestCreateIn(BaseModel):
    receiver_user_id: str


class MessageCreateIn(BaseModel):
    text: Optional[str] = Field(default=None, max_length=5000)
    attachment_id: Optional[str] = None
    reply_to_message_id: Optional[str] = None


class MessageEditIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)


class MessageIdsIn(BaseModel):
    message_ids: list[str] = Field(default_factory=list)


class ForwardMessageIn(BaseModel):
    target_chat_id: str


class PinnedMessageIn(BaseModel):
    message_id: Optional[str] = None


class ReactionIn(BaseModel):
    reaction_type: str = Field(pattern="^(emoji|image)$")
    emoji: Optional[str] = Field(default=None, max_length=32)
    attachment_id: Optional[str] = None

class PushTokenIn(BaseModel):
    token: str = Field(min_length=10, max_length=4096)
    platform: str = Field(default="android", max_length=32)


class PushTokenDeleteIn(BaseModel):
    token: str = Field(min_length=10, max_length=4096)



def now() -> datetime:
    return datetime.utcnow()


def make_id() -> str:
    return str(uuid.uuid4())


def normalize_username(username: str) -> str:
    return username.strip().lower()


def clean_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None

    value = value.strip()
    return value if value else None


def user_display_name(row) -> str:
    return row["display_name"] or row["nickname"] or row["username"]


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False

    try:
        return password_hasher.verify(password_hash, password)
    except Exception as e:
        print("PASSWORD VERIFY ERROR:", repr(e), flush=True)
        return False


def create_access_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "iat": int(now().timestamp()),
        "exp": int((now() + timedelta(minutes=JWT_EXPIRE_MINUTES)).timestamp()),
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")

        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")

        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def detect_attachment_kind(mime_type: str) -> str:
    if mime_type.startswith("image/"):
        return "image"

    if mime_type.startswith("video/"):
        return "video"

    if mime_type.startswith("audio/"):
        return "audio"

    if mime_type in ["application/pdf", "text/plain"]:
        return "document"

    return "other"


def attachment_url(storage_key: str) -> str:
    return f"/attachments/file/{quote(storage_key, safe='/')}"


def safe_filename(original_name: str) -> str:
    return (
        original_name
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
    )


def resolve_mime_type(original_name: str, uploaded_mime_type: Optional[str]) -> str:
    guessed_mime_type = mimetypes.guess_type(original_name)[0]

    if not uploaded_mime_type or uploaded_mime_type == "application/octet-stream":
        return guessed_mime_type or "application/octet-stream"

    return uploaded_mime_type


def format_attachment(row) -> Optional[dict]:
    if not row["attachment_id"]:
        return None

    return {
        "id": row["attachment_id"],
        "url": attachment_url(row["attachment_storage_key"]),
        "storage_key": row["attachment_storage_key"],
        "original_name": row["attachment_original_name"],
        "mime_type": row["attachment_mime_type"],
        "size_bytes": row["attachment_size_bytes"],
        "kind": row["attachment_kind"],
    }


def format_reply_message(row, current_user_id: Optional[str] = None) -> Optional[dict]:
    data = dict(row)

    if not data.get("reply_message_id"):
        return None

    attachment = None

    if data.get("reply_attachment_id"):
        attachment = {
            "id": data.get("reply_attachment_id"),
            "url": attachment_url(data.get("reply_attachment_storage_key")),
            "storage_key": data.get("reply_attachment_storage_key"),
            "original_name": data.get("reply_attachment_original_name"),
            "mime_type": data.get("reply_attachment_mime_type"),
            "size_bytes": data.get("reply_attachment_size_bytes"),
            "kind": data.get("reply_attachment_kind"),
        }

    return {
        "id": data.get("reply_message_id"),
        "sender_user_id": data.get("reply_sender_user_id"),
        "sender_name": data.get("reply_display_name")
        or data.get("reply_nickname")
        or data.get("reply_username"),
        "text": data.get("reply_text"),
        "message_type": data.get("reply_message_type"),
        "attachment": attachment,
        "is_mine": data.get("reply_sender_user_id") == current_user_id,
    }


def format_reaction_attachment(row) -> Optional[dict]:
    if not row["reaction_attachment_id"]:
        return None

    return {
        "id": row["reaction_attachment_id"],
        "url": attachment_url(row["reaction_attachment_storage_key"]),
        "storage_key": row["reaction_attachment_storage_key"],
        "original_name": row["reaction_attachment_original_name"],
        "mime_type": row["reaction_attachment_mime_type"],
        "size_bytes": row["reaction_attachment_size_bytes"],
        "kind": row["reaction_attachment_kind"],
    }


def format_reaction(row, current_user_id: Optional[str] = None) -> dict:
    return {
        "id": row["reaction_id"],
        "message_id": row["reaction_message_id"],
        "user_id": row["reaction_user_id"],
        "user_name": row["reaction_user_display_name"]
        or row["reaction_user_nickname"]
        or row["reaction_user_username"],
        "reaction_type": row["reaction_type"],
        "emoji": row["reaction_emoji"],
        "attachment": format_reaction_attachment(row),
        "created_at": row["reaction_created_at"].isoformat()
        if row["reaction_created_at"]
        else None,
        "is_mine": row["reaction_user_id"] == current_user_id,
    }


async def fetch_reactions_for_messages(
    conn: asyncpg.Connection,
    message_ids: list[str],
    current_user_id: Optional[str] = None,
) -> dict:
    if not message_ids:
        return {}

    rows = await conn.fetch(
        """
        SELECT
            r.id AS reaction_id,
            r.message_id AS reaction_message_id,
            r.user_id AS reaction_user_id,
            r.reaction_type,
            r.emoji AS reaction_emoji,
            r.created_at AS reaction_created_at,

            u.username AS reaction_user_username,
            u.nickname AS reaction_user_nickname,
            u.display_name AS reaction_user_display_name,

            a.id AS reaction_attachment_id,
            a.storage_key AS reaction_attachment_storage_key,
            a.original_name AS reaction_attachment_original_name,
            a.mime_type AS reaction_attachment_mime_type,
            a.size_bytes AS reaction_attachment_size_bytes,
            a.kind AS reaction_attachment_kind
        FROM public.message_reactions r
        JOIN public.users u
          ON u.id = r.user_id
        LEFT JOIN public.attachments a
          ON a.id = r.attachment_id
        WHERE r.message_id = ANY($1::text[])
        ORDER BY r.created_at ASC
        """,
        message_ids,
    )

    reactions_by_message = {}

    for row in rows:
        message_id = row["reaction_message_id"]
        reactions_by_message.setdefault(message_id, []).append(
            format_reaction(row, current_user_id),
        )

    return reactions_by_message


def format_message_row(
    row,
    reactions_by_message: Optional[dict] = None,
    current_user_id: Optional[str] = None,
) -> dict:
    data = dict(row)
    message_id = data["id"]
    sender_user_id = data["sender_user_id"]
    forwarded_name = (
        data.get("forwarded_from_display_name")
        or data.get("forwarded_from_nickname")
        or data.get("forwarded_from_username")
    )

    return {
        "id": message_id,
        "chat_id": data["chat_id"],
        "sender_user_id": sender_user_id,
        "sender_username": data.get("username"),
        "sender_name": data.get("display_name") or data.get("nickname") or data.get("username"),
        "text": data.get("text"),
        "message_type": data.get("message_type"),
        "attachment": format_attachment(row),
        "reply_to_message_id": data.get("reply_to_message_id"),
        "reply_to_message": format_reply_message(row, current_user_id),
        "reactions": (reactions_by_message or {}).get(message_id, []),
        "created_at": data["created_at"].isoformat() if data.get("created_at") else None,
        "edited_at": data["edited_at"].isoformat() if data.get("edited_at") else None,
        "is_mine": sender_user_id == current_user_id,
        "delivery_status": data.get("delivery_status"),
        "forwarded_from_message_id": data.get("forwarded_from_message_id"),
        "forwarded_from_user_id": data.get("forwarded_from_user_id"),
        "forwarded_from_name": forwarded_name,
        "pinned": bool(data.get("pinned")),
    }


async def fetch_message_payloads(
    conn: asyncpg.Connection,
    message_ids: list[str],
    current_user_id: str,
) -> list[dict]:
    if not message_ids:
        return []

    rows = await conn.fetch(
        """
        SELECT
            m.id,
            m.chat_id,
            m.sender_user_id,
            m.text,
            m.message_type,
            m.created_at,
            m.edited_at,
            m.reply_to_message_id,
            m.forwarded_from_message_id,
            m.forwarded_from_user_id,

            u.username,
            u.nickname,
            u.display_name,

            fu.username AS forwarded_from_username,
            fu.nickname AS forwarded_from_nickname,
            fu.display_name AS forwarded_from_display_name,

            a.id AS attachment_id,
            a.storage_key AS attachment_storage_key,
            a.original_name AS attachment_original_name,
            a.mime_type AS attachment_mime_type,
            a.size_bytes AS attachment_size_bytes,
            a.kind AS attachment_kind,

            rm.id AS reply_message_id,
            rm.sender_user_id AS reply_sender_user_id,
            rm.text AS reply_text,
            rm.message_type AS reply_message_type,
            ru.username AS reply_username,
            ru.nickname AS reply_nickname,
            ru.display_name AS reply_display_name,
            ra.id AS reply_attachment_id,
            ra.storage_key AS reply_attachment_storage_key,
            ra.original_name AS reply_attachment_original_name,
            ra.mime_type AS reply_attachment_mime_type,
            ra.size_bytes AS reply_attachment_size_bytes,
            ra.kind AS reply_attachment_kind,

            (m.id = c.pinned_message_id) AS pinned,

            CASE
                WHEN m.sender_user_id = $2 AND EXISTS (
                    SELECT 1
                    FROM public.message_receipts mr
                    WHERE mr.message_id = m.id
                      AND mr.user_id <> $2
                      AND mr.read_at IS NOT NULL
                ) THEN 'read'
                WHEN m.sender_user_id = $2 AND EXISTS (
                    SELECT 1
                    FROM public.message_receipts mr
                    WHERE mr.message_id = m.id
                      AND mr.user_id <> $2
                      AND mr.delivered_at IS NOT NULL
                ) THEN 'delivered'
                WHEN m.sender_user_id = $2 THEN 'sent'
                ELSE NULL
            END AS delivery_status
        FROM public.messages m
        JOIN public.chats c
          ON c.id = m.chat_id
        JOIN public.users u
          ON u.id = m.sender_user_id
        LEFT JOIN public.users fu
          ON fu.id = m.forwarded_from_user_id
        LEFT JOIN public.attachments a
          ON a.message_id = m.id
        LEFT JOIN public.messages rm
          ON rm.id = m.reply_to_message_id
         AND rm.chat_id = m.chat_id
         AND rm.deleted_at IS NULL
        LEFT JOIN public.users ru
          ON ru.id = rm.sender_user_id
        LEFT JOIN public.attachments ra
          ON ra.message_id = rm.id
        WHERE m.id = ANY($1::text[])
          AND m.deleted_at IS NULL
        ORDER BY m.created_at ASC
        """,
        message_ids,
        current_user_id,
    )

    reactions_by_message = await fetch_reactions_for_messages(
        conn,
        [row["id"] for row in rows],
        current_user_id,
    )

    return [
        format_message_row(row, reactions_by_message, current_user_id)
        for row in rows
    ]


async def fetch_message_payload(
    conn: asyncpg.Connection,
    message_id: str,
    current_user_id: str,
) -> Optional[dict]:
    payloads = await fetch_message_payloads(conn, [message_id], current_user_id)
    return payloads[0] if payloads else None


async def broadcast_receipt_updates(rows, status: str):
    grouped: Dict[tuple[str, str], list[str]] = {}

    for row in rows:
        sender_user_id = row["sender_user_id"]
        chat_id = row["chat_id"]
        message_id = row["id"]

        grouped.setdefault((sender_user_id, chat_id), []).append(message_id)

    for (sender_user_id, chat_id), message_ids in grouped.items():
        await manager.send_to_user(
            sender_user_id,
            {
                "type": "message.receipts_updated",
                "chat_id": chat_id,
                "message_ids": message_ids,
                "status": status,
                "updated_at": now().isoformat(),
            },
        )


async def get_current_user_id(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    return decode_token(credentials.credentials)


async def assert_chat_member(
    conn: asyncpg.Connection,
    chat_id: str,
    user_id: str,
) -> None:
    exists = await conn.fetchval(
        """
        SELECT 1
        FROM public.chat_members
        WHERE chat_id = $1
          AND user_id = $2
          AND hidden = false
          AND left_at IS NULL
        """,
        chat_id,
        user_id,
    )

    if not exists:
        raise HTTPException(status_code=403, detail="Not a chat member")



async def ensure_chat_member(
    chat_id: str,
    user_id: str,
) -> None:
    async with db_pool.acquire() as conn:
        await assert_chat_member(conn, chat_id, user_id)


async def mark_user_seen(user_id: str) -> datetime:
    current_time = now()

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE public.users
            SET last_login_at = $2,
                updated_at = $2
            WHERE id = $1
            """,
            user_id,
            current_time,
        )

    return current_time


async def broadcast_user_presence(
    user_id: str,
    online: bool,
    last_seen_at: Optional[datetime] = None,
):
    if last_seen_at is None:
        last_seen_at = now()

    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT DISTINCT chat_id
            FROM public.chat_members
            WHERE user_id = $1
              AND hidden = false
              AND left_at IS NULL
            """,
            user_id,
        )

    payload_time = last_seen_at.isoformat() if last_seen_at else None

    for row in rows:
        await manager.broadcast_to_chat(
            row["chat_id"],
            {
                "type": "presence.updated",
                "chat_id": row["chat_id"],
                "user_id": user_id,
                "online": online,
                "last_seen_at": payload_time,
            },
            exclude_user_id=user_id,
        )


async def get_user_display_name_by_id(user_id: str) -> str:
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT username, nickname, display_name
            FROM public.users
            WHERE id = $1
            """,
            user_id,
        )

    if not row:
        return "Пользователь"

    return user_display_name(row)


@app.on_event("startup")
async def startup():
    global db_pool

    db_pool = await asyncpg.create_pool(
        DATABASE_URL,
        min_size=0,
        max_size=1,
        command_timeout=60,
        max_inactive_connection_lifetime=10,
    )

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            ALTER TABLE public.attachments
            ADD COLUMN IF NOT EXISTS file_bytes BYTEA
            """
        )

        await conn.execute(
            """
            ALTER TABLE public.chats
            ADD COLUMN IF NOT EXISTS pinned_message_id TEXT
            """
        )

        await conn.execute(
            """
            ALTER TABLE public.messages
            ADD COLUMN IF NOT EXISTS forwarded_from_message_id TEXT
            """
        )

        await conn.execute(
            """
            ALTER TABLE public.messages
            ADD COLUMN IF NOT EXISTS forwarded_from_user_id TEXT
            """
        )

        await conn.execute(
            """
            ALTER TABLE public.messages
            ADD COLUMN IF NOT EXISTS reply_to_message_id TEXT
            """
        )

        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS public.message_receipts (
                message_id TEXT NOT NULL REFERENCES public.messages(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
                delivered_at TIMESTAMPTZ,
                read_at TIMESTAMPTZ,
                PRIMARY KEY (message_id, user_id)
            )
            """
        )

        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_message_receipts_message_id
            ON public.message_receipts(message_id)
            """
        )


@app.on_event("shutdown")
async def shutdown():
    if db_pool:
        await db_pool.close()


@app.get("/health")
async def health():
    return {"ok": True}


@app.post("/auth/register")
async def register(data: RegisterIn):
    username = normalize_username(data.username)
    nickname = data.nickname.strip()

    async with db_pool.acquire() as conn:
        existing = await conn.fetchrow(
            """
            SELECT id
            FROM public.users
            WHERE username = $1
               OR nickname = $2
            """,
            username,
            nickname,
        )

        if existing:
            raise HTTPException(
                status_code=409,
                detail="Username or nickname already exists",
            )

        user_id = make_id()
        current_time = now()

        await conn.execute(
            """
            INSERT INTO public.users (
                id,
                username,
                password_hash,
                nickname,
                display_name,
                is_active,
                created_at,
                updated_at,
                last_login_at
            )
            VALUES ($1, $2, $3, $4, $5, true, $6, $6, $6)
            """,
            user_id,
            username,
            hash_password(data.password),
            nickname,
            nickname,
            current_time,
        )

    access_token = create_access_token(user_id)
    refresh_token = create_refresh_token()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "id": user_id,
            "username": username,
            "nickname": nickname,
            "display_name": nickname,
        },
    }


@app.post("/auth/login")
async def login(data: LoginIn):
    username = normalize_username(data.username)

    async with db_pool.acquire() as conn:
        user = await conn.fetchrow(
            """
            SELECT
                id,
                username,
                nickname,
                display_name,
                password_hash,
                is_active
            FROM public.users
            WHERE username = $1
            """,
            username,
        )

        if not user:
            raise HTTPException(status_code=401, detail="Invalid username or password")

        if not user["password_hash"]:
            raise HTTPException(status_code=401, detail="Invalid username or password")

        if not verify_password(data.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid username or password")

        if not user["is_active"]:
            raise HTTPException(status_code=403, detail="User is inactive")

    access_token = create_access_token(user["id"])
    refresh_token = create_refresh_token()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "nickname": user["nickname"],
            "display_name": user["display_name"],
        },
    }


@app.post("/auth/logout")
async def logout(user_id: str = Depends(get_current_user_id)):
    return {"ok": True}


@app.post("/push/token")
async def save_push_token(
    data: PushTokenIn,
    user_id: str = Depends(get_current_user_id),
):
    current_time = now()
    token_hash_id = hashlib.sha256(data.token.encode("utf-8")).hexdigest()
    platform = data.platform.strip().lower() or "unknown"

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO public.push_tokens (
                id,
                user_id,
                token,
                platform,
                created_at,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $5)
            ON CONFLICT (token)
            DO UPDATE SET
                user_id = EXCLUDED.user_id,
                platform = EXCLUDED.platform,
                updated_at = EXCLUDED.updated_at
            """,
            token_hash_id,
            user_id,
            data.token,
            platform,
            current_time,
        )

    return {"ok": True}


@app.post("/push/token/delete")
async def delete_push_token(
    data: PushTokenDeleteIn,
    user_id: str = Depends(get_current_user_id),
):
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            DELETE FROM public.push_tokens
            WHERE token = $1
              AND user_id = $2
            """,
            data.token,
            user_id,
        )

    return {"ok": True}


@app.get("/me")
async def me(user_id: str = Depends(get_current_user_id)):
    last_error = None

    for _ in range(2):
        try:
            async with db_pool.acquire() as conn:
                user = await conn.fetchrow(
                    """
                    SELECT
                        u.id,
                        u.username,
                        u.nickname,
                        u.display_name,
                        u.avatar_attachment_id,
                        s.theme,
                        s.accent_color,
                        s.chat_wallpaper,
                        s.bubble_style,
                        a.storage_key AS avatar_storage_key
                    FROM public.users u
                    LEFT JOIN public.user_settings s ON s.user_id = u.id
                    LEFT JOIN public.attachments a ON a.id = u.avatar_attachment_id
                    WHERE u.id = $1
                    """,
                    user_id,
                )

            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            avatar_url = None

            if user["avatar_storage_key"]:
                avatar_url = attachment_url(user["avatar_storage_key"])

            return {
                "id": user["id"],
                "username": user["username"],
                "nickname": user["nickname"],
                "display_name": user["display_name"],
                "avatar_attachment_id": user["avatar_attachment_id"],
                "avatar_url": avatar_url,
                "theme": user["theme"] or "system",
                "accent_color": user["accent_color"] or "blue",
                "chat_wallpaper": user["chat_wallpaper"] or "default",
                "bubble_style": user["bubble_style"] or "rounded",
            }

        except (
            asyncpg.exceptions.ConnectionDoesNotExistError,
            asyncpg.exceptions.InterfaceError,
            ConnectionResetError,
        ) as e:
            last_error = e

    print("ME ERROR:", repr(last_error), flush=True)
    raise HTTPException(status_code=503, detail="Database connection lost, try again")


@app.post("/profile")
async def update_profile(
    data: ProfileIn,
    user_id: str = Depends(get_current_user_id),
):
    nickname = clean_text(data.nickname)
    display_name = clean_text(data.display_name)

    if not nickname and not display_name:
        raise HTTPException(status_code=400, detail="Nothing to update")

    async with db_pool.acquire() as conn:
        if nickname:
            existing = await conn.fetchrow(
                """
                SELECT id
                FROM public.users
                WHERE nickname = $1
                  AND id <> $2
                """,
                nickname,
                user_id,
            )

            if existing:
                raise HTTPException(status_code=409, detail="Nickname already exists")

        await conn.execute(
            """
            UPDATE public.users
            SET
                nickname = COALESCE($1, nickname),
                display_name = COALESCE($2, display_name),
                updated_at = $3
            WHERE id = $4
            """,
            nickname,
            display_name,
            now(),
            user_id,
        )

    return {"ok": True}


@app.post("/settings/theme")
async def update_theme(
    data: ThemeIn,
    user_id: str = Depends(get_current_user_id),
):
    if data.theme not in ["system", "light", "dark"]:
        raise HTTPException(status_code=400, detail="Invalid theme")

    current_time = now()

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO public.user_settings (
                id,
                user_id,
                theme,
                created_at,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $4)
            ON CONFLICT (user_id)
            DO UPDATE SET
                theme = EXCLUDED.theme,
                updated_at = EXCLUDED.updated_at
            """,
            make_id(),
            user_id,
            data.theme,
            current_time,
        )

    return {"ok": True}


@app.post("/settings/chat-appearance")
async def update_chat_appearance(
    data: ChatAppearanceIn,
    user_id: str = Depends(get_current_user_id),
):
    allowed_wallpapers = ["default", "clean", "gradient", "night", "mint"]
    allowed_bubble_styles = ["rounded", "soft", "compact"]

    accent_color = clean_text(data.accent_color)
    chat_wallpaper = clean_text(data.chat_wallpaper)
    bubble_style = clean_text(data.bubble_style)

    if accent_color:
        is_old_named_color = accent_color in ["blue", "green", "purple", "orange", "pink"]
        is_hex_color = False

        if accent_color.startswith("#") and len(accent_color) in [7, 9]:
            try:
                int(accent_color[1:], 16)
                is_hex_color = True
            except ValueError:
                is_hex_color = False

        if not is_old_named_color and not is_hex_color:
            raise HTTPException(status_code=400, detail="Invalid accent color")

    if chat_wallpaper:
        is_builtin_wallpaper = chat_wallpaper in allowed_wallpapers
        is_uploaded_wallpaper = chat_wallpaper.startswith("/uploads/")
        is_remote_wallpaper = chat_wallpaper.startswith("http://") or chat_wallpaper.startswith("https://")

        if not is_builtin_wallpaper and not is_uploaded_wallpaper and not is_remote_wallpaper:
            raise HTTPException(status_code=400, detail="Invalid chat wallpaper")

    if bubble_style and bubble_style not in allowed_bubble_styles:
        raise HTTPException(status_code=400, detail="Invalid bubble style")

    current_time = now()

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO public.user_settings (
                id,
                user_id,
                theme,
                accent_color,
                chat_wallpaper,
                bubble_style,
                created_at,
                updated_at
            )
            VALUES (
                $1,
                $2,
                'system',
                COALESCE($3, 'blue'),
                COALESCE($4, 'default'),
                COALESCE($5, 'rounded'),
                $6,
                $6
            )
            ON CONFLICT (user_id)
            DO UPDATE SET
                accent_color = COALESCE($3, public.user_settings.accent_color),
                chat_wallpaper = COALESCE($4, public.user_settings.chat_wallpaper),
                bubble_style = COALESCE($5, public.user_settings.bubble_style),
                updated_at = $6
            """,
            make_id(),
            user_id,
            accent_color,
            chat_wallpaper,
            bubble_style,
            current_time,
        )

    return {"ok": True}


@app.get("/attachments/file/{storage_key:path}")
async def get_attachment_file(storage_key: str):
    if ".." in storage_key.replace("\\", "/").split("/"):
        raise HTTPException(status_code=400, detail="Invalid file path")

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT storage_key, original_name, mime_type, file_bytes
            FROM public.attachments
            WHERE storage_key = $1
            """,
            storage_key,
        )

    if not row:
        raise HTTPException(status_code=404, detail="File not found")

    content = row["file_bytes"]

    if content is None:
        base_dir = UPLOAD_DIR.resolve()
        file_path = (UPLOAD_DIR / storage_key).resolve()

        if not str(file_path).startswith(str(base_dir)):
            raise HTTPException(status_code=400, detail="Invalid file path")

        if not file_path.exists() or not file_path.is_file():
            raise HTTPException(
                status_code=404,
                detail="File is not available on disk and was not saved in database",
            )

        content = file_path.read_bytes()

        async with db_pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE public.attachments
                SET file_bytes = $2
                WHERE storage_key = $1
                  AND file_bytes IS NULL
                """,
                storage_key,
                content,
            )

    original_name = row["original_name"] or "file"
    mime_type = row["mime_type"] or "application/octet-stream"

    headers = {
        "Cache-Control": "public, max-age=31536000, immutable",
        "Content-Disposition": f"inline; filename*=UTF-8''{quote(original_name)}",
    }

    return Response(
        content=bytes(content),
        media_type=mime_type,
        headers=headers,
    )


@app.post("/attachments/upload")
async def upload_attachment(
    uploaded_file: UploadFile = File(...),
    send_as_file: bool = Form(False),
    user_id: str = Depends(get_current_user_id),
):
    content = await uploaded_file.read()

    if not content:
        raise HTTPException(status_code=400, detail="Empty file")

    max_size = 50 * 1024 * 1024

    if len(content) > max_size:
        raise HTTPException(status_code=400, detail="File too large. Max 50 MB")

    original_name = uploaded_file.filename or "file"
    mime_type = resolve_mime_type(original_name, uploaded_file.content_type)

    if send_as_file:
        kind = "file"
    else:
        kind = detect_attachment_kind(mime_type)

    attachment_id = make_id()
    storage_key = f"{user_id}/{attachment_id}_{safe_filename(original_name)}"

    file_path = UPLOAD_DIR / storage_key
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(content)

    current_time = now()

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO public.attachments (
                id,
                owner_user_id,
                message_id,
                purpose,
                storage_key,
                original_name,
                mime_type,
                size_bytes,
                kind,
                file_bytes,
                created_at
            )
            VALUES ($1, $2, NULL, 'message', $3, $4, $5, $6, $7, $8, $9)
            """,
            attachment_id,
            user_id,
            storage_key,
            original_name,
            mime_type,
            len(content),
            kind,
            content,
            current_time,
        )

    return {
        "id": attachment_id,
        "original_name": original_name,
        "mime_type": mime_type,
        "size_bytes": len(content),
        "kind": kind,
        "url": attachment_url(storage_key),
    }


@app.post("/profile/avatar")
async def upload_profile_avatar(
    uploaded_file: UploadFile = File(...),
    user_id: str = Depends(get_current_user_id),
):
    content = await uploaded_file.read()

    if not content:
        raise HTTPException(status_code=400, detail="Empty file")

    max_size = 10 * 1024 * 1024

    if len(content) > max_size:
        raise HTTPException(status_code=400, detail="Avatar too large. Max 10 MB")

    original_name = uploaded_file.filename or "avatar"
    mime_type = resolve_mime_type(original_name, uploaded_file.content_type)

    if not mime_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Avatar must be an image")

    attachment_id = make_id()
    storage_key = f"{user_id}/avatars/{attachment_id}_{safe_filename(original_name)}"

    file_path = UPLOAD_DIR / storage_key
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(content)

    current_time = now()

    async with db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                INSERT INTO public.attachments (
                    id,
                    owner_user_id,
                    message_id,
                    purpose,
                    storage_key,
                    original_name,
                    mime_type,
                    size_bytes,
                    kind,
                    file_bytes,
                    created_at
                )
                VALUES ($1, $2, NULL, 'avatar', $3, $4, $5, $6, 'image', $7, $8)
                """,
                attachment_id,
                user_id,
                storage_key,
                original_name,
                mime_type,
                len(content),
                content,
                current_time,
            )

            await conn.execute(
                """
                UPDATE public.users
                SET avatar_attachment_id = $1,
                    updated_at = $2
                WHERE id = $3
                """,
                attachment_id,
                current_time,
                user_id,
            )

    return {
        "id": attachment_id,
        "url": attachment_url(storage_key),
        "original_name": original_name,
        "mime_type": mime_type,
        "size_bytes": len(content),
        "kind": "image",
    }



@app.post("/settings/chat-wallpaper-image")
async def upload_chat_wallpaper_image(
    uploaded_file: UploadFile = File(...),
    user_id: str = Depends(get_current_user_id),
):
    content = await uploaded_file.read()

    if not content:
        raise HTTPException(status_code=400, detail="Empty file")

    max_size = 15 * 1024 * 1024

    if len(content) > max_size:
        raise HTTPException(status_code=400, detail="Wallpaper too large. Max 15 MB")

    original_name = uploaded_file.filename or "wallpaper"
    mime_type = resolve_mime_type(original_name, uploaded_file.content_type)

    if not mime_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Wallpaper must be an image")

    attachment_id = make_id()
    storage_key = f"{user_id}/wallpapers/{attachment_id}_{safe_filename(original_name)}"

    file_path = UPLOAD_DIR / storage_key
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(content)

    current_time = now()
    wallpaper_url = attachment_url(storage_key)

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO public.attachments (
                id,
                owner_user_id,
                message_id,
                purpose,
                storage_key,
                original_name,
                mime_type,
                size_bytes,
                kind,
                file_bytes,
                created_at
            )
            VALUES ($1, $2, NULL, 'wallpaper', $3, $4, $5, $6, 'image', $7, $8)
            """,
            attachment_id,
            user_id,
            storage_key,
            original_name,
            mime_type,
            len(content),
            content,
            current_time,
        )

        await conn.execute(
            """
            INSERT INTO public.user_settings (
                id,
                user_id,
                theme,
                accent_color,
                chat_wallpaper,
                bubble_style,
                created_at,
                updated_at
            )
            VALUES (
                $1,
                $2,
                'system',
                'blue',
                $3,
                'rounded',
                $4,
                $4
            )
            ON CONFLICT (user_id)
            DO UPDATE SET
                chat_wallpaper = EXCLUDED.chat_wallpaper,
                updated_at = EXCLUDED.updated_at
            """,
            make_id(),
            user_id,
            wallpaper_url,
            current_time,
        )

    return {
        "ok": True,
        "wallpaper_url": wallpaper_url,
    }


@app.get("/users/search")
async def search_users(
    q: str,
    user_id: str = Depends(get_current_user_id),
):
    query = q.strip().lower()

    if len(query) < 2:
        return []

    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                u.id,
                u.username,
                u.nickname,
                u.display_name,
                a.storage_key AS avatar_storage_key
            FROM public.users u
            LEFT JOIN public.attachments a ON a.id = u.avatar_attachment_id
            WHERE u.id <> $1
              AND u.is_active = true
              AND (
                lower(u.username) LIKE $2
                OR lower(u.nickname) LIKE $2
                OR lower(u.display_name) LIKE $2
              )
            ORDER BY u.username ASC
            LIMIT 20
            """,
            user_id,
            f"%{query}%",
        )

    result = []

    for row in rows:
        avatar_url = None

        if row["avatar_storage_key"]:
            avatar_url = attachment_url(row["avatar_storage_key"])

        result.append(
            {
                "id": row["id"],
                "username": row["username"],
                "nickname": row["nickname"],
                "display_name": row["display_name"],
                "avatar_url": avatar_url,
            }
        )

    return result


@app.get("/chats")
async def list_chats(user_id: str = Depends(get_current_user_id)):
    last_error = None

    for attempt in range(2):
        try:
            async with db_pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT
                        c.id,
                        CASE
                            WHEN c.is_group = true THEN c.title
                            ELSE COALESCE(other_user.display_name, other_user.nickname, other_user.username, c.title)
                        END AS title,
                        c.is_group,
                        c.created_at,
                        c.updated_at,
                        cm.pinned,
                        cm.hidden,
                        group_avatar.storage_key AS group_avatar_storage_key,
                        other_avatar.storage_key AS other_avatar_storage_key,
                        last_msg.text AS last_message_text,
                        last_msg.message_type AS last_message_type,
                        last_msg.created_at AS last_message_created_at,
                        member_count.count AS member_count
                    FROM public.chat_members cm
                    JOIN public.chats c
                      ON c.id = cm.chat_id
                    LEFT JOIN public.attachments group_avatar
                      ON group_avatar.id = c.avatar_attachment_id
                    LEFT JOIN public.chat_members other_cm
                      ON other_cm.chat_id = c.id
                     AND other_cm.user_id <> cm.user_id
                     AND other_cm.left_at IS NULL
                     AND other_cm.hidden = false
                    LEFT JOIN public.users other_user
                      ON other_user.id = other_cm.user_id
                    LEFT JOIN public.attachments other_avatar
                      ON other_avatar.id = other_user.avatar_attachment_id
                    LEFT JOIN LATERAL (
                        SELECT
                            m.text,
                            m.message_type,
                            m.created_at
                        FROM public.messages m
                        WHERE m.chat_id = c.id
                          AND m.deleted_at IS NULL
                        ORDER BY m.created_at DESC
                        LIMIT 1
                    ) last_msg ON true
                    LEFT JOIN LATERAL (
                        SELECT COUNT(*)::int AS count
                        FROM public.chat_members active_cm
                        WHERE active_cm.chat_id = c.id
                          AND active_cm.hidden = false
                          AND active_cm.left_at IS NULL
                    ) member_count ON true
                    WHERE cm.user_id = $1
                      AND cm.hidden = false
                      AND cm.left_at IS NULL
                    ORDER BY
                        cm.pinned DESC,
                        COALESCE(last_msg.created_at, c.updated_at, c.created_at) DESC
                    """,
                    user_id,
                )

            result = []

            for row in rows:
                avatar_url = None

                if row["is_group"] and row["group_avatar_storage_key"]:
                    avatar_url = attachment_url(row["group_avatar_storage_key"])
                elif row["other_avatar_storage_key"]:
                    avatar_url = attachment_url(row["other_avatar_storage_key"])

                last_message_text = row["last_message_text"]

                if not last_message_text and row["last_message_type"] == "file":
                    last_message_text = "Вложение"

                result.append(
                    {
                        "id": row["id"],
                        "title": row["title"] or "Чат",
                        "is_group": row["is_group"],
                        "member_count": row["member_count"] or 0,
                        "pinned": row["pinned"],
                        "hidden": row["hidden"],
                        "avatar_url": avatar_url,
                        "last_message_text": last_message_text,
                        "last_message_type": row["last_message_type"],
                        "last_message_created_at": row["last_message_created_at"].isoformat()
                        if row["last_message_created_at"]
                        else None,
                        "created_at": row["created_at"].isoformat()
                        if row["created_at"]
                        else None,
                        "updated_at": row["updated_at"].isoformat()
                        if row["updated_at"]
                        else None,
                    }
                )

            return result

        except (
            asyncpg.exceptions.ConnectionDoesNotExistError,
            asyncpg.exceptions.InterfaceError,
            ConnectionResetError,
            OSError,
        ) as e:
            last_error = e
            print(
                f"LIST_CHATS DB RETRY {attempt + 1}/2:",
                repr(e),
                flush=True,
            )

    print("LIST_CHATS ERROR:", repr(last_error), flush=True)
    raise HTTPException(status_code=503, detail="Database connection lost, try again")

@app.post("/chats/direct")
async def create_direct_chat(
    data: DirectChatCreateIn,
    user_id: str = Depends(get_current_user_id),
):
    other_user_id = data.user_id

    if other_user_id == user_id:
        raise HTTPException(status_code=400, detail="Cannot create chat with yourself")

    current_time = now()

    async with db_pool.acquire() as conn:
        other_user = await conn.fetchrow(
            """
            SELECT id, username, nickname, display_name
            FROM public.users
            WHERE id = $1
              AND is_active = true
            """,
            other_user_id,
        )

        if not other_user:
            raise HTTPException(status_code=404, detail="User not found")

        existing_chat = await conn.fetchrow(
            """
            SELECT c.id
            FROM public.chats c
            JOIN public.chat_members cm1 ON cm1.chat_id = c.id
            JOIN public.chat_members cm2 ON cm2.chat_id = c.id
            WHERE c.is_group = false
              AND cm1.user_id = $1
              AND cm2.user_id = $2
            LIMIT 1
            """,
            user_id,
            other_user_id,
        )

        title = user_display_name(other_user)

        if existing_chat:
            return {
                "id": existing_chat["id"],
                "title": title,
                "is_group": False,
                "already_exists": True,
            }

        chat_id = make_id()

        async with conn.transaction():
            await conn.execute(
                """
                INSERT INTO public.chats (
                    id,
                    title,
                    is_group,
                    created_by_user_id,
                    created_at,
                    updated_at
                )
                VALUES ($1, $2, false, $3, $4, $4)
                """,
                chat_id,
                title,
                user_id,
                current_time,
            )

            await conn.execute(
                """
                INSERT INTO public.chat_members (
                    id,
                    chat_id,
                    user_id,
                    joined_at,
                    pinned,
                    hidden
                )
                VALUES
                    ($1, $2, $3, $5, false, false),
                    ($4, $2, $6, $5, false, false)
                """,
                make_id(),
                chat_id,
                user_id,
                make_id(),
                current_time,
                other_user_id,
            )

    return {
        "id": chat_id,
        "title": title,
        "is_group": False,
        "already_exists": False,
        "created_at": current_time.isoformat(),
    }



@app.post("/support/developer-chat")
async def open_developer_chat(
    data: SupportDeveloperChatIn,
    user_id: str = Depends(get_current_user_id),
):
    developer_user_id = clean_text(DEVELOPER_USER_ID)
    developer_username = clean_text(DEVELOPER_USERNAME)

    if not developer_user_id and not developer_username:
        raise HTTPException(
            status_code=500,
            detail="Developer contact is not configured",
        )

    current_time = now()

    async with db_pool.acquire() as conn:
        if developer_user_id:
            developer = await conn.fetchrow(
                """
                SELECT id, username, nickname, display_name
                FROM public.users
                WHERE id = $1
                  AND is_active = true
                """,
                developer_user_id,
            )
        else:
            developer = await conn.fetchrow(
                """
                SELECT id, username, nickname, display_name
                FROM public.users
                WHERE lower(username) = lower($1)
                  AND is_active = true
                """,
                developer_username,
            )

        if not developer:
            raise HTTPException(status_code=404, detail="Developer user not found")

        other_user_id = developer["id"]

        if other_user_id == user_id:
            raise HTTPException(
                status_code=400,
                detail="Developer chat cannot be opened with yourself",
            )

        title = user_display_name(developer)

        existing_chat = await conn.fetchrow(
            """
            SELECT c.id
            FROM public.chats c
            JOIN public.chat_members cm1 ON cm1.chat_id = c.id
            JOIN public.chat_members cm2 ON cm2.chat_id = c.id
            WHERE c.is_group = false
              AND cm1.user_id = $1
              AND cm2.user_id = $2
            LIMIT 1
            """,
            user_id,
            other_user_id,
        )

        already_exists = existing_chat is not None
        chat_id = existing_chat["id"] if existing_chat else make_id()

        async with conn.transaction():
            if already_exists:
                await conn.execute(
                    """
                    UPDATE public.chat_members
                    SET hidden = false,
                        left_at = NULL
                    WHERE chat_id = $1
                      AND user_id = ANY($2::text[])
                    """,
                    chat_id,
                    [user_id, other_user_id],
                )

                await conn.execute(
                    """
                    UPDATE public.chats
                    SET updated_at = $1
                    WHERE id = $2
                    """,
                    current_time,
                    chat_id,
                )
            else:
                await conn.execute(
                    """
                    INSERT INTO public.chats (
                        id,
                        title,
                        is_group,
                        created_by_user_id,
                        created_at,
                        updated_at
                    )
                    VALUES ($1, $2, false, $3, $4, $4)
                    """,
                    chat_id,
                    title,
                    user_id,
                    current_time,
                )

                await conn.execute(
                    """
                    INSERT INTO public.chat_members (
                        id,
                        chat_id,
                        user_id,
                        joined_at,
                        pinned,
                        hidden
                    )
                    VALUES
                        ($1, $2, $3, $5, false, false),
                        ($4, $2, $6, $5, false, false)
                    """,
                    make_id(),
                    chat_id,
                    user_id,
                    make_id(),
                    current_time,
                    other_user_id,
                )

    chat_payload = {
        "id": chat_id,
        "title": title,
        "is_group": False,
        "already_exists": already_exists,
        "created_at": current_time.isoformat(),
    }

    await manager.send_to_user(
        other_user_id,
        {
            "type": "chat.created",
            "chat": chat_payload,
        },
    )

    await manager.send_to_user(
        user_id,
        {
            "type": "chat.created",
            "chat": chat_payload,
        },
    )

    return {"chat": chat_payload}


@app.post("/chats/group")
async def create_group_chat(
    data: GroupChatCreateIn,
    user_id: str = Depends(get_current_user_id),
):
    title = data.title.strip()
    if not title:
        raise HTTPException(status_code=400, detail="Group title required")

    member_user_ids = []
    seen = {user_id}

    for raw_id in data.member_user_ids:
        value = clean_text(raw_id)
        if value and value not in seen:
            seen.add(value)
            member_user_ids.append(value)

    if not member_user_ids:
        raise HTTPException(status_code=400, detail="Select at least one member")

    current_time = now()
    chat_id = make_id()

    async with db_pool.acquire() as conn:
        users_count = await conn.fetchval(
            """
            SELECT COUNT(*)
            FROM public.users
            WHERE id = ANY($1::text[])
              AND is_active = true
            """,
            member_user_ids,
        )

        if users_count != len(member_user_ids):
            raise HTTPException(status_code=404, detail="Some users not found")

        async with conn.transaction():
            await conn.execute(
                """
                INSERT INTO public.chats (
                    id,
                    title,
                    is_group,
                    created_by_user_id,
                    created_at,
                    updated_at
                )
                VALUES ($1, $2, true, $3, $4, $4)
                """,
                chat_id,
                title,
                user_id,
                current_time,
            )

            await conn.execute(
                """
                INSERT INTO public.chat_members (
                    id,
                    chat_id,
                    user_id,
                    joined_at,
                    pinned,
                    hidden,
                    role,
                    left_at
                )
                VALUES ($1, $2, $3, $4, false, false, 'owner', NULL)
                """,
                make_id(),
                chat_id,
                user_id,
                current_time,
            )

            for member_id in member_user_ids:
                await conn.execute(
                    """
                    INSERT INTO public.chat_members (
                        id,
                        chat_id,
                        user_id,
                        joined_at,
                        pinned,
                        hidden,
                        role,
                        left_at
                    )
                    VALUES ($1, $2, $3, $4, false, false, 'member', NULL)
                    """,
                    make_id(),
                    chat_id,
                    member_id,
                    current_time,
                )

    payload = {
        "id": chat_id,
        "title": title,
        "is_group": True,
        "member_count": len(member_user_ids) + 1,
        "avatar_url": None,
        "created_at": current_time.isoformat(),
    }

    for member_id in member_user_ids:
        await manager.send_to_user(
            member_id,
            {
                "type": "chat.created",
                "chat": payload,
            },
        )

    return payload


@app.get("/chats/{chat_id}/members")
async def list_chat_members(
    chat_id: str,
    user_id: str = Depends(get_current_user_id),
):
    async with db_pool.acquire() as conn:
        await assert_chat_member(conn, chat_id, user_id)

        rows = await conn.fetch(
            """
            SELECT
                cm.user_id,
                cm.role,
                cm.joined_at,
                u.username,
                u.nickname,
                u.display_name,
                a.storage_key AS avatar_storage_key
            FROM public.chat_members cm
            JOIN public.users u ON u.id = cm.user_id
            LEFT JOIN public.attachments a ON a.id = u.avatar_attachment_id
            WHERE cm.chat_id = $1
              AND cm.hidden = false
              AND cm.left_at IS NULL
            ORDER BY
                CASE cm.role
                    WHEN 'owner' THEN 0
                    WHEN 'admin' THEN 1
                    ELSE 2
                END,
                COALESCE(u.display_name, u.nickname, u.username) ASC
            """,
            chat_id,
        )

    result = []

    for row in rows:
        avatar_url = None
        if row["avatar_storage_key"]:
            avatar_url = attachment_url(row["avatar_storage_key"])

        result.append(
            {
                "user_id": row["user_id"],
                "username": row["username"],
                "nickname": row["nickname"],
                "display_name": row["display_name"],
                "name": row["display_name"] or row["nickname"] or row["username"],
                "role": row["role"],
                "avatar_url": avatar_url,
                "joined_at": row["joined_at"].isoformat() if row["joined_at"] else None,
                "is_mine": row["user_id"] == user_id,
            }
        )

    return result


async def assert_group_admin(
    conn: asyncpg.Connection,
    chat_id: str,
    user_id: str,
) -> None:
    row = await conn.fetchrow(
        """
        SELECT c.is_group, cm.role
        FROM public.chats c
        JOIN public.chat_members cm ON cm.chat_id = c.id
        WHERE c.id = $1
          AND cm.user_id = $2
          AND cm.hidden = false
          AND cm.left_at IS NULL
        """,
        chat_id,
        user_id,
    )

    if not row:
        raise HTTPException(status_code=403, detail="Not a chat member")

    if not row["is_group"]:
        raise HTTPException(status_code=400, detail="Chat is not a group")

    if row["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Only group admin can do this")


@app.post("/chats/{chat_id}/members")
async def add_chat_members(
    chat_id: str,
    data: GroupMembersAddIn,
    user_id: str = Depends(get_current_user_id),
):
    raw_ids = []
    seen = {user_id}

    for item in data.user_ids:
        value = clean_text(item)
        if value and value not in seen:
            seen.add(value)
            raw_ids.append(value)

    if not raw_ids:
        raise HTTPException(status_code=400, detail="No users selected")

    current_time = now()

    async with db_pool.acquire() as conn:
        await assert_group_admin(conn, chat_id, user_id)

        existing_users_count = await conn.fetchval(
            """
            SELECT COUNT(*)
            FROM public.users
            WHERE id = ANY($1::text[])
              AND is_active = true
            """,
            raw_ids,
        )

        if existing_users_count != len(raw_ids):
            raise HTTPException(status_code=404, detail="Some users not found")

        added_ids = []

        async with conn.transaction():
            for member_id in raw_ids:
                existing_member = await conn.fetchrow(
                    """
                    SELECT id, left_at
                    FROM public.chat_members
                    WHERE chat_id = $1
                      AND user_id = $2
                    LIMIT 1
                    """,
                    chat_id,
                    member_id,
                )

                if existing_member and existing_member["left_at"] is None:
                    continue

                if existing_member:
                    await conn.execute(
                        """
                        UPDATE public.chat_members
                        SET hidden = false,
                            left_at = NULL,
                            joined_at = $1,
                            role = 'member'
                        WHERE id = $2
                        """,
                        current_time,
                        existing_member["id"],
                    )
                else:
                    await conn.execute(
                        """
                        INSERT INTO public.chat_members (
                            id,
                            chat_id,
                            user_id,
                            joined_at,
                            pinned,
                            hidden,
                            role,
                            left_at
                        )
                        VALUES ($1, $2, $3, $4, false, false, 'member', NULL)
                        """,
                        make_id(),
                        chat_id,
                        member_id,
                        current_time,
                    )

                added_ids.append(member_id)

            await conn.execute(
                """
                UPDATE public.chats
                SET updated_at = $1
                WHERE id = $2
                """,
                current_time,
                chat_id,
            )

        chat = await conn.fetchrow(
            """
            SELECT id, title, is_group
            FROM public.chats
            WHERE id = $1
            """,
            chat_id,
        )

    payload = {
        "id": chat["id"],
        "title": chat["title"],
        "is_group": chat["is_group"],
    }

    for member_id in added_ids:
        await manager.send_to_user(
            member_id,
            {
                "type": "chat.created",
                "chat": payload,
            },
        )

    await manager.broadcast_to_chat(
        chat_id,
        {
            "type": "chat.members.updated",
            "chat_id": chat_id,
        },
    )

    return {"ok": True, "added_count": len(added_ids)}


@app.post("/chats/{chat_id}/leave")
async def leave_group_chat(
    chat_id: str,
    user_id: str = Depends(get_current_user_id),
):
    current_time = now()

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT c.is_group, cm.id, cm.role
            FROM public.chats c
            JOIN public.chat_members cm ON cm.chat_id = c.id
            WHERE c.id = $1
              AND cm.user_id = $2
              AND cm.hidden = false
              AND cm.left_at IS NULL
            """,
            chat_id,
            user_id,
        )

        if not row:
            raise HTTPException(status_code=403, detail="Not a chat member")

        if not row["is_group"]:
            raise HTTPException(status_code=400, detail="Cannot leave direct chat")

        if row["role"] == "owner":
            other_owner = await conn.fetchval(
                """
                SELECT user_id
                FROM public.chat_members
                WHERE chat_id = $1
                  AND user_id <> $2
                  AND hidden = false
                  AND left_at IS NULL
                ORDER BY joined_at ASC
                LIMIT 1
                """,
                chat_id,
                user_id,
            )

            if other_owner:
                await conn.execute(
                    """
                    UPDATE public.chat_members
                    SET role = 'owner'
                    WHERE chat_id = $1
                      AND user_id = $2
                    """,
                    chat_id,
                    other_owner,
                )

        await conn.execute(
            """
            UPDATE public.chat_members
            SET hidden = true,
                left_at = $1
            WHERE id = $2
            """,
            current_time,
            row["id"],
        )

    await manager.broadcast_to_chat(
        chat_id,
        {
            "type": "chat.members.updated",
            "chat_id": chat_id,
        },
    )

    return {"ok": True}


@app.post("/chats/{chat_id}/delete")
async def delete_chat_for_me(
    chat_id: str,
    user_id: str = Depends(get_current_user_id),
):
    current_time = now()
    affected_user_ids = []

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT c.is_group, cm.id, cm.role
            FROM public.chats c
            JOIN public.chat_members cm ON cm.chat_id = c.id
            WHERE c.id = $1
              AND cm.user_id = $2
              AND cm.hidden = false
              AND cm.left_at IS NULL
            """,
            chat_id,
            user_id,
        )

        if not row:
            raise HTTPException(status_code=403, detail="Not a chat member")

        if row["is_group"] and row["role"] == "owner":
            other_owner = await conn.fetchval(
                """
                SELECT user_id
                FROM public.chat_members
                WHERE chat_id = $1
                  AND user_id <> $2
                  AND hidden = false
                  AND left_at IS NULL
                ORDER BY joined_at ASC
                LIMIT 1
                """,
                chat_id,
                user_id,
            )

            if other_owner:
                await conn.execute(
                    """
                    UPDATE public.chat_members
                    SET role = 'owner'
                    WHERE chat_id = $1
                      AND user_id = $2
                    """,
                    chat_id,
                    other_owner,
                )

        affected_rows = await conn.fetch(
            """
            SELECT user_id
            FROM public.chat_members
            WHERE chat_id = $1
              AND hidden = false
              AND left_at IS NULL
            """,
            chat_id,
        )
        affected_user_ids = [r["user_id"] for r in affected_rows]

        await conn.execute(
            """
            UPDATE public.chat_members
            SET hidden = true,
                left_at = $1
            WHERE id = $2
            """,
            current_time,
            row["id"],
        )

    await manager.send_to_user(
        user_id,
        {
            "type": "chat.deleted",
            "chat_id": chat_id,
        },
    )

    for target_user_id in affected_user_ids:
        if target_user_id == user_id:
            continue

        await manager.send_to_user(
            target_user_id,
            {
                "type": "chat.members.updated",
                "chat_id": chat_id,
            },
        )

    return {"ok": True}


@app.post("/chats/{chat_id}/title")
async def update_group_title(
    chat_id: str,
    data: ChatTitleUpdateIn,
    user_id: str = Depends(get_current_user_id),
):
    title = data.title.strip()
    if not title:
        raise HTTPException(status_code=400, detail="Group title required")

    current_time = now()

    async with db_pool.acquire() as conn:
        await assert_group_admin(conn, chat_id, user_id)

        await conn.execute(
            """
            UPDATE public.chats
            SET title = $1,
                updated_at = $2
            WHERE id = $3
              AND is_group = true
            """,
            title,
            current_time,
            chat_id,
        )

    await manager.broadcast_to_chat(
        chat_id,
        {
            "type": "chat.updated",
            "chat_id": chat_id,
            "title": title,
        },
    )

    return {"ok": True, "title": title}


@app.post("/chats/{chat_id}/avatar")
async def upload_group_avatar(
    chat_id: str,
    uploaded_file: UploadFile = File(...),
    user_id: str = Depends(get_current_user_id),
):
    content = await uploaded_file.read()

    if not content:
        raise HTTPException(status_code=400, detail="Empty file")

    max_size = 10 * 1024 * 1024

    if len(content) > max_size:
        raise HTTPException(status_code=400, detail="Avatar too large. Max 10 MB")

    original_name = uploaded_file.filename or "group_avatar"
    mime_type = resolve_mime_type(original_name, uploaded_file.content_type)

    if not mime_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Avatar must be an image")

    attachment_id = make_id()
    storage_key = f"groups/{chat_id}/{attachment_id}_{safe_filename(original_name)}"

    file_path = UPLOAD_DIR / storage_key
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(content)

    current_time = now()

    async with db_pool.acquire() as conn:
        await assert_group_admin(conn, chat_id, user_id)

        async with conn.transaction():
            await conn.execute(
                """
                INSERT INTO public.attachments (
                    id,
                    owner_user_id,
                    message_id,
                    purpose,
                    storage_key,
                    original_name,
                    mime_type,
                    size_bytes,
                    kind,
                    file_bytes,
                    created_at
                )
                VALUES ($1, $2, NULL, 'group_avatar', $3, $4, $5, $6, 'image', $7, $8)
                """,
                attachment_id,
                user_id,
                storage_key,
                original_name,
                mime_type,
                len(content),
                content,
                current_time,
            )

            await conn.execute(
                """
                UPDATE public.chats
                SET avatar_attachment_id = $1,
                    updated_at = $2
                WHERE id = $3
                  AND is_group = true
                """,
                attachment_id,
                current_time,
                chat_id,
            )

    avatar_url = attachment_url(storage_key)

    await manager.broadcast_to_chat(
        chat_id,
        {
            "type": "chat.updated",
            "chat_id": chat_id,
            "avatar_url": avatar_url,
        },
    )

    return {
        "ok": True,
        "id": attachment_id,
        "url": avatar_url,
    }


@app.post("/chat-requests")
async def create_chat_request(
    data: ChatRequestCreateIn,
    user_id: str = Depends(get_current_user_id),
):
    receiver_user_id = data.receiver_user_id

    if receiver_user_id == user_id:
        raise HTTPException(status_code=400, detail="Cannot send request to yourself")

    current_time = now()
    request_id = make_id()

    async with db_pool.acquire() as conn:
        receiver = await conn.fetchrow(
            """
            SELECT id, username, nickname, display_name
            FROM public.users
            WHERE id = $1
              AND is_active = true
            """,
            receiver_user_id,
        )

        if not receiver:
            raise HTTPException(status_code=404, detail="User not found")

        existing_chat = await conn.fetchrow(
            """
            SELECT c.id
            FROM public.chats c
            JOIN public.chat_members cm1 ON cm1.chat_id = c.id
            JOIN public.chat_members cm2 ON cm2.chat_id = c.id
            WHERE c.is_group = false
              AND cm1.user_id = $1
              AND cm2.user_id = $2
            LIMIT 1
            """,
            user_id,
            receiver_user_id,
        )

        if existing_chat:
            raise HTTPException(status_code=409, detail="Chat already exists")

        existing_request = await conn.fetchrow(
            """
            SELECT id
            FROM public.chat_requests
            WHERE status = 'pending'
              AND (
                (requester_user_id = $1 AND receiver_user_id = $2)
                OR
                (requester_user_id = $2 AND receiver_user_id = $1)
              )
            LIMIT 1
            """,
            user_id,
            receiver_user_id,
        )

        if existing_request:
            raise HTTPException(status_code=409, detail="Chat request already pending")

        await conn.execute(
            """
            INSERT INTO public.chat_requests (
                id,
                requester_user_id,
                receiver_user_id,
                status,
                chat_id,
                created_at,
                responded_at
            )
            VALUES ($1, $2, $3, 'pending', NULL, $4, NULL)
            """,
            request_id,
            user_id,
            receiver_user_id,
            current_time,
        )

        requester = await conn.fetchrow(
            """
            SELECT id, username, nickname, display_name
            FROM public.users
            WHERE id = $1
            """,
            user_id,
        )

    request_payload = {
        "id": request_id,
        "requester_user_id": user_id,
        "receiver_user_id": receiver_user_id,
        "requester_username": requester["username"],
        "requester_name": user_display_name(requester),
        "status": "pending",
        "created_at": current_time.isoformat(),
    }

    await manager.send_to_user(
        receiver_user_id,
        {
            "type": "chat_request.created",
            "request": request_payload,
        },
    )

    return request_payload


@app.get("/chat-requests/incoming")
async def list_incoming_chat_requests(
    user_id: str = Depends(get_current_user_id),
):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                cr.id,
                cr.requester_user_id,
                cr.receiver_user_id,
                cr.status,
                cr.chat_id,
                cr.created_at,
                cr.responded_at,
                u.username AS requester_username,
                u.nickname AS requester_nickname,
                u.display_name AS requester_display_name,
                a.storage_key AS requester_avatar_storage_key
            FROM public.chat_requests cr
            JOIN public.users u ON u.id = cr.requester_user_id
            LEFT JOIN public.attachments a ON a.id = u.avatar_attachment_id
            WHERE cr.receiver_user_id = $1
              AND cr.status = 'pending'
            ORDER BY cr.created_at DESC
            """,
            user_id,
        )

    result = []

    for row in rows:
        avatar_url = None

        if row["requester_avatar_storage_key"]:
            avatar_url = attachment_url(row["requester_avatar_storage_key"])

        result.append(
            {
                "id": row["id"],
                "requester_user_id": row["requester_user_id"],
                "receiver_user_id": row["receiver_user_id"],
                "status": row["status"],
                "chat_id": row["chat_id"],
                "requester_username": row["requester_username"],
                "requester_name": row["requester_display_name"]
                or row["requester_nickname"]
                or row["requester_username"],
                "requester_avatar_url": avatar_url,
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                "responded_at": row["responded_at"].isoformat() if row["responded_at"] else None,
            }
        )

    return result


@app.get("/chat-requests/outgoing")
async def list_outgoing_chat_requests(
    user_id: str = Depends(get_current_user_id),
):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                cr.id,
                cr.requester_user_id,
                cr.receiver_user_id,
                cr.status,
                cr.chat_id,
                cr.created_at,
                cr.responded_at,
                u.username AS receiver_username,
                u.nickname AS receiver_nickname,
                u.display_name AS receiver_display_name,
                a.storage_key AS receiver_avatar_storage_key
            FROM public.chat_requests cr
            JOIN public.users u ON u.id = cr.receiver_user_id
            LEFT JOIN public.attachments a ON a.id = u.avatar_attachment_id
            WHERE cr.requester_user_id = $1
              AND cr.status = 'pending'
            ORDER BY cr.created_at DESC
            """,
            user_id,
        )

    result = []

    for row in rows:
        avatar_url = None

        if row["receiver_avatar_storage_key"]:
            avatar_url = attachment_url(row["receiver_avatar_storage_key"])

        result.append(
            {
                "id": row["id"],
                "requester_user_id": row["requester_user_id"],
                "receiver_user_id": row["receiver_user_id"],
                "status": row["status"],
                "chat_id": row["chat_id"],
                "receiver_username": row["receiver_username"],
                "receiver_name": row["receiver_display_name"]
                or row["receiver_nickname"]
                or row["receiver_username"],
                "receiver_avatar_url": avatar_url,
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                "responded_at": row["responded_at"].isoformat() if row["responded_at"] else None,
            }
        )

    return result


@app.post("/chat-requests/{request_id}/cancel")
async def cancel_chat_request(
    request_id: str,
    user_id: str = Depends(get_current_user_id),
):
    current_time = now()

    async with db_pool.acquire() as conn:
        request_row = await conn.fetchrow(
            """
            SELECT id, requester_user_id, receiver_user_id, status
            FROM public.chat_requests
            WHERE id = $1
            """,
            request_id,
        )

        if not request_row:
            raise HTTPException(status_code=404, detail="Request not found")

        if request_row["requester_user_id"] != user_id:
            raise HTTPException(status_code=403, detail="Only requester can cancel request")

        if request_row["status"] != "pending":
            raise HTTPException(status_code=409, detail="Request is not pending")

        await conn.execute(
            """
            UPDATE public.chat_requests
            SET status = 'cancelled',
                responded_at = $1
            WHERE id = $2
            """,
            current_time,
            request_id,
        )

    await manager.send_to_user(
        request_row["receiver_user_id"],
        {
            "type": "chat_request.cancelled",
            "request_id": request_id,
        },
    )

    return {"ok": True}


@app.post("/chat-requests/{request_id}/accept")
async def accept_chat_request(
    request_id: str,
    user_id: str = Depends(get_current_user_id),
):
    current_time = now()

    async with db_pool.acquire() as conn:
        request_row = await conn.fetchrow(
            """
            SELECT
                cr.id,
                cr.requester_user_id,
                cr.receiver_user_id,
                cr.status,
                requester.username AS requester_username,
                requester.nickname AS requester_nickname,
                requester.display_name AS requester_display_name,
                receiver.username AS receiver_username,
                receiver.nickname AS receiver_nickname,
                receiver.display_name AS receiver_display_name
            FROM public.chat_requests cr
            JOIN public.users requester ON requester.id = cr.requester_user_id
            JOIN public.users receiver ON receiver.id = cr.receiver_user_id
            WHERE cr.id = $1
            """,
            request_id,
        )

        if not request_row:
            raise HTTPException(status_code=404, detail="Request not found")

        if request_row["receiver_user_id"] != user_id:
            raise HTTPException(status_code=403, detail="Only receiver can accept request")

        if request_row["status"] != "pending":
            raise HTTPException(status_code=409, detail="Request is not pending")

        requester_user_id = request_row["requester_user_id"]
        receiver_user_id = request_row["receiver_user_id"]

        requester_name = (
            request_row["requester_display_name"]
            or request_row["requester_nickname"]
            or request_row["requester_username"]
        )

        receiver_name = (
            request_row["receiver_display_name"]
            or request_row["receiver_nickname"]
            or request_row["receiver_username"]
        )

        chat_id = make_id()

        async with conn.transaction():
            await conn.execute(
                """
                INSERT INTO public.chats (
                    id,
                    title,
                    is_group,
                    created_by_user_id,
                    created_at,
                    updated_at
                )
                VALUES ($1, $2, false, $3, $4, $4)
                """,
                chat_id,
                requester_name,
                receiver_user_id,
                current_time,
            )

            await conn.execute(
                """
                INSERT INTO public.chat_members (
                    id,
                    chat_id,
                    user_id,
                    joined_at,
                    pinned,
                    hidden
                )
                VALUES
                    ($1, $2, $3, $5, false, false),
                    ($4, $2, $6, $5, false, false)
                """,
                make_id(),
                chat_id,
                requester_user_id,
                make_id(),
                current_time,
                receiver_user_id,
            )

            await conn.execute(
                """
                UPDATE public.chat_requests
                SET status = 'accepted',
                    chat_id = $1,
                    responded_at = $2
                WHERE id = $3
                """,
                chat_id,
                current_time,
                request_id,
            )

    await manager.send_to_user(
        requester_user_id,
        {
            "type": "chat_request.accepted",
            "request_id": request_id,
            "chat": {
                "id": chat_id,
                "title": receiver_name,
            },
        },
    )

    await manager.send_to_user(
        receiver_user_id,
        {
            "type": "chat_request.accepted",
            "request_id": request_id,
            "chat": {
                "id": chat_id,
                "title": requester_name,
            },
        },
    )

    return {
        "ok": True,
        "chat": {
            "id": chat_id,
            "title": requester_name,
        },
    }


@app.post("/chat-requests/{request_id}/decline")
async def decline_chat_request(
    request_id: str,
    user_id: str = Depends(get_current_user_id),
):
    current_time = now()

    async with db_pool.acquire() as conn:
        request_row = await conn.fetchrow(
            """
            SELECT id, requester_user_id, receiver_user_id, status
            FROM public.chat_requests
            WHERE id = $1
            """,
            request_id,
        )

        if not request_row:
            raise HTTPException(status_code=404, detail="Request not found")

        if request_row["receiver_user_id"] != user_id:
            raise HTTPException(status_code=403, detail="Only receiver can decline request")

        if request_row["status"] != "pending":
            raise HTTPException(status_code=409, detail="Request is not pending")

        await conn.execute(
            """
            UPDATE public.chat_requests
            SET status = 'declined',
                responded_at = $1
            WHERE id = $2
            """,
            current_time,
            request_id,
        )

    await manager.send_to_user(
        request_row["requester_user_id"],
        {
            "type": "chat_request.declined",
            "request_id": request_id,
        },
    )

    return {"ok": True}


@app.get("/chats/{chat_id}/messages")
async def list_messages(
    chat_id: str,
    user_id: str = Depends(get_current_user_id),
):
    async with db_pool.acquire() as conn:
        await assert_chat_member(conn, chat_id, user_id)

        rows = await conn.fetch(
            """
            SELECT
                m.id,
                m.chat_id,
                m.sender_user_id,
                m.text,
                m.message_type,
                m.created_at,
                m.edited_at,
                m.reply_to_message_id,
                m.forwarded_from_message_id,
                m.forwarded_from_user_id,

                u.username,
                u.nickname,
                u.display_name,

                fu.username AS forwarded_from_username,
                fu.nickname AS forwarded_from_nickname,
                fu.display_name AS forwarded_from_display_name,

                a.id AS attachment_id,
                a.storage_key AS attachment_storage_key,
                a.original_name AS attachment_original_name,
                a.mime_type AS attachment_mime_type,
                a.size_bytes AS attachment_size_bytes,
                a.kind AS attachment_kind,

                rm.id AS reply_message_id,
                rm.sender_user_id AS reply_sender_user_id,
                rm.text AS reply_text,
                rm.message_type AS reply_message_type,
                ru.username AS reply_username,
                ru.nickname AS reply_nickname,
                ru.display_name AS reply_display_name,
                ra.id AS reply_attachment_id,
                ra.storage_key AS reply_attachment_storage_key,
                ra.original_name AS reply_attachment_original_name,
                ra.mime_type AS reply_attachment_mime_type,
                ra.size_bytes AS reply_attachment_size_bytes,
                ra.kind AS reply_attachment_kind,

                (m.id = c.pinned_message_id) AS pinned,

                CASE
                    WHEN m.sender_user_id = $2 AND EXISTS (
                        SELECT 1
                        FROM public.message_receipts mr
                        WHERE mr.message_id = m.id
                          AND mr.user_id <> $2
                          AND mr.read_at IS NOT NULL
                    ) THEN 'read'
                    WHEN m.sender_user_id = $2 AND EXISTS (
                        SELECT 1
                        FROM public.message_receipts mr
                        WHERE mr.message_id = m.id
                          AND mr.user_id <> $2
                          AND mr.delivered_at IS NOT NULL
                    ) THEN 'delivered'
                    WHEN m.sender_user_id = $2 THEN 'sent'
                    ELSE NULL
                END AS delivery_status
            FROM public.messages m
            JOIN public.chats c
              ON c.id = m.chat_id
            JOIN public.users u
              ON u.id = m.sender_user_id
            LEFT JOIN public.users fu
              ON fu.id = m.forwarded_from_user_id
            LEFT JOIN public.attachments a
              ON a.message_id = m.id
            LEFT JOIN public.messages rm
              ON rm.id = m.reply_to_message_id
             AND rm.chat_id = m.chat_id
             AND rm.deleted_at IS NULL
            LEFT JOIN public.users ru
              ON ru.id = rm.sender_user_id
            LEFT JOIN public.attachments ra
              ON ra.message_id = rm.id
            WHERE m.chat_id = $1
              AND m.deleted_at IS NULL
            ORDER BY m.created_at ASC
            LIMIT 300
            """,
            chat_id,
            user_id,
        )

        message_ids = [row["id"] for row in rows]
        reactions_by_message = await fetch_reactions_for_messages(
            conn,
            message_ids,
            user_id,
        )

    return [
        format_message_row(row, reactions_by_message, user_id)
        for row in rows
    ]


def _send_onesignal_request_sync(payload: dict) -> dict:
    if not ONESIGNAL_REST_API_KEY:
        raise RuntimeError("ONESIGNAL_REST_API_KEY is not set")

    body = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        ONESIGNAL_API_URL,
        data=body,
        method="POST",
headers={
    "Authorization": f"Key {ONESIGNAL_REST_API_KEY.strip()}",
    "Content-Type": "application/json; charset=utf-8",
    "Accept": "application/json",
},
    )

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OneSignal HTTP {e.code}: {error_body}") from e


async def send_onesignal_push_to_users(
    target_user_ids: list[str],
    title: str,
    body: str,
    chat_id: str,
    sender_user_id: str,
):
    print(
        "OneSignal target users:",
        {
            "chat_id": chat_id,
            "sender_user_id": sender_user_id,
            "target_user_ids": target_user_ids,
        },
        flush=True,
    )
    if not ONESIGNAL_APP_ID or not ONESIGNAL_REST_API_KEY:
        print("OneSignal skipped: env is not configured", flush=True)
        return

    target_user_ids = [user_id for user_id in target_user_ids if user_id]

    if not target_user_ids:
        print("OneSignal skipped: no target users", flush=True)
        return

    notification_title = "UMe"
    notification_body = f"{title}: {body[:160]}"

    payload = {
        "app_id": ONESIGNAL_APP_ID,
        "include_aliases": {
            "external_id": target_user_ids,
        },
        "target_channel": "push",

        "headings": {
            "en": notification_title,
            "ru": notification_title,
        },
        "contents": {
            "en": notification_body,
            "ru": notification_body,
        },

        "web_url": "https://ume-messenger-bd3b1.web.app/",

        "chrome_web_icon": "https://ume-messenger-bd3b1.web.app/icons/Icon-192.png",
        "chrome_web_badge": "https://ume-messenger-bd3b1.web.app/icons/Icon-192.png",

        "data": {
            "type": "message.created",
            "chat_id": chat_id,
            "sender_user_id": sender_user_id,
        },
    }
      
    

    try:
        result = await asyncio.to_thread(_send_onesignal_request_sync, payload)
        print("OneSignal push sent:", result, flush=True)
    except Exception as e:
        print("OneSignal push error:", repr(e), flush=True)


async def send_push_to_chat_members(
    chat_id: str,
    sender_user_id: str,
    sender_name: str,
    text: Optional[str],
    message_type: str,
):
    if message_type == "file":
        body = "Отправлено вложение"
    else:
        body = text or "Новое сообщение"

    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT DISTINCT cm.user_id
            FROM public.chat_members cm
            WHERE cm.chat_id = $1
              AND cm.user_id <> $2
              AND cm.hidden = false
              AND cm.left_at IS NULL
            """,
            chat_id,
            sender_user_id,
        )

    target_user_ids = [row["user_id"] for row in rows if row["user_id"]]

    await send_onesignal_push_to_users(
        target_user_ids=target_user_ids,
        title=sender_name,
        body=body,
        chat_id=chat_id,
        sender_user_id=sender_user_id,
    )

@app.post("/chats/{chat_id}/messages")
async def send_message(
    chat_id: str,
    data: MessageCreateIn,
    user_id: str = Depends(get_current_user_id),
):
    text = clean_text(data.text)
    attachment_id = clean_text(data.attachment_id)
    reply_to_message_id = clean_text(data.reply_to_message_id)

    if not text and not attachment_id:
        raise HTTPException(status_code=400, detail="Message text or attachment required")

    message_id = make_id()
    current_time = now()
    message_type = "file" if attachment_id else "text"

    async with db_pool.acquire() as conn:
        async with conn.transaction():
            await assert_chat_member(conn, chat_id, user_id)

            attachment = None

            if attachment_id:
                attachment_row = await conn.fetchrow(
                    """
                    SELECT
                        id,
                        owner_user_id,
                        message_id,
                        storage_key,
                        original_name,
                        mime_type,
                        size_bytes,
                        kind
                    FROM public.attachments
                    WHERE id = $1
                      AND owner_user_id = $2
                    """,
                    attachment_id,
                    user_id,
                )

                if not attachment_row:
                    raise HTTPException(status_code=404, detail="Attachment not found")

                if attachment_row["message_id"]:
                    raise HTTPException(status_code=409, detail="Attachment already used")

                attachment = {
                    "id": attachment_row["id"],
                    "url": attachment_url(attachment_row["storage_key"]),
                    "storage_key": attachment_row["storage_key"],
                    "original_name": attachment_row["original_name"],
                    "mime_type": attachment_row["mime_type"],
                    "size_bytes": attachment_row["size_bytes"],
                    "kind": attachment_row["kind"],
                }

            reply_to_message = None

            if reply_to_message_id:
                reply_row = await conn.fetchrow(
                    """
                    SELECT
                        rm.id AS reply_message_id,
                        rm.sender_user_id AS reply_sender_user_id,
                        rm.text AS reply_text,
                        rm.message_type AS reply_message_type,
                        ru.username AS reply_username,
                        ru.nickname AS reply_nickname,
                        ru.display_name AS reply_display_name,
                        ra.id AS reply_attachment_id,
                        ra.storage_key AS reply_attachment_storage_key,
                        ra.original_name AS reply_attachment_original_name,
                        ra.mime_type AS reply_attachment_mime_type,
                        ra.size_bytes AS reply_attachment_size_bytes,
                        ra.kind AS reply_attachment_kind
                    FROM public.messages rm
                    JOIN public.users ru
                      ON ru.id = rm.sender_user_id
                    LEFT JOIN public.attachments ra
                      ON ra.message_id = rm.id
                    WHERE rm.id = $1
                      AND rm.chat_id = $2
                      AND rm.deleted_at IS NULL
                    """,
                    reply_to_message_id,
                    chat_id,
                )

                if not reply_row:
                    raise HTTPException(status_code=404, detail="Reply message not found")

                reply_to_message = format_reply_message(reply_row, user_id)

            await conn.execute(
                """
                INSERT INTO public.messages (
                    id,
                    chat_id,
                    sender_user_id,
                    text,
                    message_type,
                    reply_to_message_id,
                    created_at,
                    edited_at,
                    deleted_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL)
                """,
                message_id,
                chat_id,
                user_id,
                text,
                message_type,
                reply_to_message_id,
                current_time,
            )

            if attachment_id:
                await conn.execute(
                    """
                    UPDATE public.attachments
                    SET message_id = $1
                    WHERE id = $2
                      AND owner_user_id = $3
                    """,
                    message_id,
                    attachment_id,
                    user_id,
                )

            await conn.execute(
                """
                UPDATE public.chats
                SET updated_at = $1
                WHERE id = $2
                """,
                current_time,
                chat_id,
            )

        user = await conn.fetchrow(
            """
            SELECT username, nickname, display_name
            FROM public.users
            WHERE id = $1
            """,
            user_id,
        )

    message_payload = {
        "id": message_id,
        "chat_id": chat_id,
        "sender_user_id": user_id,
        "sender_username": user["username"],
        "sender_name": user["display_name"] or user["nickname"] or user["username"],
        "text": text,
        "message_type": message_type,
        "attachment": attachment,
        "reply_to_message_id": reply_to_message_id,
        "reply_to_message": reply_to_message,
        "reactions": [],
        "created_at": current_time.isoformat(),
        "edited_at": None,
        "delivery_status": "sent",
        "forwarded_from_message_id": None,
        "forwarded_from_user_id": None,
        "forwarded_from_name": None,
        "pinned": False,
    }

    await manager.broadcast_to_chat(
        chat_id,
        {
            "type": "message.created",
            "chat_id": chat_id,
            "message": message_payload,
        },
        exclude_user_id=user_id,
    )

    await send_push_to_chat_members(
        chat_id=chat_id,
        sender_user_id=user_id,
        sender_name=message_payload["sender_name"],
        text=text,
        message_type=message_type,
    )

    return {
        **message_payload,
        "is_mine": True,
    }


@app.post("/messages/{message_id}/edit")
async def edit_message(
    message_id: str,
    data: MessageEditIn,
    user_id: str = Depends(get_current_user_id),
):
    text = clean_text(data.text)

    if not text:
        raise HTTPException(status_code=400, detail="Message text required")

    current_time = now()

    async with db_pool.acquire() as conn:
        message = await conn.fetchrow(
            """
            SELECT id, chat_id, sender_user_id, deleted_at
            FROM public.messages
            WHERE id = $1
            """,
            message_id,
        )

        if not message:
            raise HTTPException(status_code=404, detail="Message not found")

        if message["sender_user_id"] != user_id:
            raise HTTPException(status_code=403, detail="You can edit only your messages")

        if message["deleted_at"] is not None:
            raise HTTPException(status_code=409, detail="Message already deleted")

        await assert_chat_member(conn, message["chat_id"], user_id)

        await conn.execute(
            """
            UPDATE public.messages
            SET text = $1,
                edited_at = $2
            WHERE id = $3
            """,
            text,
            current_time,
            message_id,
        )

        updated = await conn.fetchrow(
            """
            SELECT
                m.id,
                m.chat_id,
                m.sender_user_id,
                m.text,
                m.message_type,
                m.created_at,
                m.edited_at,
                m.reply_to_message_id,

                u.username,
                u.nickname,
                u.display_name,

                a.id AS attachment_id,
                a.storage_key AS attachment_storage_key,
                a.original_name AS attachment_original_name,
                a.mime_type AS attachment_mime_type,
                a.size_bytes AS attachment_size_bytes,
                a.kind AS attachment_kind,

                rm.id AS reply_message_id,
                rm.sender_user_id AS reply_sender_user_id,
                rm.text AS reply_text,
                rm.message_type AS reply_message_type,
                ru.username AS reply_username,
                ru.nickname AS reply_nickname,
                ru.display_name AS reply_display_name,
                ra.id AS reply_attachment_id,
                ra.storage_key AS reply_attachment_storage_key,
                ra.original_name AS reply_attachment_original_name,
                ra.mime_type AS reply_attachment_mime_type,
                ra.size_bytes AS reply_attachment_size_bytes,
                ra.kind AS reply_attachment_kind
            FROM public.messages m
            JOIN public.users u
              ON u.id = m.sender_user_id
            LEFT JOIN public.attachments a
              ON a.message_id = m.id
            LEFT JOIN public.messages rm
              ON rm.id = m.reply_to_message_id
             AND rm.chat_id = m.chat_id
             AND rm.deleted_at IS NULL
            LEFT JOIN public.users ru
              ON ru.id = rm.sender_user_id
            LEFT JOIN public.attachments ra
              ON ra.message_id = rm.id
            WHERE m.id = $1
            """,
            message_id,
        )

    payload = {
        "id": updated["id"],
        "chat_id": updated["chat_id"],
        "sender_user_id": updated["sender_user_id"],
        "sender_username": updated["username"],
        "sender_name": updated["display_name"] or updated["nickname"] or updated["username"],
        "text": updated["text"],
        "message_type": updated["message_type"],
        "attachment": format_attachment(updated),
        "reply_to_message_id": updated["reply_to_message_id"],
        "reply_to_message": format_reply_message(updated, user_id),
        "created_at": updated["created_at"].isoformat() if updated["created_at"] else None,
        "edited_at": updated["edited_at"].isoformat() if updated["edited_at"] else None,
    }

    async with db_pool.acquire() as conn:
        reactions_by_message = await fetch_reactions_for_messages(
            conn,
            [updated["id"]],
            user_id,
        )

    payload["reactions"] = reactions_by_message.get(updated["id"], [])

    await manager.broadcast_to_chat(
        updated["chat_id"],
        {
            "type": "message.updated",
            "chat_id": updated["chat_id"],
            "message": payload,
        },
    )

    return {
        **payload,
        "is_mine": True,
    }


@app.post("/messages/{message_id}/delete")
async def delete_message(
    message_id: str,
    user_id: str = Depends(get_current_user_id),
):
    current_time = now()

    async with db_pool.acquire() as conn:
        message = await conn.fetchrow(
            """
            SELECT id, chat_id, sender_user_id, deleted_at
            FROM public.messages
            WHERE id = $1
            """,
            message_id,
        )

        if not message:
            raise HTTPException(status_code=404, detail="Message not found")

        if message["sender_user_id"] != user_id:
            raise HTTPException(status_code=403, detail="You can delete only your messages")

        if message["deleted_at"] is not None:
            return {"ok": True}

        await assert_chat_member(conn, message["chat_id"], user_id)

        await conn.execute(
            """
            UPDATE public.messages
            SET deleted_at = $1
            WHERE id = $2
            """,
            current_time,
            message_id,
        )

    await manager.broadcast_to_chat(
        message["chat_id"],
        {
            "type": "message.deleted",
            "chat_id": message["chat_id"],
            "message_id": message_id,
        },
    )

    return {"ok": True}


@app.post("/messages/delivered")
async def mark_messages_delivered(
    data: MessageIdsIn,
    user_id: str = Depends(get_current_user_id),
):
    message_ids = [item.strip() for item in data.message_ids if item.strip()]

    if not message_ids:
        return {"ok": True, "message_ids": []}

    current_time = now()

    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT m.id, m.chat_id, m.sender_user_id
            FROM public.messages m
            JOIN public.chat_members cm
              ON cm.chat_id = m.chat_id
             AND cm.user_id = $2
             AND cm.hidden = false
             AND cm.left_at IS NULL
            WHERE m.id = ANY($1::text[])
              AND m.sender_user_id <> $2
              AND m.deleted_at IS NULL
            """,
            message_ids,
            user_id,
        )

        if not rows:
            return {"ok": True, "message_ids": []}

        await conn.executemany(
            """
            INSERT INTO public.message_receipts (
                message_id,
                user_id,
                delivered_at,
                read_at
            )
            VALUES ($1, $2, $3, NULL)
            ON CONFLICT (message_id, user_id)
            DO UPDATE SET
                delivered_at = COALESCE(public.message_receipts.delivered_at, EXCLUDED.delivered_at)
            """,
            [(row["id"], user_id, current_time) for row in rows],
        )

    await broadcast_receipt_updates(rows, "delivered")

    return {
        "ok": True,
        "message_ids": [row["id"] for row in rows],
    }


@app.post("/chats/{chat_id}/messages/read")
async def mark_chat_messages_read(
    chat_id: str,
    user_id: str = Depends(get_current_user_id),
):
    current_time = now()

    async with db_pool.acquire() as conn:
        await assert_chat_member(conn, chat_id, user_id)

        rows = await conn.fetch(
            """
            SELECT id, chat_id, sender_user_id
            FROM public.messages
            WHERE chat_id = $1
              AND sender_user_id <> $2
              AND deleted_at IS NULL
            """,
            chat_id,
            user_id,
        )

        if not rows:
            return {"ok": True, "message_ids": []}

        await conn.executemany(
            """
            INSERT INTO public.message_receipts (
                message_id,
                user_id,
                delivered_at,
                read_at
            )
            VALUES ($1, $2, $3, $3)
            ON CONFLICT (message_id, user_id)
            DO UPDATE SET
                delivered_at = COALESCE(public.message_receipts.delivered_at, EXCLUDED.delivered_at),
                read_at = COALESCE(public.message_receipts.read_at, EXCLUDED.read_at)
            """,
            [(row["id"], user_id, current_time) for row in rows],
        )

    await broadcast_receipt_updates(rows, "read")

    return {
        "ok": True,
        "message_ids": [row["id"] for row in rows],
    }


@app.get("/chats/{chat_id}/pinned-message")
async def get_pinned_message(
    chat_id: str,
    user_id: str = Depends(get_current_user_id),
):
    async with db_pool.acquire() as conn:
        await assert_chat_member(conn, chat_id, user_id)

        pinned_message_id = await conn.fetchval(
            """
            SELECT pinned_message_id
            FROM public.chats
            WHERE id = $1
            """,
            chat_id,
        )

        if not pinned_message_id:
            return {"message": None}

        payload = await fetch_message_payload(conn, pinned_message_id, user_id)

    return {"message": payload}


@app.post("/chats/{chat_id}/pinned-message")
async def set_pinned_message(
    chat_id: str,
    data: PinnedMessageIn,
    user_id: str = Depends(get_current_user_id),
):
    message_id = clean_text(data.message_id)

    async with db_pool.acquire() as conn:
        async with conn.transaction():
            await assert_chat_member(conn, chat_id, user_id)

            if message_id:
                message_exists = await conn.fetchval(
                    """
                    SELECT 1
                    FROM public.messages
                    WHERE id = $1
                      AND chat_id = $2
                      AND deleted_at IS NULL
                    """,
                    message_id,
                    chat_id,
                )

                if not message_exists:
                    raise HTTPException(status_code=404, detail="Message not found")

            await conn.execute(
                """
                UPDATE public.chats
                SET pinned_message_id = $2,
                    updated_at = $3
                WHERE id = $1
                """,
                chat_id,
                message_id,
                now(),
            )

            payload = None

            if message_id:
                payload = await fetch_message_payload(conn, message_id, user_id)

    await manager.broadcast_to_chat(
        chat_id,
        {
            "type": "chat.pinned_message.updated",
            "chat_id": chat_id,
            "message": payload,
        },
    )

    return {"message": payload}


@app.post("/messages/delete-batch")
async def delete_messages_batch(
    data: MessageIdsIn,
    user_id: str = Depends(get_current_user_id),
):
    message_ids = [item.strip() for item in data.message_ids if item.strip()]

    if not message_ids:
        return {"ok": True, "message_ids": []}

    current_time = now()

    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, chat_id
            FROM public.messages
            WHERE id = ANY($1::text[])
              AND sender_user_id = $2
              AND deleted_at IS NULL
            """,
            message_ids,
            user_id,
        )

        if not rows:
            return {"ok": True, "message_ids": []}

        await conn.execute(
            """
            UPDATE public.messages
            SET deleted_at = $3
            WHERE id = ANY($1::text[])
              AND sender_user_id = $2
              AND deleted_at IS NULL
            """,
            [row["id"] for row in rows],
            user_id,
            current_time,
        )

    by_chat: Dict[str, list[str]] = {}

    for row in rows:
        by_chat.setdefault(row["chat_id"], []).append(row["id"])

    for chat_id, ids in by_chat.items():
        await manager.broadcast_to_chat(
            chat_id,
            {
                "type": "messages.deleted",
                "chat_id": chat_id,
                "message_ids": ids,
            },
        )

    return {
        "ok": True,
        "message_ids": [row["id"] for row in rows],
    }


@app.post("/messages/{message_id}/forward")
async def forward_message(
    message_id: str,
    data: ForwardMessageIn,
    user_id: str = Depends(get_current_user_id),
):
    target_chat_id = clean_text(data.target_chat_id)

    if not target_chat_id:
        raise HTTPException(status_code=400, detail="Target chat required")

    new_message_id = make_id()
    current_time = now()

    async with db_pool.acquire() as conn:
        async with conn.transaction():
            original = await conn.fetchrow(
                """
                SELECT
                    m.id,
                    m.chat_id,
                    m.sender_user_id,
                    m.text,
                    m.message_type,
                    m.deleted_at,

                    a.id AS attachment_id,
                    a.storage_key AS attachment_storage_key,
                    a.original_name AS attachment_original_name,
                    a.mime_type AS attachment_mime_type,
                    a.size_bytes AS attachment_size_bytes,
                    a.kind AS attachment_kind,
                    a.file_bytes AS attachment_file_bytes
                FROM public.messages m
                LEFT JOIN public.attachments a
                  ON a.message_id = m.id
                WHERE m.id = $1
                """,
                message_id,
            )

            if not original or original["deleted_at"] is not None:
                raise HTTPException(status_code=404, detail="Message not found")

            await assert_chat_member(conn, original["chat_id"], user_id)
            await assert_chat_member(conn, target_chat_id, user_id)

            await conn.execute(
                """
                INSERT INTO public.messages (
                    id,
                    chat_id,
                    sender_user_id,
                    text,
                    message_type,
                    created_at,
                    edited_at,
                    deleted_at,
                    forwarded_from_message_id,
                    forwarded_from_user_id
                )
                VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, $7, $8)
                """,
                new_message_id,
                target_chat_id,
                user_id,
                original["text"],
                original["message_type"],
                current_time,
                original["id"],
                original["sender_user_id"],
            )

            if original["attachment_id"]:
                original_name = original["attachment_original_name"] or "file"
                mime_type = original["attachment_mime_type"] or "application/octet-stream"
                kind = original["attachment_kind"] or detect_attachment_kind(mime_type)
                content = original["attachment_file_bytes"]

                if content is None and original["attachment_storage_key"]:
                    base_dir = UPLOAD_DIR.resolve()
                    source_path = (UPLOAD_DIR / original["attachment_storage_key"]).resolve()

                    if str(source_path).startswith(str(base_dir)) and source_path.exists() and source_path.is_file():
                        content = source_path.read_bytes()

                if content is None:
                    raise HTTPException(
                        status_code=404,
                        detail="Original attachment is not available",
                    )

                new_attachment_id = make_id()
                new_storage_key = f"{user_id}/{new_attachment_id}_{safe_filename(original_name)}"
                new_file_path = UPLOAD_DIR / new_storage_key
                new_file_path.parent.mkdir(parents=True, exist_ok=True)
                new_file_path.write_bytes(bytes(content))

                await conn.execute(
                    """
                    INSERT INTO public.attachments (
                        id,
                        owner_user_id,
                        message_id,
                        purpose,
                        storage_key,
                        original_name,
                        mime_type,
                        size_bytes,
                        kind,
                        file_bytes,
                        created_at
                    )
                    VALUES ($1, $2, $3, 'message', $4, $5, $6, $7, $8, $9, $10)
                    """,
                    new_attachment_id,
                    user_id,
                    new_message_id,
                    new_storage_key,
                    original_name,
                    mime_type,
                    len(content),
                    kind,
                    content,
                    current_time,
                )

            await conn.execute(
                """
                UPDATE public.chats
                SET updated_at = $1
                WHERE id = $2
                """,
                current_time,
                target_chat_id,
            )

            payload = await fetch_message_payload(conn, new_message_id, user_id)

    if payload is None:
        raise HTTPException(status_code=500, detail="Forwarded message was not created")

    await manager.broadcast_to_chat(
        target_chat_id,
        {
            "type": "message.created",
            "chat_id": target_chat_id,
            "message": payload,
        },
        exclude_user_id=user_id,
    )

    return payload


@app.post("/messages/{message_id}/reaction")
async def set_message_reaction(
    message_id: str,
    data: ReactionIn,
    user_id: str = Depends(get_current_user_id),
):
    reaction_type = data.reaction_type
    emoji = clean_text(data.emoji)
    attachment_id = clean_text(data.attachment_id)
    current_time = now()

    if reaction_type == "emoji":
        if not emoji:
            raise HTTPException(status_code=400, detail="Emoji reaction required")

        attachment_id = None

    if reaction_type == "image":
        if not attachment_id:
            raise HTTPException(status_code=400, detail="Image reaction attachment required")

        emoji = None

    async with db_pool.acquire() as conn:
        message = await conn.fetchrow(
            """
            SELECT id, chat_id, deleted_at
            FROM public.messages
            WHERE id = $1
            """,
            message_id,
        )

        if not message:
            raise HTTPException(status_code=404, detail="Message not found")

        if message["deleted_at"] is not None:
            raise HTTPException(status_code=409, detail="Message deleted")

        await assert_chat_member(conn, message["chat_id"], user_id)

        if reaction_type == "image":
            attachment = await conn.fetchrow(
                """
                SELECT id, owner_user_id, kind, mime_type
                FROM public.attachments
                WHERE id = $1
                  AND owner_user_id = $2
                """,
                attachment_id,
                user_id,
            )

            if not attachment:
                raise HTTPException(status_code=404, detail="Attachment not found")

            if attachment["kind"] != "image" and not attachment["mime_type"].startswith("image/"):
                raise HTTPException(status_code=400, detail="Reaction attachment must be an image")

        reaction_id = make_id()

        await conn.execute(
            """
            INSERT INTO public.message_reactions (
                id,
                message_id,
                user_id,
                reaction_type,
                emoji,
                attachment_id,
                created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (message_id, user_id)
            DO UPDATE SET
                reaction_type = EXCLUDED.reaction_type,
                emoji = EXCLUDED.emoji,
                attachment_id = EXCLUDED.attachment_id,
                created_at = EXCLUDED.created_at
            """,
            reaction_id,
            message_id,
            user_id,
            reaction_type,
            emoji,
            attachment_id,
            current_time,
        )

        reaction_row = await conn.fetchrow(
            """
            SELECT
                r.id AS reaction_id,
                r.message_id AS reaction_message_id,
                r.user_id AS reaction_user_id,
                r.reaction_type,
                r.emoji AS reaction_emoji,
                r.created_at AS reaction_created_at,

                u.username AS reaction_user_username,
                u.nickname AS reaction_user_nickname,
                u.display_name AS reaction_user_display_name,

                a.id AS reaction_attachment_id,
                a.storage_key AS reaction_attachment_storage_key,
                a.original_name AS reaction_attachment_original_name,
                a.mime_type AS reaction_attachment_mime_type,
                a.size_bytes AS reaction_attachment_size_bytes,
                a.kind AS reaction_attachment_kind
            FROM public.message_reactions r
            JOIN public.users u
              ON u.id = r.user_id
            LEFT JOIN public.attachments a
              ON a.id = r.attachment_id
            WHERE r.message_id = $1
              AND r.user_id = $2
            """,
            message_id,
            user_id,
        )

    reaction_payload = format_reaction(reaction_row, user_id)

    await manager.broadcast_to_chat(
        message["chat_id"],
        {
            "type": "reaction.updated",
            "chat_id": message["chat_id"],
            "message_id": message_id,
            "reaction": reaction_payload,
        },
    )

    return reaction_payload


@app.post("/messages/{message_id}/reaction/delete")
@app.delete("/messages/{message_id}/reaction")
async def delete_message_reaction(
    message_id: str,
    user_id: str = Depends(get_current_user_id),
):
    async with db_pool.acquire() as conn:
        message = await conn.fetchrow(
            """
            SELECT id, chat_id, deleted_at
            FROM public.messages
            WHERE id = $1
            """,
            message_id,
        )

        if not message:
            raise HTTPException(status_code=404, detail="Message not found")

        await assert_chat_member(conn, message["chat_id"], user_id)

        await conn.execute(
            """
            DELETE FROM public.message_reactions
            WHERE message_id = $1
              AND user_id = $2
            """,
            message_id,
            user_id,
        )

    await manager.broadcast_to_chat(
        message["chat_id"],
        {
            "type": "reaction.deleted",
            "chat_id": message["chat_id"],
            "message_id": message_id,
            "user_id": user_id,
        },
    )

    return {"ok": True}



@app.get("/chats/{chat_id}/presence")
async def get_chat_presence(
    chat_id: str,
    user_id: str = Depends(get_current_user_id),
):
    await ensure_chat_member(chat_id, user_id)

    async with db_pool.acquire() as conn:
        chat = await conn.fetchrow(
            """
            SELECT id, is_group
            FROM public.chats
            WHERE id = $1
            """,
            chat_id,
        )

        if not chat:
            raise HTTPException(status_code=404, detail="Chat not found")

        if chat["is_group"]:
            return {
                "chat_id": chat_id,
                "is_group": True,
            }

        peer = await conn.fetchrow(
            """
            SELECT
                u.id,
                u.username,
                u.nickname,
                u.display_name,
                u.last_login_at
            FROM public.chat_members cm
            JOIN public.users u
              ON u.id = cm.user_id
            WHERE cm.chat_id = $1
              AND cm.user_id <> $2
              AND cm.hidden = false
              AND cm.left_at IS NULL
            LIMIT 1
            """,
            chat_id,
            user_id,
        )

    if not peer:
        return {
            "chat_id": chat_id,
            "is_group": False,
            "online": False,
            "last_seen_at": None,
        }

    return {
        "chat_id": chat_id,
        "is_group": False,
        "user_id": peer["id"],
        "name": user_display_name(peer),
        "online": manager.is_online(peer["id"]),
        "last_seen_at": peer["last_login_at"].isoformat()
        if peer["last_login_at"]
        else None,
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token")

    if not token:
        await websocket.close(code=1008)
        return

    try:
        user_id = decode_token(token)
    except Exception:
        await websocket.close(code=1008)
        return

    await manager.connect(user_id, websocket)
    last_seen_at = await mark_user_seen(user_id)
    await broadcast_user_presence(user_id, True, last_seen_at)

    try:
        await websocket.send_text(
            json.dumps(
                {
                    "type": "connected",
                    "user_id": user_id,
                }
            )
        )

        while True:
            raw = await websocket.receive_text()

            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                continue

            if event.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
                continue

            if event.get("type") == "chat.activity":
                chat_id = event.get("chat_id")
                activity_type = event.get("activity_type")

                allowed_activity_types = {
                    "idle",
                    "typing",
                    "recording_voice",
                    "sending_audio",
                    "sending_video",
                    "sending_photo",
                }

                if not chat_id or activity_type not in allowed_activity_types:
                    continue

                try:
                    await ensure_chat_member(chat_id, user_id)
                except Exception:
                    continue

                user_name = await get_user_display_name_by_id(user_id)

                await manager.broadcast_to_chat(
                    chat_id,
                    {
                        "type": "chat.activity",
                        "chat_id": chat_id,
                        "user_id": user_id,
                        "user_name": user_name,
                        "activity_type": activity_type,
                        "created_at": now().isoformat(),
                    },
                    exclude_user_id=user_id,
                )

    except WebSocketDisconnect:
        manager.disconnect(user_id, websocket)

        if not manager.is_online(user_id):
            last_seen_at = await mark_user_seen(user_id)
            await broadcast_user_presence(user_id, False, last_seen_at)