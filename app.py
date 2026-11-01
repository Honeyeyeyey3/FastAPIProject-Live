import hashlib
import os
import re
import secrets
import logging
import uvicorn
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Header
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

# Import models
from models import Base, FileRecord, User, UserSession

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Database setup (SQLite, portable path relative to this file)
DATABASE_PATH = os.getenv("DATABASE_PATH", os.path.join(BASE_DIR, "files.db"))
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Where uploaded file bytes actually live on disk, named by their hash
STORAGE_DIR = os.getenv("STORAGE_DIR", os.path.join(BASE_DIR, "storage"))
os.makedirs(STORAGE_DIR, exist_ok=True)

# Auto-create tables (adds any missing tables; does NOT alter existing ones)
Base.metadata.create_all(bind=engine)

# In-memory ledger mirror (for fast reads) — full public ledger, everyone's files
ledger = []

# Logging
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

# How long a login session stays valid
SESSION_TTL_DAYS = 30

# Largest file a visitor may upload (MB). Keeps the public server from filling up.
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "10"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024

MOBILE_RE = re.compile(r"^[0-9]{7,15}$")


def block_dict(r: FileRecord) -> dict:
    return {
        "id": r.id,
        "filename": r.filename,
        "hash": r.filehash,
        "filesize": r.filesize,
        "content_type": r.content_type,
        "timestamp": r.timestamp.isoformat() if r.timestamp else None,
    }


def rebuild_ledger_from_db():
    """Resync the in-memory ledger mirror with what's actually in the DB."""
    db = SessionLocal()
    try:
        rows = db.query(FileRecord).order_by(FileRecord.id.asc()).all()
        ledger.clear()
        for r in rows:
            ledger.append(block_dict(r))
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Populate in-memory ledger from database on startup."""
    try:
        rebuild_ledger_from_db()
        logger.info("Loaded %d ledger entries from DB", len(ledger))
    except Exception:
        logger.exception("Failed loading ledger from DB on startup")
    yield


app = FastAPI(title="Secure File Sharing Blockchain", lifespan=lifespan)

# Allow CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Optional whole-API key auth (unchanged from before — separate from user accounts)
# ---------------------------------------------------------------------------
security = HTTPBearer(auto_error=False)


def require_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    require = os.getenv("REQUIRE_AUTH", "0")
    if require.lower() in ("1", "true", "yes"):
        api_key = os.getenv("API_KEY")
        if not api_key:
            raise HTTPException(status_code=500, detail="API_KEY not configured")
        if not credentials or credentials.scheme.lower() != "bearer" or credentials.credentials != api_key:
            raise HTTPException(status_code=401, detail="Unauthorized")
    return True


def calculate_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def storage_path(filehash: str) -> str:
    return os.path.join(STORAGE_DIR, filehash)


def delete_stored_bytes_if_orphaned(db, filehash: str, keep_id: int):
    """Remove the file bytes on disk only if no other DB row still references this hash."""
    other = db.query(FileRecord).filter(FileRecord.filehash == filehash, FileRecord.id != keep_id).first()
    if not other:
        path = storage_path(filehash)
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                logger.warning("Could not remove orphaned file bytes for %s", filehash)


# ---------------------------------------------------------------------------
# Password hashing (PBKDF2-SHA256, stdlib only — no plaintext password is ever stored)
# ---------------------------------------------------------------------------
PBKDF2_ITERATIONS = 200_000


def hash_password(password: str, salt_hex: str = None):
    if salt_hex is None:
        salt_hex = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), PBKDF2_ITERATIONS)
    return dk.hex(), salt_hex


def verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), PBKDF2_ITERATIONS)
    return secrets.compare_digest(dk.hex(), expected_hash_hex)


# ---------------------------------------------------------------------------
# Sessions (opaque bearer tokens, stored in DB so they survive a restart)
# ---------------------------------------------------------------------------
def create_session(db, user_id: int) -> str:
    token = secrets.token_hex(32)
    expires = datetime.utcnow() + timedelta(days=SESSION_TTL_DAYS)
    db.add(UserSession(token=token, user_id=user_id, expires_at=expires))
    db.commit()
    return token


def get_current_user(authorization: str):
    """Returns the logged-in User for a valid 'Bearer <token>' header, else None. Never raises."""
    if not authorization:
        return None
    token = authorization.replace("Bearer ", "").strip()
    if not token:
        return None
    db = SessionLocal()
    try:
        sess = db.query(UserSession).filter(UserSession.token == token).first()
        if not sess:
            return None
        if sess.expires_at < datetime.utcnow():
            db.delete(sess)
            db.commit()
            return None
        return db.query(User).filter(User.id == sess.user_id).first()
    finally:
        db.close()


def get_current_user_dep(authorization: str = Header(default=None)):
    return get_current_user(authorization)


def require_login(user=Depends(get_current_user_dep)):
    if not user:
        raise HTTPException(status_code=401, detail="Please log in first")
    return user


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------
class RegisterPayload(BaseModel):
    mobile: str
    password: str


class LoginPayload(BaseModel):
    mobile: str
    password: str


class ResetPayload(BaseModel):
    password: str


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------
@app.post("/auth/register")
def register(payload: RegisterPayload):
    mobile = payload.mobile.strip()
    password = payload.password

    if not MOBILE_RE.match(mobile):
        raise HTTPException(status_code=400, detail="Enter a valid mobile number (digits only)")
    if len(password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.mobile == mobile).first()
        if existing:
            raise HTTPException(status_code=400, detail="An account with this mobile number already exists")
        pw_hash, salt = hash_password(password)
        user = User(mobile=mobile, password_hash=pw_hash, password_salt=salt)
        db.add(user)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(status_code=400, detail="An account with this mobile number already exists")
        db.refresh(user)
        token = create_session(db, user.id)
        return {"token": token, "mobile": user.mobile}
    finally:
        db.close()


@app.post("/auth/login")
def login(payload: LoginPayload):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.mobile == payload.mobile.strip()).first()
        if not user or not verify_password(payload.password, user.password_salt, user.password_hash):
            raise HTTPException(status_code=401, detail="Incorrect mobile number or password")
        token = create_session(db, user.id)
        return {"token": token, "mobile": user.mobile}
    finally:
        db.close()


@app.post("/auth/logout")
def logout(authorization: str = Header(default=None)):
    if authorization:
        token = authorization.replace("Bearer ", "").strip()
        if token:
            db = SessionLocal()
            try:
                sess = db.query(UserSession).filter(UserSession.token == token).first()
                if sess:
                    db.delete(sess)
                    db.commit()
            finally:
                db.close()
    return {"status": "logged out"}


@app.get("/auth/me")
def me(user=Depends(require_login)):
    db = SessionLocal()
    try:
        count = db.query(FileRecord).filter(FileRecord.owner_id == user.id).count()
    finally:
        db.close()
    return {"mobile": user.mobile, "created_at": user.created_at.isoformat() if user.created_at else None, "file_count": count}


@app.get("/my-files/")
def my_files(user=Depends(require_login)):
    db = SessionLocal()
    try:
        rows = db.query(FileRecord).filter(FileRecord.owner_id == user.id).order_by(FileRecord.id.asc()).all()
        return {"ledger": [block_dict(r) for r in rows]}
    finally:
        db.close()


@app.post("/auth/reset")
def reset_account(payload: ResetPayload, user=Depends(require_login)):
    """Wipes every file this account has sealed. The login (mobile + password) is untouched —
    this is meant to let someone start over on the same account, not delete the account itself."""
    db = SessionLocal()
    try:
        fresh_user = db.query(User).filter(User.id == user.id).first()
        if not fresh_user or not verify_password(payload.password, fresh_user.password_salt, fresh_user.password_hash):
            raise HTTPException(status_code=401, detail="Incorrect password")

        files = db.query(FileRecord).filter(FileRecord.owner_id == user.id).all()
        for f in files:
            delete_stored_bytes_if_orphaned(db, f.filehash, f.id)
            db.delete(f)
        db.commit()
    finally:
        db.close()

    rebuild_ledger_from_db()
    return {"status": "reset", "message": "Your files are cleared. Your mobile number and password still work the same."}


# ---------------------------------------------------------------------------
# File endpoints
# ---------------------------------------------------------------------------
@app.post("/upload/")
async def upload_file(file: UploadFile = File(...), authorization: str = Header(default=None), _auth=Depends(require_api_key)):
    """Upload a file, hash it, persist the bytes, and record it on the ledger.
    If a valid session token is sent, the file is tied to that account."""
    # Read at most one byte past the limit, so oversized files are refused without loading them fully
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File too large — the limit is {MAX_UPLOAD_MB} MB")
    file_hash = calculate_hash(content)
    current_user = get_current_user(authorization)

    db = SessionLocal()
    try:
        existing = db.query(FileRecord).filter(FileRecord.filehash == file_hash).first()
        if existing:
            raise HTTPException(status_code=400, detail="File already exists in blockchain")

        record = FileRecord(
            filename=file.filename,
            filehash=file_hash,
            filesize=len(content),
            content_type=file.content_type or "application/octet-stream",
            owner_id=current_user.id if current_user else None,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="File already exists (db constraint)")
    finally:
        db.close()

    # Persist bytes to disk only after the DB row is safely committed
    with open(storage_path(file_hash), "wb") as f:
        f.write(content)

    block = block_dict(record)
    ledger.append(block)
    return JSONResponse({"status": "success", "block": block, "owner": bool(current_user)})


@app.get("/verify/{filehash}")
def verify_file(filehash: str, _auth=Depends(require_api_key)):
    db = SessionLocal()
    try:
        record = db.query(FileRecord).filter(FileRecord.filehash == filehash).first()
        if record:
            return {
                "verified": True,
                "filename": record.filename,
                "filesize": record.filesize,
                "content_type": record.content_type,
                "timestamp": record.timestamp.isoformat(),
            }
        return {"verified": False}
    finally:
        db.close()


@app.get("/download/{filehash}")
def download_file(filehash: str, _auth=Depends(require_api_key)):
    db = SessionLocal()
    try:
        record = db.query(FileRecord).filter(FileRecord.filehash == filehash).first()
    finally:
        db.close()

    if not record:
        raise HTTPException(status_code=404, detail="No record for this hash")

    path = storage_path(filehash)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Record exists but file bytes are missing on disk")

    return FileResponse(
        path,
        media_type=record.content_type or "application/octet-stream",
        filename=record.filename,
    )


@app.get("/api")
def api_info():
    return {"message": "Welcome to Secure File Sharing Blockchain API"}


# Serve the frontend last so it doesn't shadow the API routes above
app.mount("/", StaticFiles(directory=os.path.join(BASE_DIR, "static"), html=True), name="frontend")

if __name__ == "__main__":
    # Hosting platforms set PORT; locally we keep 127.0.0.1:8000 with auto-reload
    on_server = "PORT" in os.environ
    uvicorn.run(
        "app:app",
        host="0.0.0.0" if on_server else "127.0.0.1",
        port=int(os.getenv("PORT", "8000")),
        reload=not on_server,
    )
