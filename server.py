import os
import random
import string
import sqlite3
import aiosqlite
from datetime import datetime, timedelta
from typing import Optional, List
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
import bcrypt as _bcrypt
from pydantic import BaseModel

load_dotenv()

DB_PATH = os.getenv("DB_PATH", "/tmp/rota_croquete.db")
JWT_SECRET = os.getenv("JWT_SECRET", "super_secret_change_in_production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_DAYS = 30

app = FastAPI(title="Rota do Croquete API", debug=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Database setup ────────────────────────────────────────────────────────────

CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    invite_code TEXT UNIQUE NOT NULL,
    owner_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS event_participants (
    event_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY (event_id, user_id)
);
CREATE TABLE IF NOT EXISTS places (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    latitude REAL NOT NULL,
    longitude REAL NOT NULL,
    order_index INTEGER NOT NULL DEFAULT 0,
    added_by TEXT NOT NULL,
    added_by_username TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ratings (
    id TEXT PRIMARY KEY,
    place_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL,
    sabor REAL NOT NULL,
    crocancia REAL NOT NULL,
    recheio REAL NOT NULL,
    qualidade_preco REAL NOT NULL,
    global_score REAL NOT NULL,
    comment TEXT,
    photo_base64 TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(place_id, user_id)
);
"""

async def get_db():
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    try:
        yield db
    finally:
        await db.close()

@app.on_event("startup")
async def startup():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(CREATE_TABLES)
        await db.commit()


# ── Auth helpers ──────────────────────────────────────────────────────────────

oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def _hash(pw: str) -> str:
    return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt()).decode()

def _verify(pw: str, hashed: str) -> bool:
    return _bcrypt.checkpw(pw.encode(), hashed.encode())

def _create_token(user_id: str) -> str:
    exp = datetime.utcnow() + timedelta(days=JWT_EXPIRE_DAYS)
    return jwt.encode({"sub": user_id, "exp": exp}, JWT_SECRET, algorithm=JWT_ALGORITHM)

def _make_invite_code() -> str:
    chars = string.ascii_uppercase + string.digits
    return "CROQ-" + "".join(random.choices(chars, k=6))

async def _current_user(token: str = Depends(oauth2), db=Depends(get_db)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")
    async with db.execute("SELECT * FROM users WHERE id=?", (user_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Utilizador não encontrado")
    return dict(row)

def _row(r) -> dict:
    return dict(r) if r else None

def _rows(rs) -> list:
    return [dict(r) for r in rs]


# ── Models ────────────────────────────────────────────────────────────────────

class RegisterBody(BaseModel):
    username: str
    password: str

class EventCreate(BaseModel):
    name: str

class JoinEvent(BaseModel):
    code: str

class PlaceCreate(BaseModel):
    name: str
    address: str
    latitude: float
    longitude: float
    order_index: Optional[int] = None

class ReorderBody(BaseModel):
    place_ids: List[str]

class RatingCreate(BaseModel):
    sabor: float
    crocancia: float
    recheio: float
    qualidade_preco: float
    comment: Optional[str] = None
    photo_base64: Optional[str] = None


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.get("/api/")
async def root():
    return {"status": "ok", "app": "Rota do Croquete"}

@app.get("/api/debug")
async def debug():
    import sys, traceback
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute("SELECT name FROM sqlite_master WHERE type='table'") as cur:
                tables = [r[0] for r in await cur.fetchall()]
        return {"python": sys.version, "db_path": DB_PATH, "tables": tables, "ok": True}
    except Exception as e:
        return {"error": str(e), "trace": traceback.format_exc(), "python": sys.version, "db_path": DB_PATH}

@app.post("/api/auth/register")
async def register(body: RegisterBody, db=Depends(get_db)):
    if len(body.username.strip()) < 2:
        raise HTTPException(400, "Username muito curto")
    if len(body.password) < 6:
        raise HTTPException(400, "Password muito curta (mínimo 6 caracteres)")
    async with db.execute("SELECT id FROM users WHERE username=?", (body.username,)) as cur:
        if await cur.fetchone():
            raise HTTPException(400, "Username já existe")
    user_id = str(uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        "INSERT INTO users (id, username, hashed_password, created_at) VALUES (?,?,?,?)",
        (user_id, body.username.strip(), _hash(body.password), now),
    )
    await db.commit()
    token = _create_token(user_id)
    return {"access_token": token, "token_type": "bearer",
            "user": {"id": user_id, "username": body.username.strip(), "created_at": now}}

@app.post("/api/auth/login")
async def login(form: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)):
    async with db.execute("SELECT * FROM users WHERE username=?", (form.username,)) as cur:
        row = await cur.fetchone()
    if not row or not _verify(form.password, row["hashed_password"]):
        raise HTTPException(401, "Username ou password incorretos")
    user = dict(row)
    token = _create_token(user["id"])
    return {"access_token": token, "token_type": "bearer",
            "user": {"id": user["id"], "username": user["username"], "created_at": user["created_at"]}}

@app.get("/api/auth/me")
async def me(user=Depends(_current_user)):
    return {"id": user["id"], "username": user["username"], "created_at": user["created_at"]}


# ── Events ────────────────────────────────────────────────────────────────────

async def _build_event(db, event_id: str) -> dict:
    async with db.execute("SELECT * FROM events WHERE id=?", (event_id,)) as cur:
        ev = _row(await cur.fetchone())
    if not ev:
        return None
    async with db.execute(
        "SELECT user_id FROM event_participants WHERE event_id=?", (event_id,)
    ) as cur:
        ev["participants"] = [r["user_id"] for r in await cur.fetchall()]
    return ev

@app.post("/api/events")
async def create_event(body: EventCreate, user=Depends(_current_user), db=Depends(get_db)):
    code = _make_invite_code()
    event_id = str(uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        "INSERT INTO events (id, name, invite_code, owner_id, created_at) VALUES (?,?,?,?,?)",
        (event_id, body.name.strip(), code, user["id"], now),
    )
    await db.execute(
        "INSERT INTO event_participants (event_id, user_id) VALUES (?,?)",
        (event_id, user["id"]),
    )
    await db.commit()
    return await _build_event(db, event_id)

@app.post("/api/events/join")
async def join_event(body: JoinEvent, user=Depends(_current_user), db=Depends(get_db)):
    async with db.execute(
        "SELECT * FROM events WHERE invite_code=?", (body.code.upper(),)
    ) as cur:
        ev = _row(await cur.fetchone())
    if not ev:
        raise HTTPException(404, "Código inválido — rota não encontrada")
    await db.execute(
        "INSERT OR IGNORE INTO event_participants (event_id, user_id) VALUES (?,?)",
        (ev["id"], user["id"]),
    )
    await db.commit()
    return await _build_event(db, ev["id"])

@app.get("/api/events/mine")
async def my_events(user=Depends(_current_user), db=Depends(get_db)):
    async with db.execute(
        "SELECT event_id FROM event_participants WHERE user_id=?", (user["id"],)
    ) as cur:
        ids = [r["event_id"] for r in await cur.fetchall()]
    return [ev for eid in ids if (ev := await _build_event(db, eid))]

@app.get("/api/events/{event_id}")
async def get_event(event_id: str, user=Depends(_current_user), db=Depends(get_db)):
    ev = await _build_event(db, event_id)
    if not ev:
        raise HTTPException(404, "Evento não encontrado")
    if user["id"] not in ev["participants"]:
        raise HTTPException(403, "Sem acesso a este evento")
    return ev

@app.get("/api/events/{event_id}/participants")
async def event_participants(event_id: str, user=Depends(_current_user), db=Depends(get_db)):
    ev = await _build_event(db, event_id)
    if not ev or user["id"] not in ev["participants"]:
        raise HTTPException(403, "Sem acesso")
    result = []
    for uid in ev["participants"]:
        async with db.execute(
            "SELECT id, username, created_at FROM users WHERE id=?", (uid,)
        ) as cur:
            row = await cur.fetchone()
            if row:
                result.append(dict(row))
    return result


# ── Places ────────────────────────────────────────────────────────────────────

async def _check_access(db, event_id: str, user_id: str):
    ev = await _build_event(db, event_id)
    if not ev:
        raise HTTPException(404, "Evento não encontrado")
    if user_id not in ev["participants"]:
        raise HTTPException(403, "Sem acesso a este evento")
    return ev

@app.post("/api/events/{event_id}/places")
async def add_place(event_id: str, body: PlaceCreate, user=Depends(_current_user), db=Depends(get_db)):
    await _check_access(db, event_id, user["id"])
    async with db.execute(
        "SELECT COUNT(*) as c FROM places WHERE event_id=?", (event_id,)
    ) as cur:
        count = (await cur.fetchone())["c"]
    place_id = str(uuid4())
    order_idx = body.order_index if body.order_index is not None else count
    now = datetime.utcnow().isoformat()
    await db.execute(
        "INSERT INTO places (id, event_id, name, address, latitude, longitude, order_index, added_by, added_by_username, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (place_id, event_id, body.name.strip(), body.address.strip(),
         body.latitude, body.longitude, order_idx, user["id"], user["username"], now),
    )
    await db.commit()
    async with db.execute("SELECT * FROM places WHERE id=?", (place_id,)) as cur:
        return _row(await cur.fetchone())

@app.get("/api/events/{event_id}/places")
async def list_places(event_id: str, user=Depends(_current_user), db=Depends(get_db)):
    await _check_access(db, event_id, user["id"])
    async with db.execute(
        "SELECT * FROM places WHERE event_id=? ORDER BY order_index ASC", (event_id,)
    ) as cur:
        return _rows(await cur.fetchall())

@app.delete("/api/events/{event_id}/places/{place_id}")
async def delete_place(event_id: str, place_id: str, user=Depends(_current_user), db=Depends(get_db)):
    await _check_access(db, event_id, user["id"])
    await db.execute("DELETE FROM places WHERE id=? AND event_id=?", (place_id, event_id))
    await db.execute("DELETE FROM ratings WHERE place_id=?", (place_id,))
    await db.commit()
    return {"ok": True}

@app.post("/api/events/{event_id}/places/reorder")
async def reorder_places(event_id: str, body: ReorderBody, user=Depends(_current_user), db=Depends(get_db)):
    await _check_access(db, event_id, user["id"])
    for idx, pid in enumerate(body.place_ids):
        await db.execute(
            "UPDATE places SET order_index=? WHERE id=? AND event_id=?", (idx, pid, event_id)
        )
    await db.commit()
    async with db.execute(
        "SELECT * FROM places WHERE event_id=? ORDER BY order_index ASC", (event_id,)
    ) as cur:
        return _rows(await cur.fetchall())

@app.post("/api/events/{event_id}/places/auto-order")
async def auto_order(event_id: str, user=Depends(_current_user), db=Depends(get_db)):
    await _check_access(db, event_id, user["id"])
    async with db.execute(
        "SELECT * FROM places WHERE event_id=?", (event_id,)
    ) as cur:
        places = _rows(await cur.fetchall())
    if len(places) < 2:
        return places
    ordered = [places[0]]
    remaining = places[1:]
    while remaining:
        last = ordered[-1]
        nearest = min(
            remaining,
            key=lambda p: (p["latitude"] - last["latitude"]) ** 2
            + (p["longitude"] - last["longitude"]) ** 2,
        )
        ordered.append(nearest)
        remaining.remove(nearest)
    for idx, place in enumerate(ordered):
        await db.execute(
            "UPDATE places SET order_index=? WHERE id=?", (idx, place["id"])
        )
    await db.commit()
    async with db.execute(
        "SELECT * FROM places WHERE event_id=? ORDER BY order_index ASC", (event_id,)
    ) as cur:
        return _rows(await cur.fetchall())

@app.get("/api/places/{place_id}")
async def get_place(place_id: str, user=Depends(_current_user), db=Depends(get_db)):
    async with db.execute("SELECT * FROM places WHERE id=?", (place_id,)) as cur:
        place = _row(await cur.fetchone())
    if not place:
        raise HTTPException(404, "Local não encontrado")
    await _check_access(db, place["event_id"], user["id"])
    return place


# ── Ratings ───────────────────────────────────────────────────────────────────

def _global_score(sabor, crocancia, recheio, qp) -> float:
    return round((sabor + crocancia + recheio + qp) / 4, 2)

@app.post("/api/places/{place_id}/ratings")
async def upsert_rating(place_id: str, body: RatingCreate, user=Depends(_current_user), db=Depends(get_db)):
    async with db.execute("SELECT * FROM places WHERE id=?", (place_id,)) as cur:
        place = _row(await cur.fetchone())
    if not place:
        raise HTTPException(404, "Local não encontrado")
    await _check_access(db, place["event_id"], user["id"])
    for v in [body.sabor, body.crocancia, body.recheio, body.qualidade_preco]:
        if not (1 <= v <= 5):
            raise HTTPException(400, "Avaliações devem ser entre 1 e 5")
    gs = _global_score(body.sabor, body.crocancia, body.recheio, body.qualidade_preco)
    rating_id = str(uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        """INSERT INTO ratings (id, place_id, user_id, username, sabor, crocancia, recheio, qualidade_preco, global_score, comment, photo_base64, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(place_id, user_id) DO UPDATE SET
             id=excluded.id, sabor=excluded.sabor, crocancia=excluded.crocancia,
             recheio=excluded.recheio, qualidade_preco=excluded.qualidade_preco,
             global_score=excluded.global_score, comment=excluded.comment,
             photo_base64=excluded.photo_base64, created_at=excluded.created_at""",
        (rating_id, place_id, user["id"], user["username"],
         body.sabor, body.crocancia, body.recheio, body.qualidade_preco,
         gs, body.comment, body.photo_base64, now),
    )
    await db.commit()
    async with db.execute(
        "SELECT * FROM ratings WHERE place_id=? AND user_id=?", (place_id, user["id"])
    ) as cur:
        return _row(await cur.fetchone())

@app.get("/api/places/{place_id}/ratings")
async def list_ratings(place_id: str, user=Depends(_current_user), db=Depends(get_db)):
    async with db.execute("SELECT * FROM places WHERE id=?", (place_id,)) as cur:
        place = _row(await cur.fetchone())
    if not place:
        raise HTTPException(404, "Local não encontrado")
    await _check_access(db, place["event_id"], user["id"])
    async with db.execute(
        "SELECT id, place_id, user_id, username, sabor, crocancia, recheio, qualidade_preco, global_score, comment, created_at FROM ratings WHERE place_id=?",
        (place_id,),
    ) as cur:
        return _rows(await cur.fetchall())

@app.get("/api/places/{place_id}/my-rating")
async def my_rating(place_id: str, user=Depends(_current_user), db=Depends(get_db)):
    async with db.execute(
        "SELECT * FROM ratings WHERE place_id=? AND user_id=?", (place_id, user["id"])
    ) as cur:
        row = await cur.fetchone()
    return _row(row) or {}


# ── Ranking ───────────────────────────────────────────────────────────────────

@app.get("/api/events/{event_id}/ranking")
async def ranking(event_id: str, user=Depends(_current_user), db=Depends(get_db)):
    await _check_access(db, event_id, user["id"])
    async with db.execute(
        "SELECT * FROM places WHERE event_id=? ORDER BY order_index ASC", (event_id,)
    ) as cur:
        places = _rows(await cur.fetchall())
    result = []
    for p in places:
        async with db.execute(
            "SELECT sabor, crocancia, recheio, qualidade_preco, global_score FROM ratings WHERE place_id=?",
            (p["id"],),
        ) as cur:
            ratings = _rows(await cur.fetchall())
        n = len(ratings)
        if n == 0:
            result.append({"place_id": p["id"], "name": p["name"], "address": p["address"],
                           "ratings_count": 0, "sabor": 0, "crocancia": 0,
                           "recheio": 0, "qualidade_preco": 0, "global_score": 0})
        else:
            result.append({
                "place_id": p["id"], "name": p["name"], "address": p["address"],
                "ratings_count": n,
                "sabor": round(sum(r["sabor"] for r in ratings) / n, 2),
                "crocancia": round(sum(r["crocancia"] for r in ratings) / n, 2),
                "recheio": round(sum(r["recheio"] for r in ratings) / n, 2),
                "qualidade_preco": round(sum(r["qualidade_preco"] for r in ratings) / n, 2),
                "global_score": round(sum(r["global_score"] for r in ratings) / n, 2),
            })
    result.sort(key=lambda x: x["global_score"], reverse=True)
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8001, reload=True)
