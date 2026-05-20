import os
import random
import string
from datetime import datetime, timedelta
from typing import Optional, List
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
import bcrypt as _bcrypt
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel

load_dotenv()

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "rota_croquete")
JWT_SECRET = os.getenv("JWT_SECRET", "super_secret_change_in_production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_DAYS = 30

app = FastAPI(title="Rota do Croquete API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client: AsyncIOMotorClient = None
db = None

@app.on_event("startup")
async def startup():
    global client, db
    client = AsyncIOMotorClient(MONGO_URL)
    db = client[DB_NAME]
    await db.users.create_index("username", unique=True)
    await db.events.create_index("invite_code", unique=True)
    await db.ratings.create_index([("place_id", 1), ("user_id", 1)], unique=True)
    await db.places.create_index([("event_id", 1), ("order_index", 1)])

@app.on_event("shutdown")
async def shutdown():
    client.close()

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

async def _current_user(token: str = Depends(oauth2)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="Utilizador não encontrado")
    return user


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

@app.post("/api/auth/register")
async def register(body: RegisterBody):
    if len(body.username.strip()) < 2:
        raise HTTPException(400, "Username muito curto")
    if len(body.password) < 6:
        raise HTTPException(400, "Password muito curta (mínimo 6 caracteres)")
    existing = await db.users.find_one({"username": body.username})
    if existing:
        raise HTTPException(400, "Username já existe")
    user = {
        "id": str(uuid4()),
        "username": body.username.strip(),
        "hashed_password": _hash(body.password),
        "created_at": datetime.utcnow().isoformat(),
    }
    await db.users.insert_one(user)
    token = _create_token(user["id"])
    return {"access_token": token, "token_type": "bearer",
            "user": {"id": user["id"], "username": user["username"], "created_at": user["created_at"]}}

@app.post("/api/auth/login")
async def login(form: OAuth2PasswordRequestForm = Depends()):
    user = await db.users.find_one({"username": form.username}, {"_id": 0})
    if not user or not _verify(form.password, user["hashed_password"]):
        raise HTTPException(401, "Username ou password incorretos")
    token = _create_token(user["id"])
    return {"access_token": token, "token_type": "bearer",
            "user": {"id": user["id"], "username": user["username"], "created_at": user["created_at"]}}

@app.get("/api/auth/me")
async def me(user=Depends(_current_user)):
    return {"id": user["id"], "username": user["username"], "created_at": user["created_at"]}


# ── Events ────────────────────────────────────────────────────────────────────

@app.post("/api/events")
async def create_event(body: EventCreate, user=Depends(_current_user)):
    code = _make_invite_code()
    event = {
        "id": str(uuid4()),
        "name": body.name.strip(),
        "invite_code": code,
        "owner_id": user["id"],
        "participants": [user["id"]],
        "created_at": datetime.utcnow().isoformat(),
    }
    await db.events.insert_one(event)
    return {k: v for k, v in event.items() if k != "_id"}

@app.post("/api/events/join")
async def join_event(body: JoinEvent, user=Depends(_current_user)):
    event = await db.events.find_one({"invite_code": body.code.upper()}, {"_id": 0})
    if not event:
        raise HTTPException(404, "Código inválido — rota não encontrada")
    await db.events.update_one({"id": event["id"]}, {"$addToSet": {"participants": user["id"]}})
    updated = await db.events.find_one({"id": event["id"]}, {"_id": 0})
    return updated

@app.get("/api/events/mine")
async def my_events(user=Depends(_current_user)):
    cursor = db.events.find({"participants": user["id"]}, {"_id": 0})
    return await cursor.to_list(length=100)

@app.get("/api/events/{event_id}")
async def get_event(event_id: str, user=Depends(_current_user)):
    event = await db.events.find_one({"id": event_id}, {"_id": 0})
    if not event:
        raise HTTPException(404, "Evento não encontrado")
    if user["id"] not in event.get("participants", []):
        raise HTTPException(403, "Sem acesso a este evento")
    return event

@app.get("/api/events/{event_id}/participants")
async def event_participants(event_id: str, user=Depends(_current_user)):
    event = await db.events.find_one({"id": event_id}, {"_id": 0})
    if not event or user["id"] not in event.get("participants", []):
        raise HTTPException(403, "Sem acesso")
    users = []
    for uid in event.get("participants", []):
        u = await db.users.find_one({"id": uid}, {"_id": 0, "hashed_password": 0})
        if u:
            users.append(u)
    return users


# ── Places ────────────────────────────────────────────────────────────────────

async def _check_access(event_id: str, user_id: str):
    event = await db.events.find_one({"id": event_id}, {"_id": 0})
    if not event:
        raise HTTPException(404, "Evento não encontrado")
    if user_id not in event.get("participants", []):
        raise HTTPException(403, "Sem acesso a este evento")
    return event

@app.post("/api/events/{event_id}/places")
async def add_place(event_id: str, body: PlaceCreate, user=Depends(_current_user)):
    await _check_access(event_id, user["id"])
    count = await db.places.count_documents({"event_id": event_id})
    place = {
        "id": str(uuid4()),
        "event_id": event_id,
        "name": body.name.strip(),
        "address": body.address.strip(),
        "latitude": body.latitude,
        "longitude": body.longitude,
        "order_index": body.order_index if body.order_index is not None else count,
        "added_by": user["id"],
        "added_by_username": user["username"],
        "created_at": datetime.utcnow().isoformat(),
    }
    await db.places.insert_one(place)
    return {k: v for k, v in place.items() if k != "_id"}

@app.get("/api/events/{event_id}/places")
async def list_places(event_id: str, user=Depends(_current_user)):
    await _check_access(event_id, user["id"])
    cursor = db.places.find({"event_id": event_id}, {"_id": 0}).sort("order_index", 1)
    return await cursor.to_list(length=200)

@app.delete("/api/events/{event_id}/places/{place_id}")
async def delete_place(event_id: str, place_id: str, user=Depends(_current_user)):
    await _check_access(event_id, user["id"])
    await db.places.delete_one({"id": place_id, "event_id": event_id})
    await db.ratings.delete_many({"place_id": place_id})
    return {"ok": True}

@app.post("/api/events/{event_id}/places/reorder")
async def reorder_places(event_id: str, body: ReorderBody, user=Depends(_current_user)):
    await _check_access(event_id, user["id"])
    for idx, pid in enumerate(body.place_ids):
        await db.places.update_one({"id": pid, "event_id": event_id}, {"$set": {"order_index": idx}})
    cursor = db.places.find({"event_id": event_id}, {"_id": 0}).sort("order_index", 1)
    return await cursor.to_list(length=200)

@app.post("/api/events/{event_id}/places/auto-order")
async def auto_order(event_id: str, user=Depends(_current_user)):
    await _check_access(event_id, user["id"])
    places = await db.places.find({"event_id": event_id}, {"_id": 0}).to_list(length=200)
    if len(places) < 2:
        return places
    ordered = [places[0]]
    remaining = places[1:]
    while remaining:
        last = ordered[-1]
        nearest = min(remaining, key=lambda p: (p["latitude"] - last["latitude"]) ** 2 + (p["longitude"] - last["longitude"]) ** 2)
        ordered.append(nearest)
        remaining.remove(nearest)
    for idx, place in enumerate(ordered):
        await db.places.update_one({"id": place["id"]}, {"$set": {"order_index": idx}})
    return await db.places.find({"event_id": event_id}, {"_id": 0}).sort("order_index", 1).to_list(length=200)

@app.get("/api/places/{place_id}")
async def get_place(place_id: str, user=Depends(_current_user)):
    place = await db.places.find_one({"id": place_id}, {"_id": 0})
    if not place:
        raise HTTPException(404, "Local não encontrado")
    await _check_access(place["event_id"], user["id"])
    return place


# ── Ratings ───────────────────────────────────────────────────────────────────

def _global_score(sabor, crocancia, recheio, qp) -> float:
    return round((sabor + crocancia + recheio + qp) / 4, 2)

@app.post("/api/places/{place_id}/ratings")
async def upsert_rating(place_id: str, body: RatingCreate, user=Depends(_current_user)):
    place = await db.places.find_one({"id": place_id}, {"_id": 0})
    if not place:
        raise HTTPException(404, "Local não encontrado")
    await _check_access(place["event_id"], user["id"])
    for v in [body.sabor, body.crocancia, body.recheio, body.qualidade_preco]:
        if not (1 <= v <= 5):
            raise HTTPException(400, "Avaliações devem ser entre 1 e 5")
    gs = _global_score(body.sabor, body.crocancia, body.recheio, body.qualidade_preco)
    rating = {
        "id": str(uuid4()),
        "place_id": place_id,
        "user_id": user["id"],
        "username": user["username"],
        "sabor": body.sabor,
        "crocancia": body.crocancia,
        "recheio": body.recheio,
        "qualidade_preco": body.qualidade_preco,
        "global_score": gs,
        "comment": body.comment,
        "photo_base64": body.photo_base64,
        "created_at": datetime.utcnow().isoformat(),
    }
    await db.ratings.update_one(
        {"place_id": place_id, "user_id": user["id"]},
        {"$set": rating},
        upsert=True,
    )
    saved = await db.ratings.find_one({"place_id": place_id, "user_id": user["id"]}, {"_id": 0})
    return saved

@app.get("/api/places/{place_id}/ratings")
async def list_ratings(place_id: str, user=Depends(_current_user)):
    place = await db.places.find_one({"id": place_id}, {"_id": 0})
    if not place:
        raise HTTPException(404, "Local não encontrado")
    await _check_access(place["event_id"], user["id"])
    cursor = db.ratings.find({"place_id": place_id}, {"_id": 0})
    return await cursor.to_list(length=100)

@app.get("/api/places/{place_id}/my-rating")
async def my_rating(place_id: str, user=Depends(_current_user)):
    rating = await db.ratings.find_one({"place_id": place_id, "user_id": user["id"]}, {"_id": 0})
    return rating or {}


# ── Ranking ───────────────────────────────────────────────────────────────────

@app.get("/api/events/{event_id}/ranking")
async def ranking(event_id: str, user=Depends(_current_user)):
    await _check_access(event_id, user["id"])
    places = await db.places.find({"event_id": event_id}, {"_id": 0}).sort("order_index", 1).to_list(200)
    result = []
    for p in places:
        ratings = await db.ratings.find({"place_id": p["id"]}, {"_id": 0, "photo_base64": 0}).to_list(100)
        n = len(ratings)
        if n == 0:
            result.append({"place_id": p["id"], "name": p["name"], "address": p.get("address", ""),
                           "ratings_count": 0, "sabor": 0, "crocancia": 0, "recheio": 0, "qualidade_preco": 0, "global_score": 0})
        else:
            result.append({
                "place_id": p["id"], "name": p["name"], "address": p.get("address", ""),
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
