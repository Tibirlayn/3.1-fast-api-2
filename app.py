import os
import hashlib
import hmac
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, model_validator


DATABASE = Path(os.getenv('DATABASE_PATH', Path(__file__).with_name('ads.db')))
TOKEN_TTL = 48 * 60 * 60


def hash_password(password):
    salt = secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1)
    return f'{salt}:{digest.hex()}'


def verify_password(password, stored):
    salt, digest = stored.split(':')
    actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1)
    return hmac.compare_digest(actual.hex(), digest)


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


@asynccontextmanager
async def lifespan(app):
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATABASE)
    try:
        db.execute('PRAGMA foreign_keys = ON')
        db.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                "group" TEXT NOT NULL CHECK ("group" IN ('user', 'admin'))
            );
            CREATE TABLE IF NOT EXISTS tokens (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at REAL NOT NULL
            );
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS advertisements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price REAL NOT NULL CHECK (price >= 0),
                author INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL
            )
        ''')
        username = os.getenv('ADMIN_USERNAME')
        password = os.getenv('ADMIN_PASSWORD')
        if username and password:
            existing = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
            if existing is None:
                db.execute(
                    'INSERT INTO users (username, password_hash, "group") VALUES (?, ?, ?)',
                    (username, hash_password(password), 'admin'),
                )
        db.commit()
    finally:
        db.close()
    yield


app = FastAPI(lifespan=lifespan)


def get_db():
    db = sqlite3.connect(DATABASE, check_same_thread=False)
    db.execute('PRAGMA foreign_keys = ON')
    db.row_factory = sqlite3.Row
    try:
        yield db
    finally:
        db.close()


Db = Annotated[sqlite3.Connection, Depends(get_db)]
Text = Annotated[str, Field(min_length=1)]
Price = Annotated[float, Field(ge=0, allow_inf_nan=False)]
Password = Annotated[str, Field(min_length=1, max_length=1024)]
bearer = HTTPBearer(auto_error=False)


def optional_user(
    db: Db,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
):
    if credentials is None:
        return None
    user = db.execute(
        '''SELECT users.* FROM users JOIN tokens ON users.id = tokens.user_id
           WHERE tokens.token_hash = ? AND tokens.expires_at > ?''',
        (token_hash(credentials.credentials), time.time()),
    ).fetchone()
    if user is None:
        raise HTTPException(401, 'Неверный или просроченный токен', headers={'WWW-Authenticate': 'Bearer'})
    return dict(user)


def current_user(user: Annotated[dict | None, Depends(optional_user)]):
    if user is None:
        raise HTTPException(401, 'Нужен токен', headers={'WWW-Authenticate': 'Bearer'})
    return user


CurrentUser = Annotated[dict, Depends(current_user)]


def check_owner(user, owner_id):
    if user['group'] != 'admin' and user['id'] != owner_id:
        raise HTTPException(403, 'Недостаточно прав')


class Login(BaseModel):
    model_config = ConfigDict(extra='forbid')
    username: Text
    password: Password


class UserCreate(Login):
    group: Literal['user', 'admin'] = 'user'


class UserPublic(BaseModel):
    id: int
    username: str
    group: Literal['user', 'admin']


class PartialUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')

    @model_validator(mode='after')
    def check_fields(self):
        if not self.model_fields_set:
            raise ValueError('Нужно передать хотя бы одно поле')
        if any(getattr(self, field) is None for field in self.model_fields_set):
            raise ValueError('Поля не могут быть null')
        return self


class UserUpdate(PartialUpdate):
    username: Text | None = None
    password: Password | None = None
    group: Literal['user', 'admin'] | None = None


def find_user(db, user_id):
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user is None:
        raise HTTPException(404, 'Пользователь не найден')
    return dict(user)


@app.post('/login')
def login(data: Login, db: Db):
    user = db.execute('SELECT * FROM users WHERE username = ?', (data.username,)).fetchone()
    if user is None or not verify_password(data.password, user['password_hash']):
        raise HTTPException(401, 'Неверное имя пользователя или пароль')
    token = secrets.token_urlsafe(32)
    db.execute('INSERT INTO tokens VALUES (?, ?, ?)',
               (token_hash(token), user['id'], time.time() + TOKEN_TTL))
    db.commit()
    return {'token': token, 'token_type': 'bearer', 'expires_in': TOKEN_TTL}


@app.post('/user', response_model=UserPublic, status_code=201)
def create_user(data: UserCreate, db: Db, user: Annotated[dict | None, Depends(optional_user)]):
    if data.group == 'admin' and (user is None or user['group'] != 'admin'):
        raise HTTPException(403, 'Только администратор может назначать группу admin')
    try:
        cursor = db.execute(
            'INSERT INTO users (username, password_hash, "group") VALUES (?, ?, ?)',
            (data.username, hash_password(data.password), data.group),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        raise HTTPException(409, 'Имя пользователя уже занято')
    return find_user(db, cursor.lastrowid)


@app.get('/user', response_model=list[UserPublic])
def list_users(db: Db, user: CurrentUser):
    if user['group'] != 'admin':
        raise HTTPException(403, 'Недостаточно прав')
    return [dict(row) for row in db.execute('SELECT * FROM users ORDER BY id')]


@app.get('/user/{user_id}', response_model=UserPublic)
def get_user(user_id: int, db: Db):
    return find_user(db, user_id)


@app.patch('/user/{user_id}', response_model=UserPublic)
def update_user(user_id: int, data: UserUpdate, db: Db, user: CurrentUser):
    target = find_user(db, user_id)
    check_owner(user, user_id)
    updates = data.model_dump(exclude_unset=True)
    if 'group' in updates and user['group'] != 'admin' and updates['group'] != target['group']:
        raise HTTPException(403, 'Только администратор может менять группу')
    if 'password' in updates:
        updates['password_hash'] = hash_password(updates.pop('password'))
    fields = ', '.join(f'"{field}" = ?' for field in updates)
    try:
        db.execute(f'UPDATE users SET {fields} WHERE id = ?', [*updates.values(), user_id])
        if 'password_hash' in updates:
            db.execute('DELETE FROM tokens WHERE user_id = ?', (user_id,))
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        raise HTTPException(409, 'Имя пользователя уже занято')
    return find_user(db, user_id)


@app.delete('/user/{user_id}', status_code=204)
def delete_user(user_id: int, db: Db, user: CurrentUser):
    find_user(db, user_id)
    check_owner(user, user_id)
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    return Response(status_code=204)


class AdvertisementCreate(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)

    title: Text
    description: Text
    price: Price
    author: Annotated[int, Field(gt=0)] | None = None


class AdvertisementUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)

    title: Text | None = None
    description: Text | None = None
    price: Price | None = None
    author: Annotated[int, Field(gt=0)] | None = None

    @model_validator(mode='after')
    def check_fields(self):
        if not self.model_fields_set:
            raise ValueError('Нужно передать хотя бы одно поле')
        if any(getattr(self, field) is None for field in self.model_fields_set):
            raise ValueError('Поля не могут быть null')
        return self


class Advertisement(AdvertisementCreate):
    author: int
    id: int
    created_at: datetime


def find_ad(db, advertisement_id):
    ad = db.execute(
        'SELECT * FROM advertisements WHERE id = ?', (advertisement_id,),
    ).fetchone()
    if ad is None:
        raise HTTPException(status_code=404, detail='Объявление не найдено')
    return dict(ad)


@app.post('/advertisement', response_model=Advertisement, status_code=201)
def create_ad(data: AdvertisementCreate, db: Db, user: CurrentUser):
    author = data.author if data.author is not None else user['id']
    check_owner(user, author)
    find_user(db, author)
    cursor = db.execute(
        '''INSERT INTO advertisements (title, description, price, author, created_at)
           VALUES (?, ?, ?, ?, ?)''',
        (data.title, data.description, data.price, author,
         datetime.now(timezone.utc).isoformat()),
    )
    db.commit()
    return find_ad(db, cursor.lastrowid)


@app.get('/advertisement', response_model=list[Advertisement])
def search_ads(
    db: Db,
    title: str | None = None,
    description: str | None = None,
    price: Annotated[float | None, Query(ge=0, allow_inf_nan=False)] = None,
    author: int | None = None,
    created_at: datetime | None = None,
):
    conditions = []
    values = []
    for field, value in (('title', title), ('description', description)):
        if value is not None:
            conditions.append(f'instr({field}, ?) > 0')
            values.append(value)
    if author is not None:
        conditions.append('author = ?')
        values.append(author)
    if price is not None:
        conditions.append('price = ?')
        values.append(price)
    if created_at is not None:
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        conditions.append('created_at = ?')
        values.append(created_at.astimezone(timezone.utc).isoformat())
    sql = 'SELECT * FROM advertisements'
    if conditions:
        sql += ' WHERE ' + ' AND '.join(conditions)
    return [dict(row) for row in db.execute(sql + ' ORDER BY id', values).fetchall()]


@app.get('/advertisement/{advertisement_id}', response_model=Advertisement)
def get_ad(advertisement_id: int, db: Db):
    return find_ad(db, advertisement_id)


@app.patch('/advertisement/{advertisement_id}', response_model=Advertisement)
def update_ad(advertisement_id: int, data: AdvertisementUpdate, db: Db, user: CurrentUser):
    ad = find_ad(db, advertisement_id)
    check_owner(user, ad['author'])
    updates = data.model_dump(exclude_unset=True)
    if 'author' in updates:
        check_owner(user, updates['author'])
        find_user(db, updates['author'])
    fields = ', '.join(f'{field} = ?' for field in updates)
    db.execute(
        f'UPDATE advertisements SET {fields} WHERE id = ?',
        [*updates.values(), advertisement_id],
    )
    db.commit()
    return find_ad(db, advertisement_id)


@app.delete('/advertisement/{advertisement_id}', status_code=204)
def delete_ad(advertisement_id: int, db: Db, user: CurrentUser):
    ad = find_ad(db, advertisement_id)
    check_owner(user, ad['author'])
    db.execute('DELETE FROM advertisements WHERE id = ?', (advertisement_id,))
    db.commit()
    return Response(status_code=204)


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(app, host='127.0.0.1', port=8000)
