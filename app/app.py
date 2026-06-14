"""
Helpdesk dla sklepu internetowego.

Czesc logowania: bcrypt, JWT w HttpOnly cookie, rate limiting, walidacja
wejscia, dziennik zdarzen (security_log).
Czesc zgloszen: ochrona przed SQL Injection (parametryzacja), XSS
(escapowanie Jinja2) i CSRF (token w sesji). Zgloszenie ma status, ktory
moga zmieniac tylko pracownik i administrator (kontrola dostepu - RBAC).

Uruchomienie:
    pip install -r requirements.txt
    python app.py
Potem otworz: http://127.0.0.1:5000

Konta testowe:
    admin@sklep.pl      / Admin123!      (administrator)
    pracownik@sklep.pl  / Pracownik123!  (pracownik)
    klient@sklep.pl     / Klient123!     (klient)
"""

import os
import re
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import (Flask, g, make_response, redirect, render_template,
                   request, session, url_for)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "helpdesk.db")

# klucz ze zmiennej srodowiskowej, zeby nie trzymac go na stale w kodzie.
# fallback tylko do testow lokalnych, dlugi bo HS256 chce min. 32 bajty.
SECRET_KEY = os.environ.get("HELPDESK_SECRET", "dev-zmien-to-w-produkcji-na-losowy-dlugi-sekret")

JWT_ALGORITHM = "HS256"
JWT_TTL_MINUTES = 30

# W produkcji aplikacja powinna stac za HTTPS (reverse proxy z TLS).
# Wtedy ustawiamy HELPDESK_FORCE_HTTPS=1, zeby cookie dostalo flage Secure.
FORCE_HTTPS = os.environ.get("HELPDESK_FORCE_HTTPS", "0") == "1"

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PRIORYTETY = {"niski", "sredni", "wysoki"}
STATUSY = {"nowe", "w trakcie", "zamkniete"}
# role obslugi - widza wszystkie zgloszenia i moga zmieniac status
ROLE_OBSLUGI = {"employee", "admin"}

# Prosty rate limiting w pamieci procesu.
# W wiekszym systemie (wiele instancji backendu) lepszy bylby Redis.
RATE_WINDOW = 60
RATE_MAX_LOGIN = 5        # max prob logowania z jednego IP na minute
RATE_MAX_ZGLOSZENIA = 10  # max zgloszen z jednego IP na minute (ochrona DoS)
ATTEMPTS: dict[str, list[float]] = {}
_last_prune = 0.0

app = Flask(__name__)
app.secret_key = SECRET_KEY  # sesja Flask uzywana tylko do tokenu CSRF
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=FORCE_HTTPS,
)


# ----------------------------- baza danych -----------------------------

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        g.db = con
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    con = g.pop("db", None)
    if con is not None:
        con.close()


def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('client', 'employee', 'admin')),
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS zgloszenia (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tytul TEXT NOT NULL,
            opis TEXT NOT NULL,
            priorytet TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'nowe' CHECK(status IN ('nowe', 'w trakcie', 'zamkniete')),
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    # dziennik zdarzen bezpieczenstwa - kto, co, kiedy, z jakiego IP.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS security_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            email TEXT,
            ip TEXT,
            created_at TEXT NOT NULL
        )
    """)
    for email, password, role in [
        ("admin@sklep.pl", "Admin123!", "admin"),
        ("pracownik@sklep.pl", "Pracownik123!", "employee"),
        ("klient@sklep.pl", "Klient123!", "client"),
    ]:
        # hasla hashowane bcryptem, nigdy plain text
        h = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        cur.execute(
            "INSERT OR IGNORE INTO users (email, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (email, h, role, datetime.now(timezone.utc).isoformat()),
        )
    con.commit()
    con.close()


# ----------------------------- pomocnicze -----------------------------

def client_ip() -> str:
    return (request.remote_addr or "unknown").strip()


def log_event(event_type: str, email: str | None = None):
    db = get_db()
    db.execute(
        "INSERT INTO security_log (event_type, email, ip, created_at) VALUES (?, ?, ?, ?)",
        (event_type, email, client_ip(), datetime.now(timezone.utc).isoformat()),
    )
    db.commit()


def _prune_attempts(now: float):
    # co RATE_WINDOW czyscimy stare wpisy, zeby slownik nie rosl w nieskonczonosc.
    # bez tego kazdy nowy adres IP zostawia wpis na zawsze (drobny wektor DoS na pamiec).
    global _last_prune
    if now - _last_prune < RATE_WINDOW:
        return
    _last_prune = now
    for key in list(ATTEMPTS):
        swieze = [t for t in ATTEMPTS[key] if now - t < RATE_WINDOW]
        if swieze:
            ATTEMPTS[key] = swieze
        else:
            del ATTEMPTS[key]


def rate_limited(key: str, max_attempts: int) -> bool:
    """Zwraca True jesli z danego klucza (np. 'login:1.2.3.4') bylo za duzo prob."""
    now = time.time()
    _prune_attempts(now)
    attempts = ATTEMPTS.setdefault(key, [])
    attempts[:] = [t for t in attempts if now - t < RATE_WINDOW]
    if len(attempts) >= max_attempts:
        return True
    attempts.append(now)
    return False


def get_csrf_token() -> str:
    # synchronizer token - jeden na sesje, sekret nieznany atakujacemu z zewnatrz
    token = session.get("csrf_token")
    if not token:
        token = os.urandom(32).hex()
        session["csrf_token"] = token
    return token


def check_csrf() -> bool:
    przyslany = request.form.get("csrf_token", "")
    return bool(przyslany) and przyslany == session.get("csrf_token", "")


def create_token(user_id: int, email: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_TTL_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def read_token() -> dict | None:
    token = request.cookies.get("session_token")
    if not token:
        return None
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        # Token wygasly albo podrobiony - traktujemy jak brak logowania.
        return None


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        payload = read_token()
        if payload is None:
            return redirect(url_for("login"))
        g.user = payload
        return view(*args, **kwargs)
    return wrapper


@app.after_request
def security_headers(response):
    # proste naglowki bezpieczenstwa - obrona w glab (defense in depth)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    # nie wysylamy adresu strony do innych serwisow
    response.headers["Referrer-Policy"] = "no-referrer"
    # nie cache'ujemy stron z sesja - inaczej przycisk "wstecz" pokazuje panel
    # po wylogowaniu (i wyglada jakby logout nie dzialal)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(404)
def blad_404(e):
    return render_template("error.html", code=404, message="Nie znaleziono strony."), 404


@app.errorhandler(500)
def blad_500(e):
    # nie pokazujemy uzytkownikowi szczegolow bledu
    return render_template("error.html", code=500, message="Wystapil blad serwera."), 500


# ------------------------------- widoki -------------------------------

@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        # rate limiting - ochrona przed brute force
        if rate_limited("login:" + client_ip(), RATE_MAX_LOGIN):
            log_event("login_rate_limited", request.form.get("email", ""))
            error = "Za duzo prob logowania. Sprobuj ponownie za minute."
            return render_template("login.html", error=error), 429

        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        # walidacja po stronie backendu (nie ufamy temu co przyszlo z formularza)
        if not email or not password:
            error = "Email i haslo sa wymagane."
        elif len(email) > 120 or not EMAIL_RE.match(email):
            error = "Niepoprawny format adresu e-mail."
        elif len(password) < 8 or len(password) > 128:
            error = "Haslo ma niepoprawna dlugosc."
        if error:
            log_event("login_validation_error", email)
            return render_template("login.html", error=error), 400

        db = get_db()
        # SQL Injection: parametryzowane zapytanie (?) zamiast konkatenacji
        user = db.execute(
            "SELECT id, email, password_hash, role FROM users WHERE email = ?",
            (email,),
        ).fetchone()

        if user and bcrypt.checkpw(password.encode("utf-8"), user["password_hash"]):
            token = create_token(user["id"], user["email"], user["role"])
            log_event("login_success", email)
            response = make_response(redirect(url_for("panel")))
            # JWT w HttpOnly cookie - JavaScript nie ma do niego dostepu
            response.set_cookie(
                "session_token",
                token,
                httponly=True,
                secure=FORCE_HTTPS,
                samesite="Strict",
                max_age=JWT_TTL_MINUTES * 60,
            )
            return response

        log_event("login_failed", email)
        # Nie zdradzamy, czy email istnieje, czy haslo jest zle.
        error = "Bledny login lub haslo."

    return render_template("login.html", error=error)


@app.route("/panel")
@login_required
def panel():
    return render_template("panel.html", user=g.user)


@app.route("/zgloszenia")
@login_required
def zgloszenia():
    db = get_db()
    # kontrola dostepu (RBAC): tozsamosc i role bierzemy z tokenu, nigdy z URL.
    # obsluga (pracownik/admin) widzi wszystkie zgloszenia, klient tylko swoje.
    if g.user["role"] in ROLE_OBSLUGI:
        wyniki = db.execute(
            """SELECT z.id, z.tytul, z.opis, z.priorytet, z.status, z.created_at, u.email
               FROM zgloszenia z JOIN users u ON u.id = z.user_id
               ORDER BY z.id DESC"""
        ).fetchall()
        moze_zmieniac = True
    else:
        wyniki = db.execute(
            """SELECT id, tytul, opis, priorytet, status, created_at, NULL AS email
               FROM zgloszenia WHERE user_id = ? ORDER BY id DESC""",
            (int(g.user["sub"]),),
        ).fetchall()
        moze_zmieniac = False
    return render_template(
        "zgloszenia.html",
        zgloszenia=wyniki,
        user=g.user,
        moze_zmieniac=moze_zmieniac,
        statusy=sorted(STATUSY),
        csrf_token=get_csrf_token(),
    )


@app.route("/zgloszenie/<int:zgloszenie_id>/status", methods=["POST"])
@login_required
def zmien_status(zgloszenie_id):
    # punkt kontroli z analizy STRIDE (Tampering): zmiane stanu sprawdzamy
    # na backendzie - CSRF, potem rola, potem whitelist wartosci.
    if not check_csrf():
        log_event("csrf_blocked", g.user["email"])
        return render_template("error.html", code=403, message="Nieprawidlowy token CSRF."), 403
    if g.user["role"] not in ROLE_OBSLUGI:
        log_event("status_change_denied", g.user["email"])
        return render_template("error.html", code=403, message="Brak uprawnien do zmiany statusu."), 403
    nowy = request.form.get("status", "")
    if nowy not in STATUSY:
        return render_template("error.html", code=400, message="Nieprawidlowy status."), 400

    db = get_db()
    cur = db.execute("UPDATE zgloszenia SET status = ? WHERE id = ?", (nowy, zgloszenie_id))
    db.commit()
    if cur.rowcount == 0:
        return render_template("error.html", code=404, message="Nie znaleziono zgloszenia."), 404

    log_event("status_changed:" + nowy, g.user["email"])
    return redirect(url_for("zgloszenia"))


@app.route("/nowe_zgloszenie", methods=["GET", "POST"])
@login_required
def nowe_zgloszenie():
    error = None
    sukces = None

    if request.method == "POST":
        # CSRF: token z sesji musi zgadzac sie z polem formularza
        if not check_csrf():
            log_event("csrf_blocked", g.user["email"])
            return render_template("nowe_zgloszenie.html",
                                   error="Nieprawidlowe zadanie (bledny token CSRF).",
                                   csrf_token=get_csrf_token(), user=g.user), 403

        # limit zgloszen - DoS mial najwyzszy wynik w analizie DREAD
        if rate_limited("zgloszenie:" + client_ip(), RATE_MAX_ZGLOSZENIA):
            log_event("zgloszenie_rate_limited", g.user["email"])
            return render_template("nowe_zgloszenie.html",
                                   error="Za duzo zgloszen w krotkim czasie. Sprobuj za minute.",
                                   csrf_token=get_csrf_token(), user=g.user), 429

        tytul = (request.form.get("tytul") or "").strip()
        opis = (request.form.get("opis") or "").strip()
        priorytet = request.form.get("priorytet", "niski")

        # walidacja: dlugosci + whitelist priorytetow
        if not tytul or not opis:
            error = "Tytul i opis sa wymagane."
        elif len(tytul) > 200:
            error = "Tytul jest za dlugi (max 200 znakow)."
        elif len(opis) > 2000:
            error = "Opis jest za dlugi (max 2000 znakow)."
        elif priorytet not in PRIORYTETY:
            # Whitelist - odrzucamy wszystko spoza listy, nie ufamy frontendowi.
            error = "Nieprawidlowa wartosc priorytetu."
        else:
            db = get_db()
            # SQL Injection: parametryzowane zapytanie (status bierze domyslne 'nowe')
            db.execute(
                "INSERT INTO zgloszenia (tytul, opis, priorytet, user_id, created_at) VALUES (?, ?, ?, ?, ?)",
                (tytul, opis, priorytet, int(g.user["sub"]),
                 datetime.now(timezone.utc).isoformat()),
            )
            db.commit()
            sukces = "Zgloszenie zostalo dodane!"

    return render_template("nowe_zgloszenie.html", error=error, sukces=sukces,
                           csrf_token=get_csrf_token(), user=g.user)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    # Wylogowanie przez POST (nie GET), zeby nie dalo sie wylogowac linkiem.
    log_event("logout", g.user["email"])
    session.clear()
    response = make_response(redirect(url_for("login")))
    response.delete_cookie("session_token")
    return response


if __name__ == "__main__":
    init_db()
    # debug=False - w trybie debug moglyby wyciekac szczegoly bledow.
    app.run(host="127.0.0.1", port=5000, debug=False)
