"""
Testy aplikacji Helpdesk (pytest).

Uruchomienie (z katalogu app/):
    pip install -r requirements.txt -r requirements-dev.txt
    pytest

Kazdy test dostaje swieza baze w pliku tymczasowym, wiec testy sa niezalezne.
"""

import re
import sqlite3
import time

import pytest

import app as helpdesk


@pytest.fixture
def klient(tmp_path, monkeypatch):
    db = tmp_path / "test.db"
    monkeypatch.setattr(helpdesk, "DB_PATH", str(db))
    helpdesk.ATTEMPTS.clear()
    helpdesk._last_prune = 0.0
    helpdesk.init_db()
    return helpdesk.app.test_client()


# --------------------------- pomocnicze ---------------------------

def zaloguj(klient, email, haslo):
    return klient.post("/login", data={"email": email, "password": haslo})


def pobierz_csrf(klient, sciezka="/nowe_zgloszenie"):
    html = klient.get(sciezka).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([0-9a-f]+)"', html).group(1)


def dodaj_zgloszenie(klient, tytul="Problem z zamowieniem", opis="Tresc zgloszenia", priorytet="niski"):
    token = pobierz_csrf(klient)
    return klient.post("/nowe_zgloszenie", data={
        "tytul": tytul, "opis": opis, "priorytet": priorytet, "csrf_token": token,
    })


def id_pierwszego_zgloszenia():
    con = sqlite3.connect(helpdesk.DB_PATH)
    try:
        return con.execute("SELECT id FROM zgloszenia ORDER BY id LIMIT 1").fetchone()[0]
    finally:
        con.close()


def status_zgloszenia(zid):
    con = sqlite3.connect(helpdesk.DB_PATH)
    try:
        return con.execute("SELECT status FROM zgloszenia WHERE id = ?", (zid,)).fetchone()[0]
    finally:
        con.close()


# --------------------------- logowanie / walidacja ---------------------------

def test_zle_haslo(klient):
    r = zaloguj(klient, "klient@sklep.pl", "zlehaslo1")
    assert "Bledny login lub haslo" in r.get_data(as_text=True)


def test_sqli_w_logowaniu_odrzucone(klient):
    r = zaloguj(klient, "' OR '1'='1'--", "cokolwiek1")
    assert r.status_code == 400


def test_poprawne_logowanie_ustawia_cookie(klient):
    r = zaloguj(klient, "klient@sklep.pl", "Klient123!")
    assert r.status_code == 302
    assert "session_token" in r.headers.get("Set-Cookie", "")


def test_rate_limit_logowania(klient):
    ostatni = None
    for _ in range(6):
        ostatni = zaloguj(klient, "klient@sklep.pl", "zlehaslo1")
    assert ostatni.status_code == 429


# --------------------------- zgloszenia / CSRF / XSS ---------------------------

def test_nowe_zgloszenie_bez_csrf_403(klient):
    zaloguj(klient, "klient@sklep.pl", "Klient123!")
    r = klient.post("/nowe_zgloszenie", data={"tytul": "x", "opis": "y", "priorytet": "niski"})
    assert r.status_code == 403


def test_nowe_zgloszenie_z_csrf_sukces(klient):
    zaloguj(klient, "klient@sklep.pl", "Klient123!")
    r = dodaj_zgloszenie(klient)
    assert "Zgloszenie zostalo dodane" in r.get_data(as_text=True)


def test_nowe_zgloszenie_ma_status_nowe(klient):
    zaloguj(klient, "klient@sklep.pl", "Klient123!")
    dodaj_zgloszenie(klient)
    assert status_zgloszenia(id_pierwszego_zgloszenia()) == "nowe"


def test_xss_escapowany(klient):
    zaloguj(klient, "klient@sklep.pl", "Klient123!")
    dodaj_zgloszenie(klient, tytul="<script>alert(1)</script>")
    html = klient.get("/zgloszenia").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_zly_priorytet_odrzucony(klient):
    zaloguj(klient, "klient@sklep.pl", "Klient123!")
    token = pobierz_csrf(klient)
    r = klient.post("/nowe_zgloszenie", data={
        "tytul": "a", "opis": "b", "priorytet": "hakerski", "csrf_token": token})
    assert "Nieprawidlowa wartosc priorytetu" in r.get_data(as_text=True)


# --------------------------- wylogowanie ---------------------------

def test_wylogowanie(klient):
    zaloguj(klient, "klient@sklep.pl", "Klient123!")
    klient.post("/logout")
    r = klient.get("/panel")
    assert r.status_code == 302


# --------------------------- role / RBAC ---------------------------

def test_klient_widzi_tylko_swoje(klient):
    zaloguj(klient, "klient@sklep.pl", "Klient123!")
    dodaj_zgloszenie(klient, tytul="Sprawa klienta")
    html = klient.get("/zgloszenia").get_data(as_text=True)
    assert "Autor:" not in html                      # klient nie widzi kolumny autora
    assert 'action="/zgloszenie/' not in html        # ani formularza zmiany statusu


def test_admin_widzi_wszystkie_z_autorem(klient):
    zaloguj(klient, "klient@sklep.pl", "Klient123!")
    dodaj_zgloszenie(klient, tytul="Sprawa klienta")
    zaloguj(klient, "admin@sklep.pl", "Admin123!")
    html = klient.get("/zgloszenia").get_data(as_text=True)
    assert "Sprawa klienta" in html
    assert "klient@sklep.pl" in html


def test_pracownik_widzi_wszystkie_i_ma_formularz(klient):
    zaloguj(klient, "klient@sklep.pl", "Klient123!")
    dodaj_zgloszenie(klient, tytul="Sprawa klienta")
    zaloguj(klient, "pracownik@sklep.pl", "Pracownik123!")
    html = klient.get("/zgloszenia").get_data(as_text=True)
    assert "Sprawa klienta" in html
    assert 'action="/zgloszenie/' in html            # pracownik ma formularz zmiany statusu


# --------------------------- zmiana statusu (Tampering / kontrola dostepu) ---------------------------

def test_admin_zmienia_status(klient):
    zaloguj(klient, "klient@sklep.pl", "Klient123!")
    dodaj_zgloszenie(klient)
    zid = id_pierwszego_zgloszenia()
    zaloguj(klient, "admin@sklep.pl", "Admin123!")
    token = pobierz_csrf(klient, "/zgloszenia")
    r = klient.post(f"/zgloszenie/{zid}/status", data={"status": "w trakcie", "csrf_token": token})
    assert r.status_code == 302
    assert status_zgloszenia(zid) == "w trakcie"


def test_klient_nie_moze_zmienic_statusu(klient):
    zaloguj(klient, "klient@sklep.pl", "Klient123!")
    dodaj_zgloszenie(klient)
    zid = id_pierwszego_zgloszenia()
    token = pobierz_csrf(klient, "/nowe_zgloszenie")
    r = klient.post(f"/zgloszenie/{zid}/status", data={"status": "zamkniete", "csrf_token": token})
    assert r.status_code == 403
    assert status_zgloszenia(zid) == "nowe"   # status sie nie zmienil


def test_zmiana_statusu_bez_csrf_403(klient):
    zaloguj(klient, "klient@sklep.pl", "Klient123!")
    dodaj_zgloszenie(klient)
    zid = id_pierwszego_zgloszenia()
    zaloguj(klient, "admin@sklep.pl", "Admin123!")
    r = klient.post(f"/zgloszenie/{zid}/status", data={"status": "w trakcie"})
    assert r.status_code == 403


def test_nieprawidlowy_status_odrzucony(klient):
    zaloguj(klient, "klient@sklep.pl", "Klient123!")
    dodaj_zgloszenie(klient)
    zid = id_pierwszego_zgloszenia()
    zaloguj(klient, "admin@sklep.pl", "Admin123!")
    token = pobierz_csrf(klient, "/zgloszenia")
    r = klient.post(f"/zgloszenie/{zid}/status", data={"status": "usuniete", "csrf_token": token})
    assert r.status_code == 400


# --------------------------- wlasna strona bledu ---------------------------

def test_404_wlasna_strona(klient):
    r = klient.get("/strona-ktora-nie-istnieje")
    assert r.status_code == 404
    assert "Nie znaleziono strony" in r.get_data(as_text=True)


# --------------------------- pruning slownika rate-limit (ochrona pamieci / DoS) ---------------------------

def test_pruning_usuwa_stare_wpisy(klient):
    helpdesk.ATTEMPTS["login:9.9.9.9"] = [time.time() - 999]  # wpis sprzed dawna
    helpdesk._last_prune = 0.0                                # wymus prune przy nastepnym wywolaniu
    helpdesk.rate_limited("login:1.1.1.1", helpdesk.RATE_MAX_LOGIN)
    assert "login:9.9.9.9" not in helpdesk.ATTEMPTS
