"""Szybki test aplikacji bez przegladarki (python smoke_test.py)."""
import re

import app as helpdesk

helpdesk.init_db()
client = helpdesk.app.test_client()

# 1. logowanie zlym haslem
r = client.post("/login", data={"email": "klient@sklep.pl", "password": "zlehaslo1"})
assert "Bledny login lub haslo" in r.get_data(as_text=True), "test 1"

# 2. SQLi payload odrzucony przez walidacje formatu e-mail
r = client.post("/login", data={"email": "' OR '1'='1'--", "password": "cokolwiek1"})
assert r.status_code == 400, "test 2"

# 3. poprawne logowanie klienta -> redirect + cookie z tokenem
r = client.post("/login", data={"email": "klient@sklep.pl", "password": "Klient123!"})
assert r.status_code == 302, "test 3"
assert "session_token" in r.headers.get("Set-Cookie", ""), "test 3 cookie"

# 4. panel dostepny po zalogowaniu
r = client.get("/panel")
assert r.status_code == 200 and "klient@sklep.pl" in r.get_data(as_text=True), "test 4"

# 5. nowe zgloszenie bez tokenu CSRF -> 403
r = client.post("/nowe_zgloszenie", data={"tytul": "x", "opis": "y", "priorytet": "niski"})
assert r.status_code == 403, "test 5"

# 6. nowe zgloszenie z tokenem CSRF -> sukces
r = client.get("/nowe_zgloszenie")
token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', r.get_data(as_text=True)).group(1)
r = client.post("/nowe_zgloszenie", data={
    "tytul": "<script>alert(1)</script>", "opis": "test opisu",
    "priorytet": "wysoki", "csrf_token": token,
})
assert "Zgloszenie zostalo dodane" in r.get_data(as_text=True), "test 6"

# 7. XSS escapowany na liscie zgloszen
r = client.get("/zgloszenia")
html = r.get_data(as_text=True)
assert "<script>alert(1)</script>" not in html, "test 7 - skrypt niewykonany"
assert "&lt;script&gt;" in html, "test 7 - escapowanie"

# 8. zly priorytet odrzucony (whitelist)
r = client.get("/nowe_zgloszenie")
token = re.search(r'name="csrf_token" value="([0-9a-f]+)"', r.get_data(as_text=True)).group(1)
r = client.post("/nowe_zgloszenie", data={
    "tytul": "a", "opis": "b", "priorytet": "hakerski", "csrf_token": token,
})
assert "Nieprawidlowa wartosc priorytetu" in r.get_data(as_text=True), "test 8"

# 9. wylogowanie i brak dostepu do panelu
r = client.post("/logout")
r = client.get("/panel")
assert r.status_code == 302, "test 9"

# 10. rate limiting logowania (5 prob z IP na minute)
last = None
for _ in range(6):
    last = client.post("/login", data={"email": "klient@sklep.pl", "password": "zlehaslo1"})
assert last.status_code == 429, "test 10"

# 11. admin widzi zgloszenia z autorem
helpdesk.ATTEMPTS.clear()
r = client.post("/login", data={"email": "admin@sklep.pl", "password": "Admin123!"})
r = client.get("/zgloszenia")
assert "klient@sklep.pl" in r.get_data(as_text=True), "test 11"

print("OK - wszystkie testy przeszly (11/11)")
