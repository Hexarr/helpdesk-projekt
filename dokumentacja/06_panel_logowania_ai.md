# Tydzień 6 — Panel logowania wygenerowany przez AI + security code review

Proces: AI jako "junior developer" generuje panel logowania → code review
bezpieczeństwa → poprawiona wersja produkcyjna.

## 1. Pierwotna wersja od AI

Prompt:

> Napisz prosty panel logowania do systemu Helpdesk w Python Flask.
> Ma być formularz logowania, baza SQLite z użytkownikami i po zalogowaniu
> panel użytkownika. Kod ma być prosty, żeby dało się go szybko uruchomić lokalnie.

Rezultat: działający panel logowania, ale typowo developerski — bez hashy
haseł, bez bezpiecznej sesji, bez rate limitingu, z zapytaniem SQL składanym
przez konkatenację. Kod: [`original_ai_version/app_insecure.py`](../original_ai_version/app_insecure.py).

## 2. Security code review pierwotnego kodu

| Luka | STRIDE | CIA | Konsekwencja | Fragment |
|------|--------|-----|--------------|----------|
| Hasła jawnym tekstem | Information Disclosure | poufność | po wycieku bazy atakujący zna hasła od razu | `INSERT ... 'admin123'` |
| SQL Injection w logowaniu | Tampering / EoP | poufność, integralność | ominięcie logowania lub odczyt danych | `query = "SELECT ... '" + email + "'"` |
| Brak rate limitingu | DoS / Spoofing | dostępność, poufność | automatyczne zgadywanie haseł, przeciążenie /login | brak limitu w route |
| Brak prawdziwej sesji | Spoofing | poufność | brak bezpiecznego tokenu, brak kontroli sesji | `render_template_string(...)` |
| Brak walidacji inputu | Injection / Tampering | integralność | dane z formularza idą prosto do SQL | `request.form.get("email")` |
| Debug mode | Information Disclosure | poufność | błąd może ujawnić szczegóły aplikacji | `app.run(debug=True)` |
| Słaby secret key | Weak Secret | poufność | `secret_key = "helpdesk123"` → podrobienie cookie | stała w kodzie |

## 3. Poprawiona wersja

| Problem | Poprawka | Dlaczego tak |
|---------|----------|--------------|
| Hasła jawne | `bcrypt.hashpw()` przy tworzeniu, `bcrypt.checkpw()` przy logowaniu | po wycieku bazy hasła nie są jawne |
| Brak sesji | JWT z datą wygaśnięcia w **HttpOnly cookie** | JavaScript nie ma dostępu do tokenu (ochrona przy XSS) |
| Brute force | rate limiting: max 5 prób logowania z IP na minutę | adresuje wymaganie z tygodnia 2 |
| SQL Injection | placeholdery `WHERE email = ?` | parametryzacja oddziela dane od zapytania |
| Brak walidacji | format e-maila, długość hasła, puste pola | złe dane odrzucane przed logiką logowania |
| HTTPS | flaga `HELPDESK_FORCE_HTTPS` ustawia Secure cookie | lokalnie HTTP, w produkcji tylko HTTPS |
| Brak audytu | tabela `security_log` (logowania udane/błędne/rate limit) | widać co działo się w systemie |

Kluczowe fragmenty:

```python
# hashowanie hasla
password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
bcrypt.checkpw(password.encode("utf-8"), user["password_hash"])

# JWT w HttpOnly cookie
response.set_cookie("session_token", token, httponly=True,
                    secure=FORCE_HTTPS, samesite="Strict",
                    max_age=JWT_TTL_MINUTES * 60)

# parametryzowane zapytanie
user = db.execute(
    "SELECT id, email, password_hash, role FROM users WHERE email = ?",
    (email,),
).fetchone()
```

## 4. Co LLM zrobił źle

Największy błąd: kod **działający, ale niebezpieczny**. AI skupiło się na tym,
żeby formularz przyjmował login i hasło, a nie na tym, jak te dane chronić.
To dokładnie ryzyko z wcześniejszej analizy — backend musi wymuszać
bezpieczeństwo, bo same elementy interfejsu nie wystarczają.

LLM użył najprostszych rozwiązań: jawne hasła, konkatenacja SQL, brak sesji.
W poprawionej wersji zastąpiły je mechanizmy z wymagań bezpieczeństwa:
bcrypt, kontrola sesji, rate limiting, walidacja, parametryzowane zapytania.

Wszystkie te mechanizmy weszły do finalnej aplikacji: [`app/app.py`](../app/app.py).
