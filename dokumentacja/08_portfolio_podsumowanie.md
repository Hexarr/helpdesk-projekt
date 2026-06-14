# Tydzień 8 — Portfolio projektu: podsumowanie

## Co zawiera portfolio

1. **Działająca aplikacja** — [`app/`](../app/) łączy wszystkie moduły z tygodni 6–7
   w jednym folderze:
   - moduł logowania (tydzień 6): bcrypt, JWT w HttpOnly cookie, rate limiting,
     walidacja wejścia, dziennik zdarzeń `security_log`
   - moduł zgłoszeń (tydzień 7): lista i tworzenie zgłoszeń, ochrona przed
     SQL Injection / XSS / CSRF, whitelist priorytetów
   - poprawki z tygodnia 8: pełny RBAC z 3 rolami z modelu (klient / pracownik /
     administrator), status zgłoszenia (nowe / w trakcie / zamknięte) zmieniany
     tylko przez obsługę — punkt kontroli z analizy Tampering, rate limiting także
     dla zgłoszeń (priorytet nr 1 z DREAD — DoS), nagłówki bezpieczeństwa
     (X-Frame-Options, nosniff, CSP, Referrer-Policy), własna strona błędu 404/500
     i testy w `pytest`
2. **Artefakty z tygodni 1–8** — folder [`dokumentacja/`](.), pliki `01`–`08`
   (oryginalne PDF-y w [`dokumentacja/pdf/`](pdf/))
3. **Security Checklist** — [`SECURITY_CHECKLIST.md`](../SECURITY_CHECKLIST.md),
   18 pozycji z oznaczeniem co spełnione, a co wymaga dalszej pracy

## Jak moduły łączą się z wcześniejszą analizą

| Mechanizm w aplikacji | Skąd wynika |
|-----------------------|-------------|
| rate limiting logowania i zgłoszeń | DoS = najwyższy wynik DREAD (40), wymaganie z tygodnia 2 |
| klient widzi tylko swoje zgłoszenia | Information Disclosure (DREAD 39), scenariusz 1 z tygodnia 2 |
| role sprawdzane na backendzie (JWT, 3 role) | Elevation of Privilege (DREAD 37), RBAC z tygodnia 5 |
| zmiana statusu tylko przez pracownika/admina | Tampering ze STRIDE (DREAD 36) |
| parametryzowane zapytania SQL | Injection (OWASP), luki 1–2 z tygodnia 7 |
| escapowanie Jinja2 bez `\|safe` | Stored XSS, luka 3 z tygodnia 7 |
| token CSRF + SameSite=Strict | CSRF, luka 4 z tygodnia 7 |
| bcrypt + HttpOnly cookie | code review z tygodnia 6 |
| tabela `security_log` | wymaganie logowania zdarzeń z tygodnia 2, Repudiation ze STRIDE |
| debug=False, ogólne komunikaty błędów | code review z tygodnia 6 |

## Czego się nauczyłem

1. **Backend musi wymuszać bezpieczeństwo** — frontend można ominąć jednym
   żądaniem HTTP, więc walidacja, role i limity muszą działać na serwerze.
2. **Kod od AI trzeba review'ować** — AI generuje kod działający, ale
   niebezpieczny; bez code review luki typu SQL Injection trafiają do produkcji.
3. **Modelowanie zagrożeń porządkuje pracę** — STRIDE + DREAD dały konkretne
   priorytety (DoS, wyciek danych, eskalacja uprawnień) zamiast zgadywania,
   co zabezpieczyć najpierw.
4. **Bezpieczeństwo to warstwy** — jedna ochrona nie wystarcza: CSRF token +
   SameSite, escapowanie + HttpOnly, walidacja + parametryzacja.
