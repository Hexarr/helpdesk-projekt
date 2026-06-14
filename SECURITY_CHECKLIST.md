# Security Checklist przed wdrożeniem — Helpdesk

Legenda: ✅ spełnione w aplikacji | ⚠️ wymaga dalszej pracy przed produkcją

## Spełnione

| # | Pozycja | Status | Gdzie w projekcie |
|---|---------|--------|-------------------|
| 1 | Hasła hashowane (bcrypt z solą), nigdy plain text | ✅ | `app/app.py` — `init_db()`, `login()` |
| 2 | Parametryzowane zapytania SQL (ochrona przed SQL Injection) | ✅ | wszystkie `db.execute(..., (params,))` |
| 3 | Escapowanie HTML — szablony Jinja2 bez `\|safe` (ochrona przed XSS) | ✅ | `app/templates/*.html` |
| 4 | Token CSRF dla formularzy zmieniających stan (synchronizer token w sesji) | ✅ | `nowe_zgloszenie()`, `zmien_status()` + ukryte pole w formularzu |
| 5 | JWT w HttpOnly cookie, SameSite=Strict, czas życia 30 min | ✅ | `create_token()`, `login()` |
| 6 | Walidacja danych wejściowych na backendzie (długości, format e-mail, whitelist priorytetów) | ✅ | `login()`, `nowe_zgloszenie()` |
| 7 | Rate limiting logowania (5 prób / IP / minutę) — ochrona przed brute force | ✅ | `rate_limited()` w `login()` |
| 8 | Rate limiting zgłoszeń (10 / IP / minutę) — ochrona przed DoS | ✅ | `rate_limited()` w `nowe_zgloszenie()` |
| 9 | Kontrola dostępu na backendzie (RBAC, 3 role): klient widzi tylko swoje zgłoszenia, pracownik/admin wszystkie; zmianę statusu może wykonać tylko obsługa | ✅ | `zgloszenia()`, `zmien_status()` — rola z tokenu, nie z URL |
| 10 | Logowanie zdarzeń bezpieczeństwa (udane/nieudane logowania, rate limit, blokady CSRF) | ✅ | tabela `security_log`, `log_event()` |
| 11 | `debug=False` + ogólne komunikaty błędów (nie zdradzamy, czy email istnieje) | ✅ | `app.run(debug=False)`, komunikat "Błędny login lub hasło" |
| 12 | Nagłówki bezpieczeństwa: X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy | ✅ | `security_headers()` (after_request) |

## Wymaga dalszej pracy

| # | Pozycja | Status | Co trzeba zrobić |
|---|---------|--------|------------------|
| 13 | HTTPS + Secure cookie | ⚠️ | lokalnie aplikacja działa po HTTP; przed wdrożeniem: reverse proxy z TLS (np. nginx + certyfikat) i `HELPDESK_FORCE_HTTPS=1` |
| 14 | Secret key wyłącznie ze zmiennej środowiskowej | ⚠️ | w kodzie jest fallback deweloperski; w produkcji usunąć fallback i wymusić ustawienie `HELPDESK_SECRET` (losowy, długi) |
| 15 | MFA dla konta administratora | ⚠️ | zaplanowane w tygodniu 5 (STRIDE — Spoofing), niezaimplementowane |
| 16 | Rate limiting w pamięci procesu | ⚠️ | działa tylko dla jednej instancji; przy wielu instancjach backendu potrzebny Redis |
| 17 | Captcha dla formularzy publicznych | ⚠️ | dodatkowa ochrona anty-botowa z planu DoS (DREAD 40) |
| 18 | Backupy bazy danych + monitoring obciążenia | ⚠️ | wymaganie z tygodnia 1 (dostępność); do ustawienia na środowisku produkcyjnym |

**Podsumowanie:** 12/18 pozycji spełnione w kodzie. Pozostałe 6 to głównie
sprawy środowiska produkcyjnego (TLS, sekrety, Redis, backupy) i rozszerzenia
(MFA, captcha) — świadomie odłożone, bo aplikacja jest uruchamiana lokalnie.
