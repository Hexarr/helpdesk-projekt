# Helpdesk dla sklepu internetowego — portfolio projektu (tygodnie 1–8)

Kompletne portfolio projektu z przedmiotu: system Helpdesk projektowany
"security first" — od analizy zagrożeń (CIA, STRIDE, DREAD), przez code review
kodu generowanego przez AI, po działającą, zabezpieczoną aplikację.

## Struktura projektu

```
.
├── app/                        # FINALNA aplikacja (moduły z tygodni 6-7 w jednym folderze)
│   ├── app.py                  # logowanie + zgłoszenia, wszystkie zabezpieczenia
│   ├── requirements.txt
│   └── templates/              # szablony Jinja2 (escapowanie domyślne, bez |safe)
├── original_ai_version/
│   └── app_insecure.py         # wersja podatna od AI (tylko do analizy!)
├── dokumentacja/               # artefakty z tygodni 1-8
│   ├── 01_architektura_i_cia.md
│   ├── 02_zagrozenia_wymagania_owasp.md
│   ├── 03_dfd_stride.md
│   ├── 04_dread.md
│   ├── 05_zasady_projektowania.md
│   ├── 06_panel_logowania_ai.md
│   ├── 07_injection_xss_csrf.md
│   ├── 08_portfolio_podsumowanie.md
│   └── pdf/                    # oryginalne dokumenty PDF
├── SECURITY_CHECKLIST.md       # 18 pozycji: co spełnione, co wymaga pracy
└── README.md
```

## Uruchomienie aplikacji

```bash
cd app
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Adres: http://127.0.0.1:5000

### Konta testowe

| Email | Hasło | Rola |
|-------|-------|------|
| `admin@sklep.pl` | `Admin123!` | admin (widzi wszystkie zgłoszenia) |
| `klient@sklep.pl` | `Klient123!` | client (widzi tylko swoje) |

## Zaimplementowane zabezpieczenia (skrót)

| Zabezpieczenie | Przed czym chroni |
|----------------|-------------------|
| bcrypt (hash + sól) | wyciek haseł z bazy |
| parametryzowane zapytania SQL | SQL Injection |
| escapowanie Jinja2 (bez `\|safe`) | Stored XSS |
| token CSRF + SameSite=Strict | CSRF |
| JWT w HttpOnly cookie (30 min) | kradzież sesji przez JS |
| rate limiting (login 5/min, zgłoszenia 10/min na IP) | brute force, DoS |
| walidacja wejścia + whitelist priorytetów | złe/złośliwe dane |
| RBAC na backendzie (rola z tokenu, nie z URL) | dostęp do cudzych danych, eskalacja uprawnień |
| tabela `security_log` | brak śladów po incydencie |
| nagłówki: X-Frame-Options, nosniff, CSP, Referrer-Policy | clickjacking, MIME sniffing, wyciek referera |
| `debug=False`, ogólne komunikaty błędów | wyciek szczegółów, user enumeration |

Pełna lista z oznaczeniem braków: [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md).

## Wersja podatna (tylko do analizy)

```bash
cd original_ai_version
pip install flask
python app_insecure.py    # http://127.0.0.1:5001
```

> **UWAGA:** wersja insecure celowo zawiera luki (SQL Injection, XSS, CSRF,
> hasła plain text). Nie uruchamiaj jej na serwerze publicznym.
> Analiza luk: [dokumentacja/07_injection_xss_csrf.md](dokumentacja/07_injection_xss_csrf.md).

## Autor

Jan Pawlikowski — projekt zaliczeniowy z bezpieczeństwa aplikacji webowych.
