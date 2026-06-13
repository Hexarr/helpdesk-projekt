# Tydzień 1 — Architektura systemu i triada CIA

Projekt systemu Helpdesk dla sklepu internetowego. System służy do obsługi
zgłoszeń klientów dotyczących zamówień, zwrotów, reklamacji i płatności.

## 1. Propozycja architektury

| Komponent | Rola | Dlaczego oddzielony |
|-----------|------|---------------------|
| Frontend | aplikacja webowa dla użytkownika | użytkownik ma dostęp tylko do interfejsu |
| Backend | logika i dostęp do danych | wszystko można kontrolować po stronie serwera |
| Baza danych | przechowuje dane | oddzielenie ogranicza dostęp do danych |
| Auth | logowanie i role użytkowników | pozwala kontrolować kto ma do czego dostęp |
| Email | powiadomienia do użytkowników | dane wychodzą poza system, trzeba je ograniczać |

Komunikacja: frontend ↔ backend (HTTPS), backend ↔ baza (SQL), backend ↔ email.

## 2. Uzasadnienie z perspektywy bezpieczeństwa

- **Frontend** — możliwy XSS. Walidacja danych i HTTPS chronią przed złośliwym kodem i przechwyceniem danych.
- **Backend** — ryzyko dostępu do cudzych danych. Backend sprawdza uprawnienia użytkownika przy każdej operacji.
- **Baza danych** — ryzyko wycieku. Ograniczenie dostępu i backupy chronią dane przed utratą i osobami nieuprawnionymi.
- **Auth** — ryzyko przejęcia konta. Hashowanie haseł sprawia, że nawet po wycieku nie da się łatwo odczytać hasła.
- **Email** — ryzyko wysłania danych do złej osoby. Ograniczenie treści maili zmniejsza ilość wrażliwych danych poza systemem.

## 3. Triada CIA

- **Poufność** — dane klientów i zgłoszeń muszą być chronione przed dostępem osób trzecich.
- **Integralność** — dane nie mogą być zmienione przez nieuprawnione osoby.
- **Dostępność** — system powinien działać cały czas, aby klienci mogli zgłaszać problemy.

Trade-off: więcej zabezpieczeń może spowolnić system.

## 4. Użytkownicy i dane

Użytkownicy:
1. **Klient** — zgłasza problemy i widzi tylko swoje zgłoszenia
2. **Pracownik** — obsługuje zgłoszenia
3. **Administrator** — zarządza systemem

Dane:
1. Dane osobowe (imię, email, telefon)
2. Numery zamówień
3. Treść zgłoszeń
4. Dane logowania

Najważniejsze do ochrony są **dane osobowe i dane logowania**, ponieważ mogą
zostać użyte do przejęcia konta lub naruszenia prywatności użytkownika.

## 5. Pytania otwarte (na start projektu)

1. Jak upewnić się, że użytkownik widzi tylko swoje dane?
2. Jak ograniczyć dostęp pracowników tylko do potrzebnych danych?
3. Jak wykrywać próby nadużyć w systemie?
