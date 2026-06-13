# Tydzień 5 — Zasady bezpiecznego projektowania i decyzje techniczne

Przełożenie wyników STRIDE i DREAD na konkretne decyzje projektowe przed
implementacją. Trzy najwyższe ryzyka: przeciążenie systemu (DREAD 40),
ujawnienie danych klienta (39), podniesienie uprawnień (37).

## Część I — Zasady w architekturze

| Komponent | Zasada | Realizacja w Helpdesku |
|-----------|--------|------------------------|
| Frontend | Secure by Default, Defense in Depth | formularze pokazują tylko potrzebne pola; frontend waliduje dane, ale tylko jako pierwsza warstwa — prawdziwa kontrola jest na backendzie |
| Serwer aplikacji / API | Least Privilege, Fail Secure, Defense in Depth | każde żądanie sprawdzane na serwerze: kto wysyła i czy ma dostęp; jeśli nie można potwierdzić uprawnienia — domyślnie odmowa |
| Moduł logowania i sesji | Secure by Default, Defense in Depth | HTTPS, hasła hashowane, limit prób logowania, sesja wygasa po czasie; dla admina docelowo MFA |
| Baza danych | Least Privilege, Defense in Depth | baza niedostępna z internetu; łączy się z nią tylko backend na osobnym koncie; hasła jako hash |
| Panel administratora | Separation of Duties, Least Privilege | admin ma osobny panel i uprawnienia; pracownik nie zarządza kontami ani rolami |
| Moduł e-mail | Secure by Default, Least Privilege | e-mail tylko informuje o zmianie statusu, bez pełnych danych klienta |
| Logi i monitoring | Defense in Depth, Separation of Duties | zapis nieudanych logowań, zmian statusów, błędów dostępu; pracownik nie może edytować logów |
| Rate limiting / ochrona API | Fail Secure, Secure by Default | limity żądań dla logowania, zgłoszeń i API; przy podejrzanym ruchu system ogranicza dostęp |

## Część II — Security Design Document (3 decyzje)

### 1. Denial of Service — przeciążenie formularza zgłoszeń albo API (DREAD 40)

- **Zasady:** Defense in Depth, Fail Secure, Secure by Default
- **Decyzja:** rate limiting dla logowania, formularza zgłoszeń i API; limit rozmiaru załączników; limit zgłoszeń z jednego IP; captcha dla publicznego formularza; logowanie nietypowego ruchu.
- **Uzasadnienie / alternatywy:** rate limiting jest prosty do przetestowania i działa zanim baza zostanie przeciążona. Alternatywa — zwiększanie zasobów serwera — nie rozwiązuje problemu, tylko go przesuwa i podnosi koszty.
- **Konsekwencje:** przy zbyt wielu próbach użytkownik dostaje blokadę czasową. Minimalizacja: rozsądne limity, jasny komunikat, osobne limity per endpoint.

### 2. Information Disclosure — ujawnienie danych innego klienta (DREAD 39)

- **Zasady:** Least Privilege, Fail Secure, Defense in Depth
- **Decyzja:** każdy odczyt i zmiana zgłoszenia przechodzi przez kontrolę dostępu na backendzie (właściciel albo przypisany pracownik). Nieudane sprawdzenie = odmowa. API zwraca tylko potrzebne dane.
- **Uzasadnienie / alternatywy:** lepsze niż ukrywanie przycisków w UI, bo frontend można ominąć. Losowe ID mogą pomóc, ale głównym zabezpieczeniem jest sprawdzanie uprawnień na serwerze.
- **Konsekwencje:** mniej prostoty kodu. Minimalizacja: jeden wspólny mechanizm sprawdzania uprawnień + testy.

### 3. Elevation of Privilege — zdobycie uprawnień administratora (DREAD 37)

- **Zasady:** Separation of Duties, Least Privilege, Fail Secure
- **Decyzja:** RBAC z rolami klient / pracownik / administrator. Role zapisane i sprawdzane na backendzie, nie z parametrów frontendu. Operacje administracyjne tylko dla admina.
- **Uzasadnienie / alternatywy:** RBAC pasuje, bo role są proste i jasno oddzielone. Szczegółowy model uprawnień per akcja byłby na tym etapie zbyt skomplikowany.
- **Konsekwencje:** sztywne role. Minimalizacja: jasny podział obowiązków + testy, czy pracownik nie wykona operacji admina ręcznie spreparowanym żądaniem.

## Podsumowanie

Najważniejsza decyzja: **bezpieczeństwo nie może zależeć od frontendu**.
Frontend pomaga użytkownikowi, ale backend musi sprawdzać logowanie, role,
właściciela zgłoszenia, limity i operacje administracyjne.
