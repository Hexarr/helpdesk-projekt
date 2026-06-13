# Tydzień 4 — Ocena ryzyka DREAD

Rozszerzenie analizy STRIDE o ocenę DREAD. Każde zagrożenie dostało punkty
0–10 w pięciu kryteriach: **D**amage, **R**eproducibility, **E**xploitability,
**A**ffected Users, **D**iscoverability.

Progi: 1–10 niskie, 11–24 średnie, 25–39 wysokie, 40–50 krytyczne.

## 1. Tabela DREAD

| STRIDE | Zagrożenie | Dam. | Repr. | Expl. | Aff. | Disc. | Suma | Poziom |
|--------|-----------|------|-------|-------|------|-------|------|--------|
| S | Podszycie się pod klienta przez formularz logowania | 8 | 7 | 6 | 6 | 7 | **34** | wysokie |
| T | Zmiana ID zgłoszenia albo spreparowane żądanie API | 8 | 8 | 6 | 7 | 7 | **36** | wysokie |
| R | Brak dowodu kto zmienił status lub treść zgłoszenia | 6 | 7 | 5 | 5 | 5 | **28** | wysokie |
| I | Podgląd danych innego klienta (błąd kontroli dostępu) | 9 | 8 | 7 | 8 | 7 | **39** | wysokie |
| D | Przeciążenie formularza zgłoszeń albo API | 7 | 8 | 8 | 9 | 8 | **40** | **krytyczne** |
| E | Uzyskanie uprawnień administratora przez pracownika | 10 | 6 | 6 | 9 | 6 | **37** | wysokie |

## 2. Ranking i priorytety

| Miejsce | Zagrożenie | Suma | Wniosek |
|---------|------------|------|---------|
| 1 | D — Denial of Service | 40 | najpierw zabezpieczyć odporność systemu |
| 2 | I — Information Disclosure | 39 | bardzo ważne, bo chodzi o dane klientów |
| 3 | E — Elevation of Privilege | 37 | duże skutki dla całego systemu |
| 4 | T — Tampering | 36 | ważne, ale po trzech powyższych |
| 5 | S — Spoofing | 34 | do zabezpieczenia razem z logowaniem |
| 6 | R — Repudiation | 28 | niżej w rankingu, ale logi i tak są potrzebne |

Priorytety nie są wybrane na oko — to trzy najwyższe wyniki z tabeli.

## 3. Plan dla trzech najważniejszych zagrożeń

1. **Denial of Service (40)** — rate limiting dla logowania, formularza zgłoszeń
   i API; limit rozmiaru załączników; ograniczenie liczby zgłoszeń z jednego IP;
   captcha dla publicznego formularza; logowanie nietypowo dużej liczby żądań.
2. **Information Disclosure (39)** — sprawdzanie uprawnień po stronie backendu
   przy każdym odczycie zgłoszenia; nie polegamy na ukrywaniu w interfejsie;
   minimalizacja danych w odpowiedziach API i e-mailach.
3. **Elevation of Privilege (37)** — role klient / pracownik / administrator
   sprawdzane zawsze na backendzie; brak zaufania do parametrów roli z frontendu;
   operacje administracyjne tylko dla admina; testy kontroli dostępu.
