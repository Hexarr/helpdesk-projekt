# Tydzień 3 — Diagram przepływu danych (DFD) i analiza STRIDE

## 1. Diagram przepływu danych (DFD)

```
 [Użytkownik końcowy]                      [Administrator systemu]
  (zewnętrzna encja)                         (zewnętrzna encja)
         |                                          |
         | dane logowania, nowe zgłoszenie,         | logowanie admina,
         | komentarz, sprawdzenie statusu           | zarządzanie użytkownikami
         v                                          v
              ( Przeglądarka internetowa )  <- proces
                        |        ^
        żądania HTTPS:  |        |  status zgłoszenia,
        dane logowania, |        |  odpowiedzi,
        nowe zgłoszenie |        |  lista zgłoszeń
- - - - - - - - - - - - | - - - -|- - -  Granica zaufania 1: Internet / sieć publiczna
                        v        |
                ( Serwer aplikacji )  <- proces
                        |        ^
         zapytania SQL: |        |  wyniki zapytań:
         zapis/odczyt   |        |  dane użytkownika,
         zgłoszeń       |        |  zgłoszenia, logi
- - - - - - - - - - - - | - - - -|- - -  Granica zaufania 2: strefa aplikacji / strefa danych
                        v        |
                  [[ Baza danych ]]  <- magazyn danych
```

### Elementy diagramu

| Element | Typ DFD | Rola |
|---------|---------|------|
| Użytkownik końcowy | zewnętrzna encja | klient sklepu: loguje się, tworzy zgłoszenia, czyta odpowiedzi |
| Administrator systemu | zewnętrzna encja | zarządza systemem, kontami i uprawnieniami |
| Przeglądarka internetowa | proces | interfejs użytkownika, wysyła dane do serwera |
| Serwer aplikacji | proces | logika: logowanie, role, zgłoszenia, walidacja, dostęp do bazy |
| Baza danych | magazyn danych | konta, hashe haseł, zgłoszenia, statusy, logi |

### Granice zaufania

| Granica | Gdzie | Dlaczego ważna |
|---------|-------|----------------|
| Internet / sieć użytkownika | przeglądarka ↔ serwer aplikacji | dane przechodzą przez niezaufaną sieć → HTTPS + walidacja po stronie serwera |
| Strefa aplikacji / strefa danych | serwer aplikacji ↔ baza danych | baza trzyma dane wrażliwe, dostęp ma tylko backend |

## 2. Analiza STRIDE

| STRIDE | Komponent | Zagrożenie | CIA | Mitygacja |
|--------|-----------|------------|-----|-----------|
| **S** — Spoofing | formularz logowania | podszycie się pod klienta (wykradzione/odgadnięte hasło) | poufność, integralność | limit prób logowania, silne hasła, MFA dla adminów, logowanie nieudanych prób |
| **T** — Tampering | API zgłoszeń | zmiana ID zgłoszenia / spreparowane żądanie zmienia cudze zgłoszenie | integralność | sprawdzanie uprawnień na backendzie przy każdej operacji, walidacja, logowanie zmian |
| **R** — Repudiation | logi zdarzeń | pracownik zmienia status i twierdzi, że tego nie zrobił | integralność | audyt logów (kto, kiedy, co); logi zabezpieczone przed edycją |
| **I** — Information Disclosure | baza danych / lista zgłoszeń | użytkownik widzi dane innego klienta przez błąd kontroli dostępu | poufność | kontrola dostępu na backendzie, filtrowanie po właścicielu, minimalizacja danych w API i e-mailach |
| **D** — Denial of Service | formularz zgłoszeń / API | bot wysyła masę zgłoszeń, system przestaje odpowiadać | dostępność | rate limiting, captcha, limity rozmiaru załączników, monitoring obciążenia |
| **E** — Elevation of Privilege | moduł ról / panel admina | pracownik zdobywa uprawnienia administratora przez modyfikację parametru roli | poufność, integralność | RBAC na backendzie, brak zaufania do parametrów z frontendu, testy kontroli dostępu |

**Podsumowanie:** najważniejsze ryzyka to dostęp do cudzych zgłoszeń, przejęcie
konta, wyciek danych klientów i przeciążenie systemu. Najwięcej zabezpieczeń
powinno być po stronie backendu, bo frontend można łatwo zmienić albo ominąć.
