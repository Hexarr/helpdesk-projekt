# Tydzień 2 — Scenariusze zagrożeń, wymagania bezpieczeństwa i OWASP Top 10

## 1. Scenariusze zagrożeń

### Scenariusz 1 — misuse case: podgląd cudzego zgłoszenia
- **Aktor:** pracownik helpdesku
- **Motyw:** chce szybciej sprawdzić dane klienta albo robi to z ciekawości
- **Cel:** dostęp do zgłoszenia innego klienta bez uprawnień
- **Kroki:** loguje się → otwiera swoje zgłoszenie → zmienia identyfikator zgłoszenia w URL → system nie sprawdza uprawnień → wyświetla się cudze zgłoszenie
- **Naruszony element CIA:** poufność

### Scenariusz 2 — atak: brute force na konto klienta
- **Aktor:** zewnętrzny atakujący
- **Motyw:** przejęcie konta klienta i dostęp do jego danych
- **Cel:** zalogowanie się na cudze konto
- **Kroki:** zdobywa email klienta → próbuje wiele haseł → system nie ogranicza prób → konto nie jest blokowane → trafia poprawne hasło → loguje się
- **Naruszony element CIA:** poufność i integralność

### Scenariusz 3 — atak: przeciążenie systemu zgłoszeniami
- **Aktor:** zewnętrzny atakujący lub bot
- **Motyw:** utrudnienie działania firmy, zablokowanie dostępu prawdziwym użytkownikom
- **Cel:** obniżenie wydajności lub całkowite zablokowanie systemu
- **Kroki:** automatycznie wysyła dużo zgłoszeń i żądań do API → backend próbuje wszystko obsłużyć → baza przeciążona → system przestaje odpowiadać
- **Naruszony element CIA:** dostępność

## 2. Wymagania bezpieczeństwa

| Wymaganie | Uzasadnienie | Scenariusz |
|-----------|--------------|------------|
| System musi ograniczać liczbę prób logowania | blokuje zgadywanie hasła po kilku próbach | 2 |
| System musi walidować dane wejściowe (backend i frontend) | chroni przed wstrzyknięciem złośliwego kodu (np. XSS) | 1 i inne |
| System musi sprawdzać uprawnienia przy każdym odczycie zgłoszenia | backend weryfikuje, czy użytkownik ma prawo zobaczyć zgłoszenie | 1 |
| Hasła muszą być przechowywane w postaci hashy | po wycieku bazy hasła nie są jawne | 2 |
| System musi używać HTTPS dla całej komunikacji | chroni dane w trakcie przesyłania | 2 i transmisja |
| Rate limiting dla formularza zgłoszeń i API | ogranicza liczbę żądań z jednego IP | 3 |
| System musi logować zdarzenia bezpieczeństwa | pozwala wykrywać i analizować ataki | 2, 3 |
| E-maile nie mogą zawierać pełnych danych wrażliwych | wiadomość może trafić do niepowołanej osoby | 1 i ujawnienie danych |

## 3. Mapowanie na OWASP Top 10

| Wymaganie | Kategoria OWASP | Uzasadnienie |
|-----------|-----------------|--------------|
| Limit prób logowania | Identification and Authentication Failures | brak ochrony przed zgadywaniem haseł |
| Walidacja danych wejściowych | Injection | brak walidacji może prowadzić do wstrzyknięcia kodu |
| Kontrola dostępu do zgłoszeń | Broken Access Control | użytkownik może dostać się do cudzych danych |
| Hashowanie haseł | Cryptographic Failures | złe przechowywanie danych wrażliwych zwiększa skutki wycieku |
| HTTPS | Cryptographic Failures | brak szyfrowania transmisji = możliwe przechwycenie |
| Rate limiting | Security Misconfiguration | brak limitów ułatwia przeciążenie i nadużycia |
| Logowanie zdarzeń | Security Logging and Monitoring Failures | brak logów utrudnia wykrywanie incydentów |
| Ograniczenie danych w e-mailach | pośrednio: Cryptographic Failures | dotyczy ochrony danych wrażliwych poza systemem |
