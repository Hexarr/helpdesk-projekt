# Pierwotna wersja od AI - CELOWO zostawiona jako przykład do analizy bezpieczenstwa.
# Ten kod NIE jest wersja produkcyjna - zawiera celowe podatnosci.

from flask import Flask, request, redirect, render_template_string, session
import sqlite3

app = Flask(__name__)
# Blad: klucz sesji na stale wpisany w kod, latwy do odgadniecia
app.secret_key = "helpdesk123"
DB = "helpdesk.db"

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head><title>Logowanie - Helpdesk</title></head>
<body>
<h2>Logowanie Helpdesk</h2>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<form method="post" action="/login">
  <input name="email" placeholder="email"><br>
  <input name="password" placeholder="haslo" type="password"><br>
  <button type="submit">Zaloguj</button>
</form>
</body>
</html>
"""

PANEL_HTML = """
<!DOCTYPE html>
<html>
<head><title>Panel - Helpdesk</title></head>
<body>
<h2>Panel uzytkownika</h2>
<p>Zalogowano jako: {{ email }}</p>
<a href="/zgloszenia">Moje zgloszenia</a> |
<a href="/nowe_zgloszenie">Nowe zgloszenie</a> |
<a href="/logout">Wyloguj</a>
</body>
</html>
"""

# Blad XSS: zgloszenia wyswietlane bez escape'owania przez |safe
ZGLOSZENIA_HTML = """
<!DOCTYPE html>
<html>
<head><title>Zgloszenia - Helpdesk</title></head>
<body>
<h2>Twoje zgloszenia</h2>
<a href="/nowe_zgloszenie">Nowe zgloszenie</a> |
<a href="/logout">Wyloguj</a>
<hr>
{% for z in zgloszenia %}
  <div>
    <b>Tytul:</b> {{ z[1]|safe }}<br>
    <b>Opis:</b> {{ z[2]|safe }}<br>
    <b>Priorytet:</b> {{ z[3] }}<br>
    <hr>
  </div>
{% endfor %}
</body>
</html>
"""

# Blad CSRF: brak tokenu CSRF w formularzu
NOWE_ZGLOSZENIE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Nowe zgloszenie - Helpdesk</title></head>
<body>
<h2>Nowe zgloszenie</h2>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
{% if sukces %}<p style="color:green">{{ sukces }}</p>{% endif %}
<form method="post" action="/nowe_zgloszenie">
  <label>Tytul:</label><br>
  <input name="tytul" type="text" size="50"><br><br>
  <label>Opis:</label><br>
  <textarea name="opis" rows="5" cols="50"></textarea><br><br>
  <label>Priorytet:</label><br>
  <select name="priorytet">
    <option value="niski">Niski</option>
    <option value="sredni">Sredni</option>
    <option value="wysoki">Wysoki</option>
  </select><br><br>
  <button type="submit">Wyslij zgloszenie</button>
</form>
<a href="/zgloszenia">Wróc do listy</a>
</body>
</html>
"""


def init_db():
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT, password TEXT, role TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS zgloszenia (id INTEGER PRIMARY KEY, tytul TEXT, opis TEXT, priorytet TEXT, user_email TEXT)")
    cur.execute("DELETE FROM users")
    # Blad: haslo zapisane jawnie (plain text)
    cur.execute("INSERT INTO users VALUES (1, 'admin@sklep.pl', 'admin123', 'admin')")
    cur.execute("INSERT INTO users VALUES (2, 'klient@sklep.pl', 'klient123', 'client')")
    con.commit()
    con.close()


@app.route("/")
def index():
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")

        con = sqlite3.connect(DB)
        cur = con.cursor()
        # PODATNOSC SQL INJECTION: konkatenacja stringa bez walidacji
        query = "SELECT id, email, role FROM users WHERE email = '" + email + "' AND password = '" + password + "'"
        cur.execute(query)
        user = cur.fetchone()
        con.close()

        if user:
            session["email"] = user[1]
            session["role"] = user[2]
            return redirect("/panel")
        error = "Bledny login lub haslo"

    return render_template_string(LOGIN_HTML, error=error)


@app.route("/panel")
def panel():
    if "email" not in session:
        return redirect("/login")
    return render_template_string(PANEL_HTML, email=session["email"])


@app.route("/zgloszenia")
def zgloszenia():
    if "email" not in session:
        return redirect("/login")

    con = sqlite3.connect(DB)
    cur = con.cursor()
    # Blad: brak filtrowania po uzytowniku - kazdy zalogowany widzi wszystkie zgloszenia
    # Blad SQL Injection: email z sesji bezposrednio w query
    query = "SELECT id, tytul, opis, priorytet FROM zgloszenia WHERE user_email = '" + session["email"] + "'"
    cur.execute(query)
    wyniki = cur.fetchall()
    con.close()

    # Blad XSS: dane wyswietlane z |safe - nie sa escapowane
    return render_template_string(ZGLOSZENIA_HTML, zgloszenia=wyniki)


@app.route("/nowe_zgloszenie", methods=["GET", "POST"])
def nowe_zgloszenie():
    if "email" not in session:
        return redirect("/login")

    error = None
    sukces = None

    if request.method == "POST":
        tytul = request.form.get("tytul", "")
        opis = request.form.get("opis", "")
        priorytet = request.form.get("priorytet", "niski")

        # Brak walidacji dlugosci i tresci

        con = sqlite3.connect(DB)
        cur = con.cursor()
        # PODATNOSC SQL INJECTION: konkatenacja zamiast parametrow
        query = "INSERT INTO zgloszenia (tytul, opis, priorytet, user_email) VALUES ('" + tytul + "', '" + opis + "', '" + priorytet + "', '" + session["email"] + "')"
        cur.execute(query)
        con.commit()
        con.close()

        sukces = "Zgloszenie zostalo dodane!"

    return render_template_string(NOWE_ZGLOSZENIE_HTML, error=error, sukces=sukces)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5001)
