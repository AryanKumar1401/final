import os
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helper import apology, login_required


# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///home.db")

@app.route("/")
@login_required
def homepage():
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        #ensure username input
        if not request.form.get("username"):
            return apology("must provide username", 400)

        elif not request.form.get("password"):
            return apology("must provide passwords", 400)

        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("Password do not match")


        hash = generate_password_hash(request.form.get("password"))
        new_user_id = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                             username = request.form.get("username"), hash = hash)

        if not new_user_id:
            return apology("username taken", 400)

        session["user_id"] = new_user_id


        #display flash message
        flash("Registered!")

        return redirect(url_for("homepage"))

    else:
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        rows = db.execute("SELECT * FROM users WHERE username = :username", username = request.form.get("username"))

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("Invalid username and/or password!", 400)
        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:
        return render_template("login.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/addentry", methods=["GET", "POST"])
@login_required
def addentry():
    if request.method == "POST":

        db.execute("INSERT INTO entries (user_id, title, entry) VALUES(:user_id, :title, :entry)",
        user_id = session['user_id'],
        title=request.form.get("title"),
        entry = request.form.get("entry")
        )
        flash("Done!")
        return redirect("/")
    else:
        return render_template("addentry.html")

@app.route("/contacts")
@login_required
def contacts():
    return render_template("contacts.html")
    
@app.route("/history")
@login_required
def history():
    entries = db.execute("SELECT title, date, entry FROM entries WHERE user_id = :user_id", user_id = session["user_id"])
    

