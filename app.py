import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import time

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    rows = db.execute("SELECT * FROM stock WHERE user_id = ?", session["user_id"])
    cash = db.execute("SELECT cash FROM users WHERE id = ?;", session["user_id"])[0]["cash"]
    total = cash
    for row in rows:
        row["price"] = lookup(row["symbol"])["price"]
        total += row["price"] * row["share"]

    return render_template("index.html", rows=rows, cash=cash, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        try:
            stockSymbol = lookup(request.form.get("symbol"))
            shares = int(request.form.get("shares"))
        except:
            shares = 0

        if not stockSymbol:
            return apology("must give a valid stock symbol")
        elif shares < 1:
            return apology("must give a valid number of shares")

        cash = db.execute("SELECT cash FROM users WHERE id = ?;", session["user_id"])[0]["cash"]

        if cash < stockSymbol["price"] * shares:
            return apology("user cannot afford the number of shares at the current price")

        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - (stockSymbol["price"] * shares), session["user_id"])

        totalShares = db.execute("SELECT share FROM stock WHERE user_id = ? AND symbol = ?",
                                 session["user_id"], stockSymbol["symbol"])[0]["share"]

        if not totalShares:
            db.execute("INSERT INTO stock(user_id, symbol, share) VALUES(?, ?, ?)",
                       session["user_id"], stockSymbol["symbol"], shares)
        else:
            db.execute("UPDATE stock SET share = ? WHERE user_id = ? AND symbol = ?",
                       totalShares + shares, session["user_id"], stockSymbol["symbol"])

        timestamp = time.time()
        current_date = time.ctime(timestamp)

        db.execute("INSERT INTO history(user_id, type, symbol, share, value, data) VALUES(?, ?, ?, ?, ?, ?)",
                   session["user_id"], "buy", stockSymbol["symbol"], shares, stockSymbol["price"] * shares, current_date)

        return redirect("/")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute("SELECT * FROM history WHERE user_id = ?", session["user_id"])
    return render_template("history.html", rows=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("must pass a stock symbol", 403)

        return render_template("quote.html", symbol=lookup(symbol))

    return render_template("quote.html", symbol=lookup(""))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("must provide username", 403)
        elif not password or not confirmation:
            return apology("must provide password and password confirmation", 403)
        elif password != confirmation:
            return apology("password and password confirmation must be equal", 403)
        elif len(db.execute("SELECT * FROM users WHERE username = ?", username)) != 0:
            return apology("select username is already in use", 403)

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(password))

        return redirect("/")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        try:
            stockSymbol = lookup(request.form.get("symbol"))
            shares = int(request.form.get("shares"))
        except:
            shares = 0

        if not stockSymbol:
            return apology("must give a valid stock symbol")
        elif shares < 1:
            return apology("must give a valid number of shares")

        actualShares = db.execute("SELECT share FROM stock WHERE user_id = ? AND symbol = ?",
                                  session["user_id"], stockSymbol["symbol"])[0]["share"]

        if actualShares < shares:
            return apology("user dont have that share of that symbol")

        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + (stockSymbol["price"] * shares), session["user_id"])

        if actualShares == shares:
            db.execute("DELETE FROM stock WHERE user_id = ? AND symbol = ?", session["user_id"], stockSymbol["symbol"])
        else:
            db.execute("UPDATE stock SET share = ? WHERE user_id = ? AND symbol = ?",
                       actualShares - shares, session["user_id"], stockSymbol["symbol"])

        timestamp = time.time()
        current_date = time.ctime(timestamp)

        db.execute("INSERT INTO history(user_id, type, symbol, share, value, data) VALUES(?, ?, ?, ?, ?, ?)",
                   session["user_id"], "sell", stockSymbol["symbol"], shares, stockSymbol["price"] * shares, current_date)

        return redirect("/")

    return render_template("sell.html")


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    if request.method == "POST":

        username = request.form.get("username")
        oldPassword = request.form.get("oldPassword")
        newPassword = request.form.get("newPassword")
        confirmation = request.form.get("confirmation")

        hash = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]["hash"]

        if not username:
            return apology("must provide username", 403)
        elif username != db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]:
            return apology("must provide the acount username", 403)
        elif not oldPassword or not confirmation or not newPassword:
            return apology("must provide the old password the new password and the confirmation", 403)
        elif not check_password_hash(hash, oldPassword):
            return apology("actual password of account in invalid", 403)
        elif newPassword != confirmation:
            return apology("new password and password confirmation must be equal", 403)
        elif newPassword == oldPassword:
            return apology("new password is equal to the old password")

        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(newPassword), session["user_id"])

        return redirect("/")

    return render_template("password.html")
