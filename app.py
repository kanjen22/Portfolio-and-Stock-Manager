import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
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
    stocks = db.execute(
        "SELECT T.symbol AS symbol, T.symbol AS name, SUM(T.count * T.type) AS shares \
        FROM 'transaction' AS T \
        WHERE T.id = ? \
        GROUP BY T.symbol \
        HAVING SUM(T.count * T.type) > 0",
        session["user_id"],
    )
    stock_total = 0
    for stock in stocks:
        single_stock = lookup(stock["symbol"])["price"]
        stock["price"] = usd(single_stock)
        stock["total"] = usd(single_stock * stock["shares"])
        stock_total += single_stock * stock["shares"]
    # get cash
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = cash[0]["cash"]
    # calculate total
    total = cash + stock_total
    return render_template(
        "index.html", stocks=stocks, cash=usd(cash), total=usd(total)
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        stock_quote = lookup(symbol)
        if not symbol or not stock_quote:
            flash("invalid symbol")
            return redirect("/buy")
        shares = request.form.get("shares")
        try:
            shares = int(shares)
            if shares <= 0:
                flash("invalid shares")
                return redirect("/buy")
        except TypeError as e:
            flash("invalid shares: ", e)
            return redirect("/buy")
        # check if user has enough money
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = cash[0]["cash"]
        total_cash = stock_quote["price"] * shares
        if cash < total_cash:
            flash(f"not enough cash! You have only {usd(cash)} but need {usd(stock_quote["price"] * shares)}")
            return redirect("/buy")
        # update cash
        cash -= total_cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])
        # update history
        db.execute(
            "INSERT INTO 'transaction' (id, symbol, price, count, type, time) VALUES (?, ?, ?, ?, ?, ?)",
            session["user_id"],
            symbol,
            stock_quote["price"],
            shares,
            1,
            datetime.now(),
        )
        flash(f"transaction complete! purchased {str(shares)} shares of {symbol}.")
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute(
        "SELECT T.symbol AS symbol, T.symbol AS name, T.type as type, \
            T.count AS shares, T.price AS price, T.time AS time \
        FROM 'transaction' AS T \
        WHERE T.id = ?",
        session["user_id"],
    )
    for transaction in transactions:
        transaction["type"] = "bought" if transaction["type"] == 1 else "sold"
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            flash("must provide username")
            return render_template("login.html")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("must provide password")
            return render_template("login.html")

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        ### how does password hashing work? ###
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            flash("invalid username and/or password")
            return render_template("login.html")

        # Remember which user has logged in
        ### so session data has to be alive for multiple clients?? ###
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        message = request.args.get("message")
        if message:
            flash(message)
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
    if request.method == "GET":
        return render_template("quote.html", method="GET")
    else:
        symbol = request.form.get("symbol")
        stock_quote = lookup(symbol)
        stock_quote["price"] = usd(stock_quote["price"])
        if not stock_quote:
            flash("invalid symbol")
            return redirect("/quote")
        return render_template("quote.html", method="POST", quote=stock_quote)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        rows = db.execute("SELECT username FROM users")
        # Extract usernames into a list
        usernames = [row["username"] for row in rows]
        # Ensure username was submitted and not already taken
        if not request.form.get("username"):
            flash("must provide username")
            return redirect("/register")
        elif request.form.get("username") in usernames:
            flash("username already exists")
            return redirect("/register")
        # Ensure password and confirmation were submitted
        elif not request.form.get("password") or not request.form.get("confirmation"):
            flash("must provide both password and confirmation")
            return redirect("/register")
        elif request.form.get("password") != request.form.get("confirmation"):
            flash("passwords do not match")
            return redirect("/register")
        # Insert new username and password
        pwd_hash = generate_password_hash(request.form.get("password"))
        db.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)",
            request.form.get("username"),
            pwd_hash,
        )

        # Redirect user to home page
        return redirect(url_for("login", message="registration successful"))

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        stocks = db.execute(
            "SELECT T.symbol AS symbol, \
                SUM(T.count) AS shares \
            FROM 'transaction' AS T \
            WHERE T.id = ? \
            GROUP BY T.symbol",
            session["user_id"],
        )
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        stock_quote = lookup(symbol)
        # invalid shares
        try:
            shares = int(shares)
            if shares <= 0:
                flash("invalid shares, no less than 1")
                return redirect("/sell")
        except TypeError as e:
            flash("invalid shares: ", e)
            return redirect("/sell")
        # invalid symbol
        if not symbol or not stock_quote:
            flash("invalid symbol")
            return redirect("/sell")
        # not enough shares
        for stock in stocks:
            if symbol == stock["symbol"] and shares > stock["shares"]:
                flash(f"not enough shares of {symbol} to sell. You have {shares} and need {stock["shares"]}")
                return redirect("/sell")
        # no share
        if symbol not in [stock["symbol"] for stock in stocks]:
            flash(f"you have no share of {symbol}")
            return redirect("/sell")
        #### sell stock ####
        # update user's cash
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        cash += stock_quote["price"] * shares
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])
        # insert sell transaction
        db.execute(
            "INSERT INTO 'transaction' (id, symbol, price, count, type, time) VALUES (?, ?, ?, ?, ?, ?)",
            session['user_id'],
            symbol,
            stock_quote["price"],
            shares,
            -1,
            datetime.now(),
        )
        return redirect("/")
    else:
        return render_template("sell.html")
