from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from passlib.apps import custom_app_context as pwd_context
from tempfile import mkdtemp

from helpers import *

# configure application
app = Flask(__name__)

# ensure responses aren't cached
if app.config["DEBUG"]:
    @app.after_request
    def after_request(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Expires"] = 0
        response.headers["Pragma"] = "no-cache"
        return response

# custom filter
app.jinja_env.filters["usd"] = usd

# configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

@app.route("/")
@login_required
def index():
    """Show portfolio"""

    # get user's cash
    user_cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])

    # get sum of price and shares
    companies = db.execute("SELECT symbol, price, SUM(share) FROM history WHERE id = :id GROUP BY symbol ORDER BY symbol",
        id=session["user_id"])

    # format total of each stock bought, cost of each share, and get total of all companies' stock bough.
    total_companies = 0.00
    for company in companies:
        total = company["price"] * float(company["SUM(share)"])
        db.execute("UPDATE history SET price_formatted = :price_formatted, total_formatted = :total_formatted WHERE id = :id AND symbol = :symbol",
            id=session["user_id"], price_formatted=usd(company["price"]), total_formatted=usd(total), symbol=company["symbol"])
        total_companies = total_companies + total

    # get each bought companies info
    companies_new = db.execute("SELECT symbol, name, price, SUM(share) AS shares, price_formatted, total_formatted FROM history WHERE id = :id GROUP BY symbol ORDER BY symbol",
        id=session["user_id"])

    # calculate grand total
    grand_total = user_cash[0]["cash"] + total_companies

    # render template with info
    return render_template("index.html", user_cash=usd(user_cash[0]["cash"]), companies=companies_new, grand_total=usd(grand_total))

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock."""

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        symbol = request.form.get("symbol")

        # return apology if numbers entered in symbol input
        if any(c.isdigit() for c in symbol):
            return apology("No numbers in symbol input")

        # return aplogy if no input for symbol
        elif symbol == "":
            return apology("Didn't enter symbol")

        # return apology if input for shares is empty
        shares = request.form.get("shares")
        if not shares:
            return apology("Didn't enter shares")

        # return apology if any letters entered in shares input
        elif any(n.isalpha() for n in shares):
            return apology("No letter in shares input")

        # return apology if number of shares are less than 1
        elif int(shares) < 1:
            return apology("You need to enter more shares")

        # get quote
        quote = lookup(symbol)

        # return apology if input for symbol is empty
        if not quote:
            return apology("Didn't enter correct symbol")

        # find price of shares
        price = float(shares) * quote["price"]

        # get cash from user
        cash = db.execute("SELECT cash FROM users WHERE id = :session_id", session_id=session["user_id"])

        # update user's $$$ after spending $$$$
        if cash[0]["cash"] >= price:
            db.execute("UPDATE users SET cash = cash - :price WHERE id = :session_id", price=price, session_id=session["user_id"])

            # update user's history
            db.execute("INSERT INTO history (id, symbol, share, price, name) VALUES(:session_id, :symbol, :share, :price, :name)",
                session_id=session["user_id"], symbol=symbol, share=request.form.get("shares"), price=quote["price"], name=quote["name"])

        # return apology if user doesn't have enough money :(
        else:
            return apology("You don't have enough money")

        return redirect(url_for("index"))

    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions."""

    # get stock info
    history = db.execute("SELECT symbol, share, price, transacted FROM history WHERE id = :id GROUP BY transacted ORDER BY transacted",
        id=session["user_id"])

    # render template with info
    return render_template("history.html", history=history)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in."""

    # forget any user_id
    session.clear()

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")

        # query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # ensure username exists and password is correct
        if len(rows) != 1 or not pwd_context.verify(request.form.get("password"), rows[0]["hash"]):
            return apology("invalid username and/or password")

        # remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # redirect user to home page
        return redirect(url_for("index"))

    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out."""

    # forget any user_id
    session.clear()

    # redirect user to login form
    return redirect(url_for("login"))

@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # return apology if no symbol entered
        if not request.form.get("symbol"):
            return apology("Didn't enter symbol")

        # get quote
        quote = lookup(request.form.get("symbol"))

        # return apology if symbol doesn't exist
        if not quote:
            return apology("Symbol doesn't exist")

        # return page with quote
        return render_template("quoted.html", name=quote["name"], symbol=quote["symbol"], price=usd(quote["price"]))

    # else if user reached route via GET (as by clicking a link or via redirect)
    else :
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user."""

    # if submitted a form at register
    if request.method == "POST":
        # return apology if username not filled in form
        if not request.form.get("username"):
            return apology("Missing username!")

        # return apology if password not filled in form
        elif not request.form.get("password"):
            return apology("Missing password!")

        # return apology if password and confirmation don't match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Password and confirmation don't match!")

        # hash the password
        hashPwd = pwd_context.hash(request.form.get("password"))

        # insert username and password into database
        result = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hashPwd)",
                    username=request.form.get("username"), hashPwd=hashPwd)

        # return apology if username exists
        if not result:
            return apology("Username exists!")

        # store user id in session
        session["user_id"] = result

        # redirect user to home page
        return redirect(url_for("index"))

    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock."""
    if request.method == "POST":
        # return apology if numbers entered in symbol input
        symbol = request.form.get("symbol")
        if any(c.isdigit() for c in symbol):
            return apology("No numbers in symbol input")

        # return aplogy if no input for symbol
        elif symbol == "":
            return apology("Didn't enter symbol")

        # return apology if input for shares is empty
        shares = request.form.get("shares")
        if not shares:
            return apology("Didn't enter shares")

        # return apology if any letters entered in shares input
        elif any(n.isalpha() for n in shares):
            return apology("No letter in shares input")

        # return apology if number of shares are less than 1
        elif int(shares) < 1:
            return apology("You need to enter more shares")

        # get quote
        quote = lookup(request.form.get("symbol"))

        # return apology if input for symbol is empty
        if not quote:
            return apology("Didn't enter correct symbol")

        # make shares negative to subtract from total shares in database
        shares_neg = -1 * int(request.form.get("shares"))

        # get shares from user
        user_shares = db.execute("SELECT SUM(share) FROM history WHERE id = :id AND symbol = :symbol", id=session["user_id"],
            symbol=quote["symbol"])

        # return apology if not enough shares to sell
        if user_shares[0]["SUM(share)"] < int(request.form.get("shares")):
            return apology("You don't have enough shares to sell")

        # update user cash
        price = quote["price"] * float(request.form.get("shares"))
        db.execute("UPDATE users SET cash = cash + :price WHERE id = :id", price=price, id=session["user_id"])

        # insert new data into user's history
        db.execute("INSERT INTO history (symbol, share, price, id, name) VALUES(:symbol, :share, :price, :id, :name)",
            symbol=quote["symbol"], share=shares_neg, price=quote["price"], id=session["user_id"], name=quote["name"])

        # redirect to index
        return redirect(url_for("index"))

    # if request is by GET
    else:
        return render_template("sell.html")

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change user's password."""

    # if got to route by POST
    if request.method == "POST":
        # get old password
        old_pass = db.execute("SELECT hash FROM users WHERE id = :id", id=session["user_id"])

        # return apology if no old password entered
        if not request.form.get("old_password"):
            return apology("No old password entered")

        # return apology if no new/confirmation password entered
        elif request.form.get("new_password") == "" or request.form.get("confirmation") == "":
            return apology("No new/confirmation password entered")

        # return apology if new password and confirmation don't match
        elif request.form.get("new_password") != request.form.get("confirmation"):
            return apology("New password and confirmation don't match")

        # return apology if wrong password entered
        elif not pwd_context.verify(request.form.get("old_password"), old_pass[0]["hash"]):
            return apology("Wrong password entered")

        # hash new password
        hash_pass = pwd_context.hash(request.form.get("new_password"))

        # update password
        db.execute("UPDATE users SET hash = :hash WHERE id = :id", hash=hash_pass, id=session["user_id"])

        # redirect to index page
        return redirect(url_for("index"))

    # render change page if route is GET
    else:
        return render_template("change.html")
