import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # delete this after turn debug mode off
    # db = SQL("sqlite:///finance.db")
    # ========================================


    user_id = session['user_id']
    user = db.execute('SELECT * FROM users WHERE id = :id', id=user_id)

    grand_total = 0
    cash = float(user[0]['cash'])
    grand_total += cash

    # Loop portfolios
    rows = db.execute('SELECT * FROM portfolios WHERE user_id = :id', id=user_id)
    portfolios = []

    for r in rows:
        if r['total'] == 0:
            continue
        p = {}
        curr_price = lookup(r['symbol'])['price']
        p['symbol'] = r['symbol']
        p['name'] = r['name']
        p['qty'] = r['total']
        p['price'] = usd(curr_price)
        p['total'] = usd(curr_price * p['qty'])
        grand_total += curr_price * p['qty']
        portfolios.append(p)

    return render_template('index.html', name=user[0]['username'], grand_total=usd(grand_total), cash=usd(cash), portfolios=portfolios)

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_pass():
    """Change password"""

    # delete this after turn debug mode off
    # db = SQL("sqlite:///finance.db")
    # ========================================

    user_id = session['user_id']
    username = db.execute('SELECT username FROM users WHERE id = :id', id=user_id)[0]['username']
    if request.method == 'GET':
        return render_template('change-password.html', name=username)
    else:

        old = request.form.get('previous')
        new = request.form.get('new')
        confirm = request.form.get('confirm')

        if not old or not new or not confirm:
            return apology('fields cannot be empty')
        
        user_pass = db.execute('SELECT hash FROM users WHERE id = :id', id=user_id)[0]['hash']

        if not check_password_hash(user_pass, old):
            return apology('incorrect old password')

        if new != confirm:
            return apology('false input')

        db.execute('UPDATE users SET hash = :pwd WHERE id = :id', pwd=generate_password_hash(new), id=user_id)

        flash('Success change password')
        return redirect('/')


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""


    # delete this after turn debug mode off
    # db = SQL("sqlite:///finance.db")
    # ========================================

    username = db.execute('SELECT username FROM users WHERE id = :id', id=session['user_id'])[0]['username']

    if request.method == 'GET':
        return render_template('buy.html', name=username, symbol=request.args.get('symbol'))
    else:
        symbol = request.form.get('symbol')
        qty = int(request.form.get('shares'))

        if not symbol:
            return apology('please provide symbol')
        elif not qty:
            return apology('please provide shares')
        elif not lookup(symbol):
            return apology('the symbol is not available', 404)

        response = lookup(symbol)
        user_id = session['user_id']
        
        # Check the money is available or not
        user = db.execute('SELECT * FROM users WHERE id = :id', id=user_id)
        curr_money = float(user[0]['cash'])

        if curr_money < qty * response['price']:
            return apology('insufficient fund')
        curr_money -= qty * response['price'] 
        db.execute('UPDATE users SET cash = :money WHERE id = :id', money=curr_money, id=user_id)

        # Update table portfolios
        symbol = symbol.upper()
        portfolios = db.execute('SELECT * FROM portfolios WHERE user_id = :id AND symbol = :symbol', id=user_id, symbol=symbol)

        if len(portfolios) == 0:
            db.execute('INSERT INTO portfolios (user_id, symbol, total, name) VALUES(:id, :symbol, :total, :name)', id=user_id, symbol=symbol, total=qty, name=response['name'])
        else:
            total = int(portfolios[0]['total'])
            total += qty
            db.execute('UPDATE portfolios SET total = :total WHERE user_id = :id AND symbol = :symbol', total=total, id=user_id, symbol=symbol)

        # Insert to table transactions
        db.execute('INSERT INTO transactions (user_id, type, symbol, price, qty) VALUES(:id, "b", :symbol, :price, :qty)', id=user_id, symbol=symbol, price=response['price'], qty=qty)

        flash('Bought!')
        return redirect('/')
        
@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # delete this after turn debug mode off
    # db = SQL("sqlite:///finance.db")
    # ========================================
    
    
    user_id = session['user_id']
    username = db.execute('SELECT username FROM users WHERE id=:id', id=user_id)[0]['username']
    
    history = db.execute('SELECT * FROM transactions WHERE user_id = :id ORDER BY timestamp DESC', id=user_id)
    transactions = []
    for h in history:
        transaction = {}
        transaction['symbol'] = h['symbol']
        transaction['price'] = usd(h['price'])
        transaction['timestamp'] = h['timestamp']
        if h['type'] == 'b':
            transaction['qty'] = h['qty']
        elif h['type'] == 's':
            transaction['qty'] = -1 * h['qty']
        transactions.append(transaction)

    return render_template('history.html', name=username, transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()


    # delete this after turn debug mode off
    # db = SQL("sqlite:///finance.db")
    # ========================================

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
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

    user_id = session['user_id']
    user = db.execute('SELECT * FROM users WHERE id = :id', id=user_id)

    if request.method == 'GET':
        return render_template('quote.html', name=user[0]['username'])
    else:
        symbol = request.form.get('quote')

        if not symbol:
            return apology('missing symbol', 400)

        symbol = symbol.upper()
        response = lookup(symbol)

        if not response:
            return apology("sorry, something's wrong", 404)

        return render_template('quoted.html', name=user[0]['username'], symbol_name=response['name'], symbol=response['symbol'], price=usd(response['price']))
        

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    session.clear()

    if request.method == 'GET':
        return render_template('register.html')
    else:
        if not request.form.get("username"):
            return apology("must provide username", 403)
        elif len(db.execute('SELECT * FROM users WHERE username = :username', username=request.form.get("username"))) == 1:
            return apology('username already exists', 403)
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation", 403)
        elif request.form.get('password') != request.form.get('confirmation'):
            return apology("passwords don't match", 400)

        password = generate_password_hash(request.form.get('password'))

        db.execute('INSERT INTO users (username, hash) VALUES(:username, :password)', username=request.form.get('username'), password=password)

        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username")) 

        session["user_id"] = rows[0]["id"]    
        flash('Registered!')
        return redirect('/')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # delete this after turn debug mode off
    # db = SQL("sqlite:///finance.db")
    # ======================================== 


    user_id = session['user_id']
    user = db.execute('SELECT * FROM users WHERE id = :id', id=user_id)

    if request.method == 'GET':
        portfolios = db.execute('SELECT symbol, total FROM portfolios WHERE user_id = :id', id=session['user_id'])

        stocks = [p['symbol'] for p in portfolios if p['total'] != 0]

        return render_template('sell.html', name=user[0]['username'], stocks=stocks, symbol=request.args.get('symbol'))
    else:
        user_id = session['user_id']
        symbol = request.form.get('symbol')
        qty = request.form.get('shares')

        if not symbol:
            return apology('missing symbol')
        elif not qty:
            return apology('shares must be filled')
        qty = int(qty)
        # Quantity overflows
        stock = db.execute('SELECT * FROM portfolios WHERE user_id = :id AND symbol = :symbol', id=user_id, symbol=symbol)
        if qty > stock[0]['total']:
            return apology('invalid shares input')

        # Sell valid shares
        curr_qty = stock[0]['total']
        curr_qty -= qty

        db.execute('UPDATE portfolios SET total = :qty WHERE user_id = :id AND symbol = :symbol', qty=curr_qty, id=user_id, symbol=symbol)

        # Update cash
        price = float(lookup(symbol)['price'])
        user = db.execute('SELECT cash FROM users WHERE id = :id', id=user_id)
        cash = user[0]['cash']
        cash += qty * price
        db.execute('UPDATE users SET cash = :cash WHERE id = :id', cash=cash, id=user_id)

        # Insert transactions table
        db.execute('INSERT INTO transactions (user_id, symbol, price, qty, type) VALUES(:id, :symbol, :price, :qty, "s")', id=user_id, symbol=symbol, price=price, qty=qty)

        flash('Sold!')
        return redirect('/')

@app.route('/add-cash', methods=['GET', 'POST'])
@login_required
def add_cash():

    # delete this after turn debug mode off
    # db = SQL("sqlite:///finance.db")
    # ======================================== 

    user_id = session['user_id']
    user = db.execute('SELECT * FROM users WHERE id=:id', id=user_id)[0]
    cash = user['cash']
    username = user['username']

    if request.method == 'GET':
        return render_template('add-cash.html', name=username, cash=usd(cash))
    else:
        topup = float(request.form.get('topup'))
        cash += topup
        db.execute('UPDATE users SET cash = :cash WHERE id = :id', cash=cash, id=user_id)

        flash('Cash updated!')
        return redirect('/')


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
