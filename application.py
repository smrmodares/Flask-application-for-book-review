import os
import requests

res = requests.get("https://www.goodreads.com/book/review_counts.json", params={"key": "pNXqsEFLzAUImM9gNDJ0g", "isbns": "9781632168146"})
print(res.json())

from flask import Flask, flash, session, render_template, request, redirect, jsonify
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

app = Flask(__name__)

# Check for environment variable
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database
engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))

def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Log user in"""

    if request.method == "POST":

        # Forget any user_id
        session.clear()

        # Check inputs
        if not request.form.get("username"):
            return render_template("error.html", message="Username missing!")

        elif not request.form.get("password"):
            return render_template("error.html", message="Password missing!")

        elif not request.form.get("confirmation"):
            return render_template("error.html", message="Password confirmation missing!")

        elif request.form.get("password") != request.form.get("confirmation"):
            return render_template("error.html", message="Password and confirmation don't match!")

        elif not request.form.get("email"):
            return render_template("error.html", message="Email missing!")

        # Hash the password
        hash = hash=generate_password_hash(request.form.get("password"))


        username = request.form.get("username")
        # Check if this username exist
        exist = db.execute("SELECT user_id FROM users WHERE username = :username", {"username": username}).fetchone()

        if not exist:
            # Insert user to the database
            db.execute("INSERT INTO users (username, password, email) VALUES (:username, :hash, :email)",
                                {"username": username, "hash": hash, "email": request.form.get("email")})
            db.commit()

            # Remember which user has logged in
            uid = db.execute("SELECT user_id FROM users WHERE username = :username",
                             {"username": username}).fetchone()

            session["user_id"] = uid[0]
            flash("Registerd!")
            return redirect("/")

        else:
            return render_template("error.html", message="Username is taken.")

    # If method is GET
    else:
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":

        # Forget any user_id
        session.clear()

        if not request.form.get("username"):
            return render_template("error.html", message="Username missing!")

        elif not request.form.get("password"):
            return render_template("error.html", message="Password missing!")

        result = db.execute("SELECT * FROM users WHERE username = :username",
                            {"username": request.form.get("username")}).fetchone()

        if not result or not check_password_hash(result[2], request.form.get("password")):
            return render_template("error.html", message="Username or password is incorect.")

        else:
            session["user_id"] = result[0]
            flash("Logged in!")
            return redirect("/")

    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    """Let user search for isbn, author or title of a book"""

    if request.method == "POST":
        q = request.form.get("q")

        result = db.execute("SELECT * FROM books WHERE isbn LIKE :q OR author LIKE :q OR title LIKE :q", {"q": q + "%"} ).fetchall()

        return render_template("search.html", method=request.method, books=result)

    else:
        return render_template("search.html", method=request.method)

@app.route("/books/<int:book_id>", methods=["GET", "POST"])
@login_required
def books(book_id):

    if not book_id:
        return render_template("error.html", message="Invalid book!")

    if request.method == "POST":
        if not request.form.get("review"):
            return render_template("error.html", message="Review missing!")

        db.execute("INSERT INTO reviews (review, user_id, book_id) VALUES (:review, :user_id, :book_id)",
                    {"review": request.form.get("review"), "user_id": session["user_id"], "book_id": book_id})
        db.commit()

    book = db.execute("SELECT * FROM books WHERE book_id = :book_id", {"book_id": book_id} ).fetchone()
    if not book:
        return render_template("error.html", message="Book doesn't exist in our database!")


    reviews = db.execute("SELECT * FROM reviews WHERE book_id = :book_id", {"book_id": book_id} ).fetchall()
    # for review in reviews:
    #     review.user_id =

    flash("your review added.")
    return render_template("books.html", book=book, reviews=reviews)
