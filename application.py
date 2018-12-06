import os
import requests



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
    """Create a book page based on book_id"""

    # if a review is submited deal with it
    if request.method == "POST":

        if not request.form.get("review"):
            return render_template("error.html", message="Review missing!")

        elif not request.form.get("rating"):
            return render_template("error.html", message="Rating missing!")

        # Check if user already has a review
        review_check = db.execute("SELECT * FROM reviews WHERE user_id = :user_id",
                                  {"user_id": session["user_id"]}).fetchone()
        # If user has no review
        if not review_check:
            # Inser new review
            db.execute("INSERT INTO reviews (review, user_id, book_id, rating) VALUES (:review, :user_id, :book_id, :rating)",
                        {"review": request.form.get("review"), "user_id": session["user_id"], "book_id": book_id, "rating": request.form.get("rating")})
            db.commit()
            flash("your review added.")
        else:
            # Update the old one
            db.execute("UPDATE reviews SET (review, rating) = (:review, :rating) WHERE user_id = :user_id",
                        {"review": request.form.get("review"), "rating": int(request.form.get("rating")), "user_id": session["user_id"]})
            db.commit()
            flash("your review updated.")

    # Get book info
    book = db.execute("SELECT * FROM books WHERE book_id = :book_id", {"book_id": book_id} ).fetchone()
    if not book:
        return render_template("error.html", message="Book doesn't exist in our database!")

    # Get goodreads info
    res = requests.get("https://www.goodreads.com/book/review_counts.json", params={"key": "pNXqsEFLzAUImM9gNDJ0g", "isbns": book.isbn}).json()

    goodread = {'reviews_count': res['books'][0]['reviews_count'], 'average_rating': res['books'][0]['average_rating']}

    # Get users reviews
    reviews = db.execute("SELECT * FROM reviews JOIN users ON users.user_id = reviews.user_id WHERE book_id = :book_id",
                         {"book_id": book_id} ).fetchall()

    return render_template("books.html", book=book, reviews=reviews, goodread=goodread)

@app.route("/api/<string:isbn>")
def api(isbn):
    """API to send back a json for a book based on its ISBN"""

    #Query  database for book info
    book = db.execute("SELECT * FROM books WHERE isbn = :isbn", {"isbn": isbn}).fetchone()

    # Make a dictionary from book infos
    result = {"title": book.title, "author": book.author, "year": book.year, "isbn": book.isbn}

    # Query database for count of reviews on this book
    review_count = db.execute("SELECT COUNT(*) FROM reviews WHERE book_id = :book_id", {"book_id": book.book_id}).fetchone()[0]

    # Query database fro average rating for this book
    average_score = db.execute("SELECT AVG(rating) FROM reviews WHERE book_id = :book_id", {"book_id": book.book_id}).fetchone()[0]

    # Type error check
    if average_score == None:
        average_score = 0
    result['average_score'] = int(average_score)
    result['review_count'] = int(review_count)

    return jsonify(result)
