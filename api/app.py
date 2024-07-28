from flask import Flask, url_for, render_template, request, session, redirect, flash, jsonify
from flask_session import Session
from functools import wraps
import os
import psycopg2
import psycopg2.extras
import random
import string
import resend
from cuid import cuid
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import hmac
import hashlib
import json

load_dotenv()

app = Flask(__name__)
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
DATABASE_URL = os.getenv("DATABASE_URL")
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")

resend.api_key = RESEND_API_KEY

connection = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.NamedTupleCursor)

CONTACT_EMAIL = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>New Message Notification</title>
</head>
<body>
    <h2>New Message Received!</h2>
    <p><strong>Name:</strong> {name}</p>
    <p><strong>Email:</strong> {email}</p>
    <p><strong>Message:</strong></p>
    <blockquote>
        {message}
    </blockquote>
</body>
</html>
"""

words = ["star", "blue", "moon", "sky", "cloud", "tree", "river", "mountain", "light", "shadow"]

def generate_username():
    return random.choice(words) + random.choice(words) + str(random.randint(100, 999))

with connection:
    with connection.cursor() as cursor:
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL,
            verification_code TEXT,
            verified BOOLEAN DEFAULT FALSE,
            personal_email TEXT NOT NULL
        )""")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            username TEXT NOT NULL,
            school TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS likes_dislikes (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            post_id TEXT NOT NULL,
            liked BOOLEAN,
            CONSTRAINT unique_like_dislike UNIQUE (user_id, post_id)
        )""")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id TEXT PRIMARY KEY,
            post_id TEXT NOT NULL,
            content TEXT NOT NULL,
            username TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            upvotes INTEGER DEFAULT 0,
            downvotes INTEGER DEFAULT 0,
            FOREIGN KEY (post_id) REFERENCES posts (id)
        )""")

def generate_id():
    return cuid()

def generate_verification_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def send_verification_email(email, code):
    params = {
        "from": ADMIN_EMAIL,
        "to": [email],
        "subject": "Your Verification Code",
        "html": f"<p>Your verification code is: <strong>{code}</strong></p>",
    }
    return resend.Emails.send(params)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" not in session or not session["logged_in"]:
            return redirect("/signup")
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
@limiter.limit("10 per minute")
def index():
    return render_template("index.html")

@app.route("/signup", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def signup():
    if request.method == "POST":
        personal_email = request.form.get("personal_email").strip().lower()
        school_email = request.form.get("school_email").strip().lower()

        if not personal_email.endswith("@gmail.com"):
            flash("Personal email must be a Gmail account.")
            return redirect("/signup")

        if not school_email.endswith("@mymail.nyp.edu.sg"):
            flash("School email must end with @mymail.nyp.edu.sg")
            return redirect("/signup")

        with connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT id, username, verified FROM users WHERE email = %s", (school_email,))
                user = cursor.fetchone()

                if user and user.verified:  # If user exists and is verified
                    session["logged_in"] = True
                    session["user_id"] = user.id
                    session["username"] = user.username  # Store username in session
                    flash("Welcome back! You are now logged in.")
                    return redirect("/")
                elif user and not user.verified:  # If user exists but not verified
                    code = generate_verification_code()
                    hashed_code = generate_password_hash(code)
                    cursor.execute("UPDATE users SET verification_code = %s WHERE email = %s", (hashed_code, school_email))
                else:  # If user does not exist
                    user_id = generate_id()
                    username = generate_username()
                    code = generate_verification_code()
                    hashed_code = generate_password_hash(code)
                    cursor.execute("INSERT INTO users (id, email, username, verification_code, personal_email) VALUES (%s, %s, %s, %s, %s)", (user_id, school_email, username, hashed_code, personal_email))

        # Send test email to school email
        response = send_verification_email(school_email, "Email Verification Test")

        if response.get("id"):
            session["email"] = school_email
            return redirect("/verify")
        else:
            flash("Failed to send verification email. Please try again.")
            return redirect("/signup")
    else:
        return render_template("signup.html")

@app.route("/verify", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def verify():
    if request.method == "POST":
        email = session.get("email")
        if not email:
            return redirect("/signup")

        code = request.form.get("code").strip()

        with connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT id, username, verification_code FROM users WHERE email = %s", (email,))
                row = cursor.fetchone()

                if row and check_password_hash(row.verification_code, code):
                    cursor.execute("UPDATE users SET verified = TRUE, verification_code = NULL WHERE email = %s", (email,))
                    session["logged_in"] = True
                    session["user_id"] = row.id  # Store user_id in session
                    session["username"] = row.username  # Store username in session
                    flash("Verification successful! You are now logged in.")
                    return redirect("/")
                else:
                    flash("Invalid verification code. Please try again.")
                    return redirect("/verify")
    else:
        return render_template("verify.html")


@app.route("/logout")
@login_required
@limiter.limit("5 per minute")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect("/signup")

@app.route("/post", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute")
def create_post():
    if request.method == "POST":
        title = request.form.get("title").strip()
        content = request.form.get("content").strip()
        school = request.form.get("school")
        post_id = generate_id()
        username = session.get("username")  # Retrieve username from session
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("INSERT INTO posts (id, title, content, username, school) VALUES (%s, %s, %s, %s, %s)", (post_id, title, content, username, school))
        return redirect(f"/school/{school}")
    else:
        valid_schools = [
            "School of Applied Science",
            "School of Business Management",
            "School of Design & Media",
            "School of Engineering",
            "School of Health & Social Sciences",
            "School of Information Technology"
        ]
        return render_template("create_post.html", schools=valid_schools)

@app.route("/school/<school_name>")
@login_required
@limiter.limit("10 per minute")
def school_posts(school_name):
    valid_schools = [
        "School of Applied Science",
        "School of Business Management",
        "School of Design & Media",
        "School of Engineering",
        "School of Health & Social Sciences",
        "School of Information Technology"
    ]
    
    if school_name not in valid_schools:
        return redirect("/")
    
    with connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT posts.id, posts.title, posts.content, posts.username, posts.created_at,
                    (SELECT COUNT(*) FROM likes_dislikes WHERE post_id = posts.id AND liked = TRUE) AS likes,
                    (SELECT COUNT(*) FROM likes_dislikes WHERE post_id = posts.id AND liked = FALSE) AS dislikes,
                    (SELECT COUNT(*) FROM comments WHERE post_id = posts.id) AS comment_count
                FROM posts
                WHERE posts.school = %s
                ORDER BY likes DESC
            """, (school_name,))
            posts = cursor.fetchall()
    return render_template("school_posts.html", posts=posts, school_name=school_name)

@app.route("/like_dislike/<string:post_id>/<action>", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def like_dislike(post_id, action):
    user_id = session.get("user_id")  # assuming user_id is stored in session after login
    if action not in ["like", "dislike"]:
        return {"message": "Invalid action"}, 400

    liked = True if action == "like" else False

    with connection:
        with connection.cursor() as cursor:
            try:
                cursor.execute(
                    "INSERT INTO likes_dislikes (id, user_id, post_id, liked) VALUES (%s, %s, %s, %s) ON CONFLICT (user_id, post_id) DO UPDATE SET liked = EXCLUDED.liked",
                    (generate_id(), user_id, post_id, liked)
                )
            except Exception as e:
                return {"message": str(e)}, 400

    return redirect(request.referrer)

@app.route("/comment/<string:post_id>", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def comment(post_id):
    content = request.form.get("content").strip()
    comment_id = generate_id()
    username = session.get("username")  # Retrieve username from session
    with connection:
        with connection.cursor() as cursor:
            cursor.execute("INSERT INTO comments (id, post_id, content, username) VALUES (%s, %s, %s, %s)", (comment_id, post_id, content, username))
            send_comment_notification(post_id, content)
    return redirect(f"/post/{post_id}")

@app.route("/comment_vote/<string:comment_id>/<action>", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def comment_vote(comment_id, action):
    if action not in ["upvote", "downvote"]:
        return {"message": "Invalid action"}, 400

    with connection:
        with connection.cursor() as cursor:
            if action == "upvote":
                cursor.execute("UPDATE comments SET upvotes = upvotes + 1 WHERE id = %s", (comment_id,))
            elif action == "downvote":
                cursor.execute("UPDATE comments SET downvotes = downvotes + 1 WHERE id = %s", (comment_id,))
                cursor.execute("SELECT downvotes FROM comments WHERE id = %s", (comment_id,))
                downvotes = cursor.fetchone().downvotes
                if downvotes >= 30:
                    cursor.execute("DELETE FROM comments WHERE id = %s", (comment_id,))

    return redirect(request.referrer)

@app.route("/post/<string:post_id>")
@login_required
@limiter.limit("10 per minute")
def post_detail(post_id):
    with connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
            post = cursor.fetchone()
            cursor.execute("SELECT * FROM comments WHERE post_id = %s ORDER BY upvotes DESC", (post_id,))
            comments = cursor.fetchall()
    return render_template("post_detail.html", post=post, comments=comments)

@app.route("/search", methods=["GET"])
@login_required
@limiter.limit("10 per minute")
def search():
    query = request.args.get("query")
    with connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT * FROM posts WHERE title ILIKE %s OR content ILIKE %s
            """, (f"%{query}%", f"%{query}%"))
            posts = cursor.fetchall()
            cursor.execute("""
                SELECT * FROM comments WHERE content ILIKE %s
            """, (f"%{query}%",))
            comments = cursor.fetchall()
    return render_template("search_results.html", posts=posts, comments=comments, query=query)

@app.route("/filter", methods=["GET"])
@login_required
@limiter.limit("10 per minute")
def filter():
    school = request.args.get("school")
    order_by = request.args.get("order_by", "created_at")
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(f"""
                SELECT posts.id, posts.title, posts.content, posts.username, posts.created_at,
                    (SELECT COUNT(*) FROM likes_dislikes WHERE post_id = posts.id AND liked = TRUE) AS likes,
                    (SELECT COUNT(*) FROM likes_dislikes WHERE post_id = posts.id AND liked = FALSE) AS dislikes,
                    (SELECT COUNT(*) FROM comments WHERE post_id = posts.id) AS comment_count
                FROM posts
                WHERE posts.school = %s
                ORDER BY {order_by} DESC
            """, (school,))
            posts = cursor.fetchall()
    return render_template("filter_results.html", posts=posts, school=school, order_by=order_by)

def send_comment_notification(post_id, comment_content):
    with connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT email FROM users JOIN posts ON users.username = posts.username WHERE posts.id = %s", (post_id,))
            user = cursor.fetchone()
            if user:
                params = {
                    "from": ADMIN_EMAIL,
                    "to": [user.email],
                    "subject": "New Comment on Your Post",
                    "html": f"<p>Someone commented on your post:</p><blockquote>{comment_content}</blockquote>",
                }
                resend.Emails.send(params)

@app.route("/webhook", methods=["POST"])
@limiter.limit("10 per minute")
def webhook():
    signature = request.headers.get('Resend-Signature')
    payload = request.get_data()
    calculated_signature = hmac.new(WEBHOOK_SECRET.encode(), payload, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(signature, calculated_signature):
        print("Invalid webhook signature")
        return "Invalid signature", 400

    event = request.json
    if event["type"] == "email.delivered":
        email_id = event["data"]["email_id"]
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT email, personal_email FROM users WHERE verification_code = %s", (email_id,))
                user = cursor.fetchone()
                if user:
                    personal_email = user.personal_email
                    code = generate_verification_code()
                    hashed_code = generate_password_hash(code)
                    cursor.execute("UPDATE users SET verification_code = %s WHERE email = %s", (hashed_code, user.email))
                    send_verification_email(personal_email, code)
    return jsonify({"status": "success"}), 200


if __name__ == "__main__":
    app.run(debug=True)
