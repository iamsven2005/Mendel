from datetime import date, timedelta
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

load_dotenv()

app = Flask(__name__)
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
DATABASE_URL = os.getenv("DATABASE_URL")
RESEND_API_KEY = os.getenv("RESEND_API_KEY")

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
            personal_email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL,
            verification_code TEXT,
            verified BOOLEAN DEFAULT FALSE,
            is_admin BOOLEAN DEFAULT FALSE,
            banned BOOLEAN DEFAULT FALSE  -- Add this line
        )""")
        
        cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS banned BOOLEAN DEFAULT FALSE")
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            secret_key TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )""")

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            username TEXT NOT NULL,
            school TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            banned BOOLEAN DEFAULT FALSE
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
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS comment_votes (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            comment_id TEXT NOT NULL,
            upvote BOOLEAN,
            CONSTRAINT unique_comment_vote UNIQUE (user_id, comment_id)
        )""")
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            post_id TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id),
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
        email = request.form.get("email").strip().lower()
        personal_email = request.form.get("personal_email").strip().lower()
        admin_code = request.form.get("admin_code")

        if admin_code:
            admin_code = admin_code.strip()

        is_admin = False
        if admin_code == os.getenv("ADMIN_SIGNUP_CODE"):
            is_admin = True

        if not email.endswith("@mymail.nyp.edu.sg"):
            flash("School email must end with @mymail.nyp.edu.sg")
            return redirect("/signup")

        if not personal_email.endswith("@gmail.com"):
            flash("Personal email must end with @gmail.com")
            return redirect("/signup")

        with connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT id, username, verified FROM users WHERE email = %s", (email,))
                user = cursor.fetchone()

                if user and user.verified:  # If user exists and is verified
                    code = generate_verification_code()
                    hashed_code = generate_password_hash(code)
                    cursor.execute("UPDATE users SET verification_code = %s WHERE email = %s", (hashed_code, email))
                    response = send_verification_email(personal_email, code)

                    if response.get("id"):
                        session["email"] = email
                        return redirect("/otp")
                    else:
                        flash("Failed to send verification email. Please try again.")
                        return redirect("/signup")
                elif user and not user.verified:  # If user exists but not verified
                    code = generate_verification_code()
                    hashed_code = generate_password_hash(code)
                    cursor.execute("UPDATE users SET verification_code = %s, personal_email = %s, is_admin = %s WHERE email = %s", (hashed_code, personal_email, is_admin, email))
                else:  # If user does not exist
                    user_id = generate_id()
                    username = generate_username()
                    code = generate_verification_code()
                    hashed_code = generate_password_hash(code)
                    cursor.execute("INSERT INTO users (id, email, personal_email, username, verification_code, is_admin) VALUES (%s, %s, %s, %s, %s, %s)", (user_id, email, personal_email, username, hashed_code, is_admin))

        response = send_verification_email(personal_email, code)

        if response.get("id"):
            session["email"] = email
            return redirect("/otp")
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
                cursor.execute("SELECT id, username, verification_code, is_admin FROM users WHERE email = %s", (email,))
                row = cursor.fetchone()

                if row and check_password_hash(row.verification_code, code):
                    cursor.execute("UPDATE users SET verified = TRUE, verification_code = NULL WHERE email = %s", (email,))
                    session["logged_in"] = True
                    session["user_id"] = row.id  # Store user_id in session
                    session["username"] = row.username  # Store username in session
                    session["is_admin"] = row.is_admin  # Store admin status in session
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

        flash("Post created successfully.")
        return redirect(url_for('school_posts', school_name=school))

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
    user_id = session.get("user_id")
    if action not in ["like", "dislike"]:
        return {"message": "Invalid action"}, 400

    liked = True if action == "like" else False

    with connection:
        with connection.cursor() as cursor:
            try:
                # Check if the user has already liked/disliked the post
                cursor.execute(
                    "SELECT id, liked FROM likes_dislikes WHERE user_id = %s AND post_id = %s",
                    (user_id, post_id)
                )
                existing_vote = cursor.fetchone()

                if existing_vote:
                    # If the vote is the same, remove it
                    if existing_vote.liked == liked:
                        cursor.execute(
                            "DELETE FROM likes_dislikes WHERE id = %s",
                            (existing_vote.id,)
                        )
                    else:
                        # Update the vote
                        cursor.execute(
                            "UPDATE likes_dislikes SET liked = %s WHERE id = %s",
                            (liked, existing_vote.id)
                        )
                else:
                    # Insert a new vote
                    cursor.execute(
                        "INSERT INTO likes_dislikes (id, user_id, post_id, liked) VALUES (%s, %s, %s, %s)",
                        (generate_id(), user_id, post_id, liked)
                    )

                cursor.execute("""
                    SELECT posts.id, posts.title, posts.content, posts.username, posts.created_at,
                        (SELECT COUNT(*) FROM likes_dislikes WHERE post_id = posts.id AND liked = TRUE) AS likes,
                        (SELECT COUNT(*) FROM likes_dislikes WHERE post_id = posts.id AND liked = FALSE) AS dislikes,
                        (SELECT COUNT(*) FROM comments WHERE post_id = posts.id) AS comment_count
                    FROM posts
                    WHERE posts.id = %s
                """, (post_id,))
                post = cursor.fetchone()
            except Exception as e:
                return {"message": str(e)}, 400

    return render_template("post_snippet.html", post=post)



@app.route("/comment/<string:post_id>", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def comment(post_id):
    user_id = session.get("user_id")
    username = session.get("username")  # Retrieve username from session

    with connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT banned FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            if user and user.banned:
                flash("You are banned from commenting.")
                return redirect(url_for('post_detail', post_id=post_id))

            content = request.form.get("content").strip()
            comment_id = generate_id()
            cursor.execute("INSERT INTO comments (id, post_id, content, username) VALUES (%s, %s, %s, %s)", (comment_id, post_id, content, username))
            send_comment_notification(post_id, content)

    flash("Comment added successfully.")
    return redirect(url_for('post_detail', post_id=post_id))


@app.route("/comment_vote/<string:comment_id>/<action>", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def comment_vote(comment_id, action):
    user_id = session.get("user_id")
    if action not in ["upvote", "downvote"]:
        return {"message": "Invalid action"}, 400

    upvote = True if action == "upvote" else False

    with connection:
        with connection.cursor() as cursor:
            try:
                # Check if the user has already upvoted/downvoted the comment
                cursor.execute(
                    "SELECT id, upvote FROM comment_votes WHERE user_id = %s AND comment_id = %s",
                    (user_id, comment_id)
                )
                existing_vote = cursor.fetchone()

                if existing_vote:
                    # If the vote is the same, remove it
                    if existing_vote.upvote == upvote:
                        cursor.execute(
                            "DELETE FROM comment_votes WHERE id = %s",
                            (existing_vote.id,)
                        )
                        # Decrement the corresponding count
                        if upvote:
                            cursor.execute(
                                "UPDATE comments SET upvotes = upvotes - 1 WHERE id = %s",
                                (comment_id,)
                            )
                        else:
                            cursor.execute(
                                "UPDATE comments SET downvotes = downvotes - 1 WHERE id = %s",
                                (comment_id,)
                            )
                    else:
                        # Update the vote
                        cursor.execute(
                            "UPDATE comment_votes SET upvote = %s WHERE id = %s",
                            (upvote, existing_vote.id)
                        )
                        # Increment the new count and decrement the old count
                        if upvote:
                            cursor.execute(
                                "UPDATE comments SET upvotes = upvotes + 1, downvotes = downvotes - 1 WHERE id = %s",
                                (comment_id,)
                            )
                        else:
                            cursor.execute(
                                "UPDATE comments SET downvotes = downvotes + 1, upvotes = upvotes - 1 WHERE id = %s",
                                (comment_id,)
                            )
                else:
                    # Insert a new vote
                    cursor.execute(
                        "INSERT INTO comment_votes (id, user_id, comment_id, upvote) VALUES (%s, %s, %s, %s)",
                        (generate_id(), user_id, comment_id, upvote)
                    )
                    # Increment the corresponding count
                    if upvote:
                        cursor.execute(
                            "UPDATE comments SET upvotes = upvotes + 1 WHERE id = %s",
                            (comment_id,)
                        )
                    else:
                        cursor.execute(
                            "UPDATE comments SET downvotes = downvotes + 1 WHERE id = %s",
                            (comment_id,)
                        )

                cursor.execute("SELECT * FROM comments WHERE id = %s", (comment_id,))
                comment = cursor.fetchone()
            except Exception as e:
                return {"message": str(e)}, 400

    updated_comment = render_template("comment_snippet.html", comment=comment)
    return updated_comment




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
    new_connection = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.NamedTupleCursor)
    try:
        with new_connection:
            with new_connection.cursor() as cursor:
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
    finally:
        new_connection.close()

@app.route("/otp", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def otp():
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
                    return redirect("/otp")
    else:
        return render_template("otp.html")

@app.route("/report/<string:post_id>", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def report_post(post_id):
    user_id = session.get("user_id")
    with connection:
        with connection.cursor() as cursor:
            cursor.execute("INSERT INTO reports (id, user_id, post_id) VALUES (%s, %s, %s)", (generate_id(), user_id, post_id))
    flash("Post reported successfully.")
    return redirect(request.referrer)

@app.route("/ban/<string:post_id>", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def ban_user(post_id):
    admin_name = request.args.get('admin_name')
    if not admin_name:
        return redirect("/")

    with connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT is_admin FROM users WHERE username = %s", (admin_name,))
            admin = cursor.fetchone()
            if not admin or not admin.is_admin:
                flash("You do not have the necessary permissions to perform this action.")
                return redirect("/")

            cursor.execute("SELECT username FROM posts WHERE id = %s", (post_id,))
            user = cursor.fetchone()
            if user:
                cursor.execute("UPDATE users SET banned = TRUE WHERE username = %s", (user.username,))
                # Delete related reports first
                cursor.execute("DELETE FROM reports WHERE post_id = %s", (post_id,))
                # Delete the post and associated comments
                cursor.execute("DELETE FROM comments WHERE post_id = %s", (post_id,))
                cursor.execute("DELETE FROM posts WHERE id = %s", (post_id,))

    flash("User and post banned successfully.")
    return redirect(f"/admin/{admin_name}")


def generate_api_key_pair():
    public_key = generate_id()
    secret_key = generate_id()
    return public_key, secret_key

@app.route("/generate_api_keys", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def generate_api_keys():
    user_id = session.get("user_id")
    public_key, secret_key = generate_api_key_pair()
    with connection:
        with connection.cursor() as cursor:
            cursor.execute("INSERT INTO api_keys (id, user_id, public_key, secret_key) VALUES (%s, %s, %s, %s)", (generate_id(), user_id, public_key, secret_key))
    return jsonify({"public_key": public_key, "secret_key": secret_key})

def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        public_key = request.headers.get("X-Public-Key")
        secret_key = request.headers.get("X-Secret-Key")
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM api_keys WHERE public_key = %s AND secret_key = %s", (public_key, secret_key))
                api_key = cursor.fetchone()
                if not api_key:
                    return jsonify({"message": "Invalid API keys"}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route("/api/posts", methods=["GET"])
@api_key_required
def api_posts():
    with connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM posts WHERE banned = FALSE")
            posts = cursor.fetchall()
    return jsonify(posts)

@app.route("/api/comments", methods=["GET"])
@api_key_required
def api_comments():
    post_id = request.args.get("post_id")
    with connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM comments WHERE post_id = %s", (post_id,))
            comments = cursor.fetchall()
    return jsonify(comments)


@app.route("/api_keys", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per minute")
def api_keys():
    user_id = session.get("user_id")
    if request.method == "POST":
        public_key, secret_key = generate_api_key_pair()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("INSERT INTO api_keys (id, user_id, public_key, secret_key) VALUES (%s, %s, %s, %s)", (generate_id(), user_id, public_key, secret_key))
        flash("API key generated successfully.")
        return redirect("/api_keys")

    with connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT public_key, secret_key FROM api_keys WHERE user_id = %s", (user_id,))
            keys = cursor.fetchall()
    return render_template("api_keys.html", keys=keys)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin"):
            flash("You do not have the necessary permissions to access this page.")
            return redirect("/")
        return f(*args, **kwargs)
    return decorated_function


@app.route("/admin/<string:admin_name>", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per minute")
def admin(admin_name):
    with connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT is_admin FROM users WHERE username = %s", (admin_name,))
            admin = cursor.fetchone()
            if not admin or not admin.is_admin:
                flash("You do not have the necessary permissions to access this page.")
                return redirect("/")

    if request.method == "POST":
        action = request.form.get("action")
        post_id = request.form.get("post_id")
        if action == "ban":
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE posts SET banned = TRUE WHERE id = %s", (post_id,))
                    cursor.execute("DELETE FROM reports WHERE post_id = %s", (post_id,))
            flash("Post banned successfully.")
        return redirect(f"/admin/{admin_name}")

    with connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT reports.id as report_id, posts.id as post_id, posts.title, posts.content, posts.username as post_username, reports.user_id as reporter_id
                FROM reports
                JOIN posts ON reports.post_id = posts.id
                WHERE posts.banned = FALSE
            """)
            reports = cursor.fetchall()
    
    return render_template("admin.html", reports=reports, admin_name=admin_name)

if __name__ == "__main__":
    app.run(debug=True)
