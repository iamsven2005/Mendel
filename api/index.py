from flask import Flask, render_template, request
import os
from dotenv import load_dotenv
import psycopg2

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Database connection
url = os.getenv("DATABASE_URL")
connection = psycopg2.connect(url)

# SQL query to create the table
CREATE_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS rooms (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL
    )
"""

@app.route("/")
@app.route("/index")
def index():
    return render_template("index.html")

@app.route("/1", methods=["GET"])
def create_room():
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(CREATE_TABLE_SQL)
    return "Room table created successfully", 201

if __name__ == '__main__':
    app.run(debug=True)
