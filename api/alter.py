import os
import psycopg2
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

# Connect to the PostgreSQL database
connection = psycopg2.connect(DATABASE_URL)

# SQL statements to alter the database schema
alter_users_table = """
ALTER TABLE users ADD COLUMN username TEXT NOT NULL UNIQUE;
"""

alter_comments_table = """
ALTER TABLE comments ADD COLUMN upvotes INTEGER DEFAULT 0;
ALTER TABLE comments ADD COLUMN downvotes INTEGER DEFAULT 0;
"""

def main():
    with connection:
        with connection.cursor() as cursor:
            # Alter users table
            try:
                cursor.execute(alter_users_table)
                print("Added username column to users table.")
            except psycopg2.errors.DuplicateColumn:
                print("Username column already exists in users table.")
                connection.rollback()

            # Alter comments table
            try:
                cursor.execute(alter_comments_table)
                print("Added upvotes and downvotes columns to comments table.")
            except psycopg2.errors.DuplicateColumn:
                print("Upvotes and/or downvotes columns already exist in comments table.")
                connection.rollback()

if __name__ == "__main__":
    main()
