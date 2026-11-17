from getpass import getpass
from werkzeug.security import generate_password_hash
from db import get_db

name = input("Full name: ").strip()
username = input("Username: ").strip()
password = getpass("Password (min. 8 characters): ")

if not name or not username or len(password) < 8:
    raise SystemExit("Name, username and a password of at least 8 characters are required.")

db = get_db()
with db.cursor() as cur:
    cur.execute("SELECT id FROM users WHERE username=%s", (username,))
    row = cur.fetchone()
    if row:
        cur.execute("UPDATE users SET password_hash=%s, is_active=1, role='user' WHERE id=%s",
                    (generate_password_hash(password), row["id"]))
        print(f"Password reset for '{username}'.")
    else:
        cur.execute("""INSERT INTO users (full_name, username, password_hash, role, is_active)
                       VALUES (%s,%s,%s,'user',1)""",
                    (name, username, generate_password_hash(password)))
        print(f"User '{username}' created.")