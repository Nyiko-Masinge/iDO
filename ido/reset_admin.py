"""Reset a local iDO user's password without deleting application data."""
from getpass import getpass

from .database import connect, init_db
from .security import password_hash

def main():
    init_db()
    username = input("Username to reset [admin]: ").strip() or "admin"
    with connect() as db:
        user = db.execute("SELECT id,username FROM users WHERE username=?", (username,)).fetchone()
        if not user:
            raise SystemExit(f"No iDO user named {username!r} exists in this local database.")
    password = getpass("New password (at least 12 characters): ")
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters.")
    confirmation = getpass("Confirm new password: ")
    if password != confirmation:
        raise SystemExit("Passwords did not match; nothing was changed.")
    with connect() as db:
        db.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash(password), user["id"]))
        db.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
        db.execute("INSERT INTO audit_log(actor_id,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?)",
                   (user["id"], "local_password_reset", "user", user["id"], "{}"))
    print(f"Password reset for {username}. Existing datasets and workflows were kept.")

if __name__ == "__main__":
    main()
