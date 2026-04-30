import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from dotenv import load_dotenv
import db

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-insecure-key")

# Jinja2 auto-escapes all template output by default, guarding against XSS.
# All DB calls in db.py use %s parameterized queries, guarding against SQL injection.


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def current_user():
    return session.get("user")

def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Parameterized query — no string concatenation, safe from SQL injection.
        rows = db.query(
            "SELECT user_id, username, password_hash FROM users WHERE username = %s",
            (username,),
        )

        if rows:
            user = rows[0]
            # TODO: replace with bcrypt / werkzeug check once password hashing is wired up.
            # For now accept any non-empty password so the page is runnable against sample data.
            if password:
                session["user"] = {"id": str(user["user_id"]), "username": user["username"]}
                return redirect(url_for("dashboard"))

        flash("Invalid username or password.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    workspaces = db.query(
        """
        SELECT w.workspace_id, w.workspace_name, w.workspace_description
        FROM workspaces w
        JOIN workspace_membership wm ON w.workspace_id = wm.workspace_id
        WHERE wm.user_id = %s
        ORDER BY w.workspace_name
        """,
        (user["id"],),
    )
    return render_template("dashboard.html", user=user, workspaces=workspaces)


@app.route("/workspace/<workspace_id>")
@login_required
def workspace(workspace_id):
    user = current_user()

    # Confirm membership before showing anything.
    membership = db.query(
        "SELECT 1 FROM workspace_membership WHERE workspace_id = %s AND user_id = %s",
        (workspace_id, user["id"]),
    )
    if not membership:
        flash("You don't have access to that workspace.")
        return redirect(url_for("dashboard"))

    ws = db.query(
        "SELECT workspace_name, workspace_description FROM workspaces WHERE workspace_id = %s",
        (workspace_id,),
    )
    channels = db.query(
        """
        SELECT c.channel_id, c.channel_name, c.channel_type
        FROM channels c
        JOIN channel_membership cm ON c.channel_id = cm.channel_id
        WHERE c.workspace_id = %s AND cm.user_id = %s
        ORDER BY c.channel_name
        """,
        (workspace_id, user["id"]),
    )
    return render_template(
        "workspace.html",
        user=user,
        workspace=ws[0] if ws else {},
        workspace_id=workspace_id,
        channels=channels,
    )


@app.route("/channel/<channel_id>")
@login_required
def channel(channel_id):
    user = current_user()

    membership = db.query(
        "SELECT 1 FROM channel_membership WHERE channel_id = %s AND user_id = %s",
        (channel_id, user["id"]),
    )
    if not membership:
        flash("You don't have access to that channel.")
        return redirect(url_for("dashboard"))

    ch = db.query(
        """
        SELECT c.channel_name, c.channel_type, c.workspace_id
        FROM channels c WHERE c.channel_id = %s
        """,
        (channel_id,),
    )
    messages = db.query(
        """
        SELECT m.message_text, m.message_time, u.username
        FROM messages m
        JOIN users u ON m.user_id = u.user_id
        WHERE m.channel_id = %s
        ORDER BY m.message_time ASC
        """,
        (channel_id,),
    )
    return render_template(
        "channel.html",
        user=user,
        channel=ch[0] if ch else {},
        channel_id=channel_id,
        messages=messages,
    )


@app.route("/channel/<channel_id>/post", methods=["POST"])
@login_required
def post_message(channel_id):
    user = current_user()
    text = request.form.get("message_text", "").strip()

    if not text:
        flash("Message cannot be empty.")
        return redirect(url_for("channel", channel_id=channel_id))

    membership = db.query(
        "SELECT 1 FROM channel_membership WHERE channel_id = %s AND user_id = %s",
        (channel_id, user["id"]),
    )
    if not membership:
        flash("You don't have access to that channel.")
        return redirect(url_for("dashboard"))

    db.execute(
        "INSERT INTO messages (channel_id, user_id, message_text) VALUES (%s, %s, %s)",
        (channel_id, user["id"], text),
    )
    return redirect(url_for("channel", channel_id=channel_id))


if __name__ == "__main__":
    app.run(debug=True)
