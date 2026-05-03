import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from dotenv import load_dotenv
import psycopg2
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
        # pgcrypto's crypt() recomputes the hash from the supplied password using the
        # salt embedded in the stored hash; the row matches only if the password is right.
        rows = db.query(
            """
            SELECT user_id, username
            FROM users
            WHERE username = %s
              AND password_hash = crypt(%s, password_hash)
            """,
            (username, password),
        )

        if rows:
            user = rows[0]
            session["user"] = {"id": str(user["user_id"]), "username": user["username"]}
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        username = request.form.get("username", "").strip()
        nickname = request.form.get("nickname", "").strip() or None
        password = request.form.get("password", "")

        if "@" not in email or "." not in email:
            flash("Please enter a valid email address.")
            return render_template("register.html")
        if not username:
            flash("Username is required.")
            return render_template("register.html")
        if len(password) < 6:
            flash("Password must be at least 6 characters.")
            return render_template("register.html")

        try:
            with db.transaction() as cur:
                cur.execute(
                    """
                    INSERT INTO users (user_email, username, nickname, password_hash)
                    VALUES (%s, %s, %s, crypt(%s, gen_salt('bf')))
                    RETURNING user_id, username
                    """,
                    (email, username, nickname, password),
                )
                new_user = cur.fetchone()
        except psycopg2.errors.UniqueViolation:
            flash("That email or username is already taken.")
            return render_template("register.html")

        session["user"] = {"id": str(new_user["user_id"]), "username": new_user["username"]}
        return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/workspaces/new", methods=["GET", "POST"])
@login_required
def new_workspace():
    user = current_user()
    if request.method == "POST":
        name = request.form.get("workspace_name", "").strip()
        description = request.form.get("workspace_description", "").strip() or None

        if not name:
            flash("Workspace name is required.")
            return render_template("workspace_new.html")

        with db.transaction() as cur:
            cur.execute(
                """
                INSERT INTO workspaces (workspace_name, workspace_description, creator_id)
                VALUES (%s, %s, %s)
                RETURNING workspace_id
                """,
                (name, description, user["id"]),
            )
            new_id = cur.fetchone()["workspace_id"]
            cur.execute(
                """
                INSERT INTO workspace_membership (workspace_id, user_id, is_admin)
                VALUES (%s, %s, true)
                """,
                (new_id, user["id"]),
            )

        return redirect(url_for("workspace", workspace_id=new_id))

    return render_template("workspace_new.html")


@app.route("/workspace/<workspace_id>/channels/new", methods=["GET", "POST"])
@login_required
def new_channel(workspace_id):
    user = current_user()

    membership = db.query(
        "SELECT 1 FROM workspace_membership WHERE workspace_id = %s AND user_id = %s",
        (workspace_id, user["id"]),
    )
    if not membership:
        flash("You don't have access to that workspace.")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("channel_name", "").strip()
        channel_type = request.form.get("channel_type", "")
        other_username = request.form.get("other_username", "").strip()

        if not name:
            flash("Channel name is required.")
            return render_template("channel_new.html", workspace_id=workspace_id)
        if channel_type not in ("public", "private", "direct"):
            flash("Invalid channel type.")
            return render_template("channel_new.html", workspace_id=workspace_id)

        other_user_id = None
        if channel_type == "direct":
            if not other_username:
                flash("Direct channels require another user's username.")
                return render_template("channel_new.html", workspace_id=workspace_id)
            rows = db.query(
                """
                SELECT u.user_id
                FROM users u
                JOIN workspace_membership wm ON wm.user_id = u.user_id
                WHERE u.username = %s AND wm.workspace_id = %s
                """,
                (other_username, workspace_id),
            )
            if not rows:
                flash(f"User '{other_username}' isn't a member of this workspace.")
                return render_template("channel_new.html", workspace_id=workspace_id)
            other_user_id = str(rows[0]["user_id"])
            if other_user_id == user["id"]:
                flash("You can't create a direct channel with yourself.")
                return render_template("channel_new.html", workspace_id=workspace_id)

        try:
            with db.transaction() as cur:
                cur.execute(
                    """
                    INSERT INTO channels (workspace_id, channel_name, channel_type, creator_id)
                    VALUES (%s, %s, %s, %s)
                    RETURNING channel_id
                    """,
                    (workspace_id, name, channel_type, user["id"]),
                )
                new_id = cur.fetchone()["channel_id"]
                cur.execute(
                    "INSERT INTO channel_membership (channel_id, user_id) VALUES (%s, %s)",
                    (new_id, user["id"]),
                )
                if other_user_id:
                    cur.execute(
                        "INSERT INTO channel_membership (channel_id, user_id) VALUES (%s, %s)",
                        (new_id, other_user_id),
                    )
        except psycopg2.errors.UniqueViolation:
            flash(f"A channel called '{name}' already exists in this workspace.")
            return render_template("channel_new.html", workspace_id=workspace_id)

        return redirect(url_for("channel", channel_id=new_id))

    return render_template("channel_new.html", workspace_id=workspace_id)


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
