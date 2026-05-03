import os
import re
import secrets
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from markupsafe import Markup, escape
from dotenv import load_dotenv
import psycopg2
import db

load_dotenv()

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is required")

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Jinja2 auto-escapes all template output by default, guarding against XSS.
# All DB calls in db.py use %s parameterized queries, guarding against SQL injection.
# Every POST form carries a CSRF token validated by the before_request hook below.


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def current_user():
    user = session.get("user")
    if user and not {"id", "username", "email"}.issubset(user):
        session.clear()
        return None
    return user

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(workspace_id, *args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        rows = db.query(
            "SELECT 1 FROM workspace_membership WHERE workspace_id=%s AND user_id=%s AND is_admin=true",
            (workspace_id, user["id"]),
        )
        if not rows:
            flash("Only workspace admins can do that.")
            return redirect(url_for("workspace", workspace_id=workspace_id))
        return f(workspace_id, *args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# CSRF protection
# ---------------------------------------------------------------------------

def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


@app.before_request
def csrf_protect():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session["csrf_token"]
        if not secrets.compare_digest(sent, expected):
            abort(403)


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": csrf_token}


# ---------------------------------------------------------------------------
# Workspace context (for sidebar) + user workspaces (for rail)
# ---------------------------------------------------------------------------

def _workspace_context(workspace_id, user_id, active_channel_id=None):
    rows = db.query(
        "SELECT workspace_id, workspace_name, workspace_description FROM workspaces WHERE workspace_id = %s",
        (workspace_id,),
    )
    if not rows:
        return None
    channels = db.query(
        """
        SELECT
            c.channel_id, c.channel_name, c.channel_type,
            (
                SELECT COUNT(*) FROM messages m
                WHERE m.channel_id = c.channel_id
                  AND m.user_id <> %s
                  AND NOT EXISTS (
                      SELECT 1 FROM is_seen s
                      WHERE s.message_id = m.message_id
                        AND s.user_id = %s AND s.is_seen = true
                  )
            ) AS unread_count
        FROM channels c
        JOIN channel_membership cm ON c.channel_id = cm.channel_id
        WHERE c.workspace_id = %s AND cm.user_id = %s
        ORDER BY
          CASE c.channel_type WHEN 'public' THEN 0 WHEN 'private' THEN 1 ELSE 2 END,
          c.channel_name
        """,
        (user_id, user_id, workspace_id, user_id),
    )
    return {
        "active_workspace": rows[0],
        "active_channel_id": str(active_channel_id) if active_channel_id else None,
        "workspace_channels": channels,
    }


@app.context_processor
def inject_user_workspaces():
    user = current_user()
    if not user:
        return {"user_workspaces": []}
    rows = db.query(
        """
        SELECT w.workspace_id, w.workspace_name
        FROM workspaces w
        JOIN workspace_membership wm ON w.workspace_id = wm.workspace_id
        WHERE wm.user_id = %s
        ORDER BY w.workspace_name
        """,
        (user["id"],),
    )
    return {"user_workspaces": rows}


# ---------------------------------------------------------------------------
# Template filters
# ---------------------------------------------------------------------------

_AVATAR_PALETTE = [
    "#E91E63", "#9C27B0", "#673AB7", "#3F51B5",
    "#2196F3", "#0EA5E9", "#06B6D4", "#0D9488",
    "#16A34A", "#65A30D", "#CA8A04", "#EA580C",
    "#DC2626", "#DB2777",
]


@app.template_filter("avatar_color")
def avatar_color(name):
    h = sum(ord(c) for c in (name or ""))
    return _AVATAR_PALETTE[h % len(_AVATAR_PALETTE)]


@app.template_filter("initial")
def initial(name):
    return (name or "?")[0].upper()


@app.template_filter("highlight")
def highlight(text, term):
    if not term or not text:
        return text
    escaped_text = str(escape(text))
    pattern = re.compile(re.escape(term), re.IGNORECASE)
    result = pattern.sub(
        lambda m: f'<mark class="bg-yellow-200 text-black px-0.5 rounded">{m.group()}</mark>',
        escaped_text,
    )
    return Markup(result)


@app.template_filter("relative_time")
def relative_time(dt):
    if dt is None:
        return ""
    delta = datetime.now() - dt
    secs = delta.total_seconds()
    if secs < 60:
        return "just now"
    if secs < 3600:
        m = int(secs // 60)
        return f"{m}m ago"
    if secs < 86400:
        h = int(secs // 3600)
        return f"{h}h ago"
    if secs < 604800:
        d = int(secs // 86400)
        return f"{d}d ago"
    return dt.strftime("%b %d, %Y")


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

        # crypt() rehashes with the embedded salt; row matches only if the password is right.
        rows = db.query(
            """
            SELECT user_id, username, user_email
            FROM users
            WHERE username = %s
              AND password_hash = crypt(%s, password_hash)
            """,
            (username, password),
        )

        if rows:
            user = rows[0]
            session["user"] = {
                "id": str(user["user_id"]),
                "username": user["username"],
                "email": user["user_email"],
            }
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
                    RETURNING user_id, username, user_email
                    """,
                    (email, username, nickname, password),
                )
                new_user = cur.fetchone()
        except psycopg2.errors.UniqueViolation:
            flash("That email or username is already taken.")
            return render_template("register.html")

        session["user"] = {
            "id": str(new_user["user_id"]),
            "username": new_user["username"],
            "email": new_user["user_email"],
        }
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
            return render_template("channel_new.html", workspace_id=workspace_id, **(_workspace_context(workspace_id, user["id"]) or {}))
        if channel_type not in ("public", "private", "direct"):
            flash("Invalid channel type.")
            return render_template("channel_new.html", workspace_id=workspace_id, **(_workspace_context(workspace_id, user["id"]) or {}))

        other_user_id = None
        if channel_type == "direct":
            if not other_username:
                flash("Direct channels require another user's username.")
                return render_template("channel_new.html", workspace_id=workspace_id, **(_workspace_context(workspace_id, user["id"]) or {}))
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
                return render_template("channel_new.html", workspace_id=workspace_id, **(_workspace_context(workspace_id, user["id"]) or {}))
            other_user_id = str(rows[0]["user_id"])
            if other_user_id == user["id"]:
                flash("You can't create a direct channel with yourself.")
                return render_template("channel_new.html", workspace_id=workspace_id, **(_workspace_context(workspace_id, user["id"]) or {}))

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
            return render_template("channel_new.html", workspace_id=workspace_id, **(_workspace_context(workspace_id, user["id"]) or {}))

        return redirect(url_for("channel", channel_id=new_id))

    return render_template("channel_new.html", workspace_id=workspace_id, **(_workspace_context(workspace_id, user["id"]) or {}))


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

    membership = db.query(
        "SELECT is_admin FROM workspace_membership WHERE workspace_id = %s AND user_id = %s",
        (workspace_id, user["id"]),
    )
    if not membership:
        flash("You don't have access to that workspace.")
        return redirect(url_for("dashboard"))

    ctx = _workspace_context(workspace_id, user["id"])
    if not ctx:
        flash("Workspace not found.")
        return redirect(url_for("dashboard"))

    return render_template(
        "workspace.html",
        workspace_id=workspace_id,
        is_admin=membership[0]["is_admin"],
        **ctx,
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
    if not ch:
        flash("Channel not found.")
        return redirect(url_for("dashboard"))
    workspace_id = str(ch[0]["workspace_id"])

    messages = db.query(
        """
        SELECT m.message_id, m.message_text, m.message_time, u.username
        FROM messages m
        JOIN users u ON m.user_id = u.user_id
        WHERE m.channel_id = %s
        ORDER BY m.message_time ASC
        """,
        (channel_id,),
    )

    unread_rows = db.query(
        """
        SELECT m.message_id
        FROM messages m
        WHERE m.channel_id = %s
          AND m.user_id <> %s
          AND NOT EXISTS (
              SELECT 1 FROM is_seen s
              WHERE s.message_id = m.message_id
                AND s.user_id = %s
                AND s.is_seen = true
          )
        """,
        (channel_id, user["id"], user["id"]),
    )
    unread_ids = {str(r["message_id"]) for r in unread_rows}

    db.execute(
        """
        INSERT INTO is_seen (message_id, user_id, is_seen, seen_time)
        SELECT m.message_id, %s, true, now()
        FROM messages m
        WHERE m.channel_id = %s
        ON CONFLICT (message_id, user_id) DO UPDATE
            SET is_seen = true, seen_time = now()
            WHERE is_seen.is_seen = false
        """,
        (user["id"], channel_id),
    )

    ctx = _workspace_context(workspace_id, user["id"], active_channel_id=channel_id)

    return render_template(
        "channel.html",
        channel=ch[0],
        channel_id=channel_id,
        messages=messages,
        unread_ids=unread_ids,
        **ctx,
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


@app.route("/workspace/<workspace_id>/invite", methods=["GET", "POST"])
@login_required
@admin_required
def invite_to_workspace(workspace_id):
    user = current_user()

    ws_rows = db.query(
        "SELECT workspace_name FROM workspaces WHERE workspace_id = %s",
        (workspace_id,),
    )
    if not ws_rows:
        flash("Workspace not found.")
        return redirect(url_for("dashboard"))
    workspace_name = ws_rows[0]["workspace_name"]

    if request.method == "POST":
        invitee_email = request.form.get("invitee_email", "").strip().lower()

        if "@" not in invitee_email or "." not in invitee_email:
            flash("Please enter a valid email address.")
            return render_template("workspace_invite.html", workspace_id=workspace_id, workspace_name=workspace_name, **(_workspace_context(workspace_id, user["id"]) or {}))

        existing = db.query("SELECT user_id FROM users WHERE user_email = %s", (invitee_email,))
        invitee_user_id = str(existing[0]["user_id"]) if existing else None

        if invitee_user_id:
            already = db.query(
                "SELECT 1 FROM workspace_membership WHERE workspace_id = %s AND user_id = %s",
                (workspace_id, invitee_user_id),
            )
            if already:
                flash(f"{invitee_email} is already a member of this workspace.")
                return render_template("workspace_invite.html", workspace_id=workspace_id, workspace_name=workspace_name, **(_workspace_context(workspace_id, user["id"]) or {}))

        try:
            db.execute(
                """
                INSERT INTO workspace_invitation
                    (workspace_id, inviter_user_id, invitee_email, invitee_user_id)
                VALUES (%s, %s, %s, %s)
                """,
                (workspace_id, user["id"], invitee_email, invitee_user_id),
            )
        except psycopg2.errors.UniqueViolation:
            flash(f"There's already a pending invitation for {invitee_email}.")
            return render_template("workspace_invite.html", workspace_id=workspace_id, workspace_name=workspace_name, **(_workspace_context(workspace_id, user["id"]) or {}))

        flash(f"Invitation sent to {invitee_email}.")
        return redirect(url_for("workspace", workspace_id=workspace_id))

    return render_template("workspace_invite.html", workspace_id=workspace_id, workspace_name=workspace_name, **(_workspace_context(workspace_id, user["id"]) or {}))


@app.route("/channel/<channel_id>/invite", methods=["GET", "POST"])
@login_required
def invite_to_channel(channel_id):
    user = current_user()

    membership = db.query(
        "SELECT 1 FROM channel_membership WHERE channel_id = %s AND user_id = %s",
        (channel_id, user["id"]),
    )
    if not membership:
        flash("You don't have access to that channel.")
        return redirect(url_for("dashboard"))

    ch_rows = db.query(
        "SELECT channel_name, channel_type, workspace_id FROM channels WHERE channel_id = %s",
        (channel_id,),
    )
    if not ch_rows:
        flash("Channel not found.")
        return redirect(url_for("dashboard"))
    channel = ch_rows[0]

    if channel["channel_type"] == "direct":
        flash("Direct channels can't have additional members.")
        return redirect(url_for("channel", channel_id=channel_id))

    if request.method == "POST":
        username = request.form.get("invitee_username", "").strip()
        if not username:
            flash("Username is required.")
            return render_template("channel_invite.html", channel_id=channel_id, channel=channel, **(_workspace_context(str(channel["workspace_id"]), user["id"], active_channel_id=channel_id) or {}))

        rows = db.query(
            """
            SELECT u.user_id
            FROM users u
            JOIN workspace_membership wm ON wm.user_id = u.user_id
            WHERE u.username = %s AND wm.workspace_id = %s
            """,
            (username, channel["workspace_id"]),
        )
        if not rows:
            flash(f"User '{username}' isn't a member of this workspace.")
            return render_template("channel_invite.html", channel_id=channel_id, channel=channel, **(_workspace_context(str(channel["workspace_id"]), user["id"], active_channel_id=channel_id) or {}))
        invitee_user_id = str(rows[0]["user_id"])

        if invitee_user_id == user["id"]:
            flash("You can't invite yourself.")
            return render_template("channel_invite.html", channel_id=channel_id, channel=channel, **(_workspace_context(str(channel["workspace_id"]), user["id"], active_channel_id=channel_id) or {}))

        already = db.query(
            "SELECT 1 FROM channel_membership WHERE channel_id = %s AND user_id = %s",
            (channel_id, invitee_user_id),
        )
        if already:
            flash(f"{username} is already in this channel.")
            return render_template("channel_invite.html", channel_id=channel_id, channel=channel, **(_workspace_context(str(channel["workspace_id"]), user["id"], active_channel_id=channel_id) or {}))

        try:
            db.execute(
                """
                INSERT INTO channel_invitation (channel_id, inviter_user_id, invitee_user_id)
                VALUES (%s, %s, %s)
                """,
                (channel_id, user["id"], invitee_user_id),
            )
        except psycopg2.errors.UniqueViolation:
            flash(f"{username} already has a pending invitation to this channel.")
            return render_template("channel_invite.html", channel_id=channel_id, channel=channel, **(_workspace_context(str(channel["workspace_id"]), user["id"], active_channel_id=channel_id) or {}))

        flash(f"Invitation sent to {username}.")
        return redirect(url_for("channel", channel_id=channel_id))

    return render_template("channel_invite.html", channel_id=channel_id, channel=channel, **(_workspace_context(str(channel["workspace_id"]), user["id"], active_channel_id=channel_id) or {}))


@app.route("/invitations")
@login_required
def invitations():
    user = current_user()
    workspace_invites = db.query(
        """
        SELECT wi.invitation_id, wi.invitation_time,
               w.workspace_id, w.workspace_name, w.workspace_description,
               u.username AS inviter
        FROM workspace_invitation wi
        JOIN workspaces w ON wi.workspace_id = w.workspace_id
        JOIN users u ON wi.inviter_user_id = u.user_id
        WHERE wi.invite_status = 'pending'
          AND (wi.invitee_user_id = %s OR wi.invitee_email = %s)
        ORDER BY wi.invitation_time DESC
        """,
        (user["id"], user["email"]),
    )
    channel_invites = db.query(
        """
        SELECT ci.invitation_id, ci.invitation_time,
               c.channel_id, c.channel_name, c.channel_type,
               w.workspace_name, u.username AS inviter
        FROM channel_invitation ci
        JOIN channels c ON ci.channel_id = c.channel_id
        JOIN workspaces w ON c.workspace_id = w.workspace_id
        JOIN users u ON ci.inviter_user_id = u.user_id
        WHERE ci.invite_status = 'pending' AND ci.invitee_user_id = %s
        ORDER BY ci.invitation_time DESC
        """,
        (user["id"],),
    )
    return render_template(
        "invitations.html",
        workspace_invites=workspace_invites,
        channel_invites=channel_invites,
    )


@app.route("/invitations/workspace/<invitation_id>/<action>", methods=["POST"])
@login_required
def respond_workspace_invitation(invitation_id, action):
    if action not in ("accept", "decline"):
        flash("Invalid action.")
        return redirect(url_for("invitations"))

    user = current_user()
    rows = db.query(
        """
        SELECT workspace_id
        FROM workspace_invitation
        WHERE invitation_id = %s
          AND invite_status = 'pending'
          AND (invitee_user_id = %s OR invitee_email = %s)
        """,
        (invitation_id, user["id"], user["email"]),
    )
    if not rows:
        flash("Invitation not found or already responded.")
        return redirect(url_for("invitations"))

    workspace_id = str(rows[0]["workspace_id"])
    new_status = "accepted" if action == "accept" else "declined"

    with db.transaction() as cur:
        # Backfill invitee_user_id in case the invite was sent by email pre-signup.
        cur.execute(
            """
            UPDATE workspace_invitation
            SET invite_status = %s, responded_at = now(), invitee_user_id = %s
            WHERE invitation_id = %s
            """,
            (new_status, user["id"], invitation_id),
        )
        if action == "accept":
            cur.execute(
                """
                INSERT INTO workspace_membership (workspace_id, user_id)
                VALUES (%s, %s)
                ON CONFLICT (workspace_id, user_id) DO NOTHING
                """,
                (workspace_id, user["id"]),
            )

    flash(f"Invitation {new_status}.")
    if action == "accept":
        return redirect(url_for("workspace", workspace_id=workspace_id))
    return redirect(url_for("invitations"))


@app.route("/invitations/channel/<invitation_id>/<action>", methods=["POST"])
@login_required
def respond_channel_invitation(invitation_id, action):
    if action not in ("accept", "decline"):
        flash("Invalid action.")
        return redirect(url_for("invitations"))

    user = current_user()
    rows = db.query(
        """
        SELECT ci.channel_id, c.workspace_id
        FROM channel_invitation ci
        JOIN channels c ON ci.channel_id = c.channel_id
        WHERE ci.invitation_id = %s
          AND ci.invite_status = 'pending'
          AND ci.invitee_user_id = %s
        """,
        (invitation_id, user["id"]),
    )
    if not rows:
        flash("Invitation not found or already responded.")
        return redirect(url_for("invitations"))

    channel_id = str(rows[0]["channel_id"])
    workspace_id = str(rows[0]["workspace_id"])
    new_status = "accepted" if action == "accept" else "declined"

    if action == "accept":
        in_ws = db.query(
            "SELECT 1 FROM workspace_membership WHERE workspace_id = %s AND user_id = %s",
            (workspace_id, user["id"]),
        )
        if not in_ws:
            flash("You need to join the workspace before accepting this channel invite.")
            return redirect(url_for("invitations"))

    with db.transaction() as cur:
        cur.execute(
            """
            UPDATE channel_invitation
            SET invite_status = %s, responded_at = now()
            WHERE invitation_id = %s
            """,
            (new_status, invitation_id),
        )
        if action == "accept":
            cur.execute(
                """
                INSERT INTO channel_membership (channel_id, user_id)
                VALUES (%s, %s)
                ON CONFLICT (channel_id, user_id) DO NOTHING
                """,
                (channel_id, user["id"]),
            )

    flash(f"Invitation {new_status}.")
    if action == "accept":
        return redirect(url_for("channel", channel_id=channel_id))
    return redirect(url_for("invitations"))


@app.route("/workspace/<workspace_id>/members")
@login_required
def workspace_members(workspace_id):
    user = current_user()

    me = db.query(
        "SELECT is_admin FROM workspace_membership WHERE workspace_id = %s AND user_id = %s",
        (workspace_id, user["id"]),
    )
    if not me:
        flash("You don't have access to that workspace.")
        return redirect(url_for("dashboard"))
    is_admin = me[0]["is_admin"]

    ws = db.query(
        "SELECT workspace_name FROM workspaces WHERE workspace_id = %s",
        (workspace_id,),
    )
    if not ws:
        flash("Workspace not found.")
        return redirect(url_for("dashboard"))

    members = db.query(
        """
        SELECT u.user_id, u.username, u.nickname, wm.is_admin, wm.joined_time
        FROM workspace_membership wm
        JOIN users u ON wm.user_id = u.user_id
        WHERE wm.workspace_id = %s
        ORDER BY wm.is_admin DESC, u.username
        """,
        (workspace_id,),
    )

    admin_count_rows = db.query(
        "SELECT COUNT(*) AS n FROM workspace_membership WHERE workspace_id = %s AND is_admin = true",
        (workspace_id,),
    )
    admin_count = admin_count_rows[0]["n"] if admin_count_rows else 0

    stale_invites = []
    if is_admin:
        stale_invites = db.query(
            """
            SELECT
                c.channel_id,
                c.channel_name,
                u.username AS invitee,
                u.nickname AS invitee_nickname,
                inv.username AS invited_by,
                ci.invitation_time,
                EXTRACT(DAY FROM now() - ci.invitation_time)::int AS days_stale
            FROM channel_invitation ci
            JOIN channels c ON c.channel_id = ci.channel_id
            JOIN users u   ON u.user_id   = ci.invitee_user_id
            JOIN users inv ON inv.user_id = ci.inviter_user_id
            WHERE c.workspace_id = %s
              AND c.channel_type = 'public'
              AND ci.invite_status = 'pending'
              AND ci.invitation_time < now() - INTERVAL '5 days'
              AND NOT EXISTS (
                  SELECT 1 FROM channel_membership cm
                  WHERE cm.channel_id = ci.channel_id
                    AND cm.user_id = ci.invitee_user_id
              )
            ORDER BY c.channel_name, ci.invitation_time
            """,
            (workspace_id,),
        )

    ctx = _workspace_context(workspace_id, user["id"]) or {}
    return render_template(
        "workspace_members.html",
        workspace_id=workspace_id,
        workspace_name=ws[0]["workspace_name"],
        is_admin=is_admin,
        members=members,
        stale_invites=stale_invites,
        current_user_id=user["id"],
        admin_count=admin_count,
        **ctx,
    )


@app.route("/workspace/<workspace_id>/members/<member_id>/promote", methods=["POST"])
@login_required
@admin_required
def promote_member(workspace_id, member_id):
    rowcount = db.execute(
        """
        UPDATE workspace_membership
        SET is_admin = true
        WHERE workspace_id = %s AND user_id = %s AND is_admin = false
        """,
        (workspace_id, member_id),
    )

    flash("Member promoted to admin." if rowcount else "Member not found or already an admin.")
    return redirect(url_for("workspace_members", workspace_id=workspace_id))


@app.route("/workspace/<workspace_id>/members/<member_id>/demote", methods=["POST"])
@login_required
@admin_required
def demote_member(workspace_id, member_id):
    admin_count_rows = db.query(
        "SELECT COUNT(*) AS n FROM workspace_membership WHERE workspace_id = %s AND is_admin = true",
        (workspace_id,),
    )
    n_admins = admin_count_rows[0]["n"] if admin_count_rows else 0
    if n_admins <= 1:
        flash("Can't demote: the workspace must have at least one admin.")
        return redirect(url_for("workspace_members", workspace_id=workspace_id))

    rowcount = db.execute(
        """
        UPDATE workspace_membership
        SET is_admin = false
        WHERE workspace_id = %s AND user_id = %s AND is_admin = true
        """,
        (workspace_id, member_id),
    )
    flash("Admin demoted to member." if rowcount else "Member not found or not an admin.")
    return redirect(url_for("workspace_members", workspace_id=workspace_id))


@app.route("/workspace/<workspace_id>/members/<member_id>/remove", methods=["POST"])
@login_required
@admin_required
def remove_member(workspace_id, member_id):
    user = current_user()
    if member_id == user["id"]:
        flash("You can't remove yourself. Use 'Leave workspace' instead.")
        return redirect(url_for("workspace_members", workspace_id=workspace_id))

    with db.transaction() as cur:
        cur.execute(
            """
            DELETE FROM channel_membership
            WHERE user_id = %s
              AND channel_id IN (SELECT channel_id FROM channels WHERE workspace_id = %s)
            """,
            (member_id, workspace_id),
        )
        cur.execute(
            "DELETE FROM workspace_membership WHERE workspace_id = %s AND user_id = %s",
            (workspace_id, member_id),
        )

    flash("Member removed.")
    return redirect(url_for("workspace_members", workspace_id=workspace_id))


@app.route("/workspace/<workspace_id>/channels")
@login_required
def browse_channels(workspace_id):
    user = current_user()
    membership = db.query(
        "SELECT 1 FROM workspace_membership WHERE workspace_id = %s AND user_id = %s",
        (workspace_id, user["id"]),
    )
    if not membership:
        flash("You don't have access to that workspace.")
        return redirect(url_for("dashboard"))

    channels = db.query(
        """
        SELECT c.channel_id, c.channel_name,
               COUNT(cm2.user_id) AS member_count,
               EXISTS(
                   SELECT 1 FROM channel_membership cm
                   WHERE cm.channel_id = c.channel_id AND cm.user_id = %s
               ) AS is_member
        FROM channels c
        LEFT JOIN channel_membership cm2 ON cm2.channel_id = c.channel_id
        WHERE c.workspace_id = %s AND c.channel_type = 'public'
        GROUP BY c.channel_id, c.channel_name
        ORDER BY c.channel_name
        """,
        (user["id"], workspace_id),
    )
    ctx = _workspace_context(workspace_id, user["id"]) or {}
    return render_template("channels_browse.html", workspace_id=workspace_id, channels=channels, **ctx)


@app.route("/workspace/<workspace_id>/channels/<channel_id>/join", methods=["POST"])
@login_required
def join_channel(workspace_id, channel_id):
    user = current_user()
    wm = db.query(
        "SELECT 1 FROM workspace_membership WHERE workspace_id = %s AND user_id = %s",
        (workspace_id, user["id"]),
    )
    if not wm:
        flash("You don't have access to that workspace.")
        return redirect(url_for("dashboard"))

    ch = db.query(
        "SELECT channel_type FROM channels WHERE channel_id = %s AND workspace_id = %s",
        (channel_id, workspace_id),
    )
    if not ch or ch[0]["channel_type"] != "public":
        flash("Channel not found.")
        return redirect(url_for("browse_channels", workspace_id=workspace_id))

    db.execute(
        "INSERT INTO channel_membership (channel_id, user_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
        (channel_id, user["id"]),
    )
    return redirect(url_for("channel", channel_id=channel_id))


@app.route("/channel/<channel_id>/leave", methods=["POST"])
@login_required
def leave_channel(channel_id):
    user = current_user()
    ch = db.query(
        "SELECT channel_type, workspace_id, channel_name FROM channels WHERE channel_id = %s",
        (channel_id,),
    )
    if not ch:
        flash("Channel not found.")
        return redirect(url_for("dashboard"))

    if ch[0]["channel_type"] == "direct":
        flash("You can't leave a direct message channel.")
        return redirect(url_for("channel", channel_id=channel_id))

    workspace_id = str(ch[0]["workspace_id"])
    db.execute(
        "DELETE FROM channel_membership WHERE channel_id = %s AND user_id = %s",
        (channel_id, user["id"]),
    )
    flash(f"You left #{ch[0]['channel_name']}.")
    return redirect(url_for("workspace", workspace_id=workspace_id))


@app.route("/workspace/<workspace_id>/leave", methods=["POST"])
@login_required
def leave_workspace(workspace_id):
    user = current_user()
    me = db.query(
        "SELECT is_admin FROM workspace_membership WHERE workspace_id = %s AND user_id = %s",
        (workspace_id, user["id"]),
    )
    if not me:
        flash("You're not a member of that workspace.")
        return redirect(url_for("dashboard"))

    if me[0]["is_admin"]:
        other_admins = db.query(
            "SELECT 1 FROM workspace_membership WHERE workspace_id = %s AND user_id != %s AND is_admin = true",
            (workspace_id, user["id"]),
        )
        other_members = db.query(
            "SELECT 1 FROM workspace_membership WHERE workspace_id = %s AND user_id != %s",
            (workspace_id, user["id"]),
        )
        if not other_admins and other_members:
            flash("You're the only admin. Promote someone else to admin before leaving.")
            return redirect(url_for("workspace", workspace_id=workspace_id))

    with db.transaction() as cur:
        cur.execute(
            """
            DELETE FROM channel_membership
            WHERE user_id = %s
              AND channel_id IN (SELECT channel_id FROM channels WHERE workspace_id = %s)
            """,
            (user["id"], workspace_id),
        )
        cur.execute(
            "DELETE FROM workspace_membership WHERE workspace_id = %s AND user_id = %s",
            (workspace_id, user["id"]),
        )

    flash("You left the workspace.")
    return redirect(url_for("dashboard"))


@app.route("/workspace/<workspace_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def edit_workspace(workspace_id):
    user = current_user()
    ws = db.query(
        "SELECT workspace_name, workspace_description FROM workspaces WHERE workspace_id = %s",
        (workspace_id,),
    )
    if not ws:
        flash("Workspace not found.")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("workspace_name", "").strip()
        description = request.form.get("workspace_description", "").strip() or None

        if not name:
            flash("Workspace name is required.")
            return render_template("workspace_edit.html", workspace_id=workspace_id, ws=ws[0], **(_workspace_context(workspace_id, user["id"]) or {}))

        db.execute(
            "UPDATE workspaces SET workspace_name = %s, workspace_description = %s WHERE workspace_id = %s",
            (name, description, workspace_id),
        )
        flash("Workspace updated.")
        return redirect(url_for("workspace", workspace_id=workspace_id))

    return render_template("workspace_edit.html", workspace_id=workspace_id, ws=ws[0], **(_workspace_context(workspace_id, user["id"]) or {}))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    row = db.query(
        "SELECT user_id, username, user_email, nickname FROM users WHERE user_id = %s",
        (user["id"],),
    )
    if not row:
        flash("User not found.")
        return redirect(url_for("dashboard"))

    user_data = row[0]

    if request.method == "POST":
        nickname = request.form.get("nickname", "").strip() or None
        email = request.form.get("email", "").strip()
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")

        if "@" not in email or "." not in email:
            flash("Please enter a valid email address.")
            return render_template("profile.html", user_data=user_data)

        if new_password:
            if not current_password:
                flash("Enter your current password to set a new one.")
                return render_template("profile.html", user_data=user_data)
            if len(new_password) < 6:
                flash("New password must be at least 6 characters.")
                return render_template("profile.html", user_data=user_data)
            check = db.query(
                "SELECT 1 FROM users WHERE user_id = %s AND password_hash = crypt(%s, password_hash)",
                (user["id"], current_password),
            )
            if not check:
                flash("Current password is incorrect.")
                return render_template("profile.html", user_data=user_data)

        try:
            with db.transaction() as cur:
                if new_password:
                    cur.execute(
                        """
                        UPDATE users SET nickname = %s, user_email = %s,
                            password_hash = crypt(%s, gen_salt('bf'))
                        WHERE user_id = %s
                        """,
                        (nickname, email, new_password, user["id"]),
                    )
                else:
                    cur.execute(
                        "UPDATE users SET nickname = %s, user_email = %s WHERE user_id = %s",
                        (nickname, email, user["id"]),
                    )
        except psycopg2.errors.UniqueViolation:
            flash("That email is already taken.")
            return render_template("profile.html", user_data=user_data)

        session["user"] = {**session["user"], "email": email}
        flash("Profile updated.")
        return redirect(url_for("profile"))

    return render_template("profile.html", user_data=user_data)


@app.route("/search")
@login_required
def search():
    user = current_user()
    q = request.args.get("q", "").strip()

    results = []
    if q:
        results = db.query(
            """
            SELECT
                m.message_id,
                m.message_time,
                m.message_text,
                c.channel_id,
                c.channel_name,
                c.channel_type,
                w.workspace_id,
                w.workspace_name,
                u.username AS posted_by,
                u.nickname AS posted_by_nickname
            FROM messages m
            JOIN channels c ON m.channel_id = c.channel_id
            JOIN workspaces w ON c.workspace_id = w.workspace_id
            JOIN users u ON m.user_id = u.user_id
            JOIN channel_membership cm
                ON cm.channel_id = c.channel_id AND cm.user_id = %s
            JOIN workspace_membership wm
                ON wm.workspace_id = w.workspace_id AND wm.user_id = %s
            WHERE m.message_text ILIKE %s
            ORDER BY m.message_time DESC
            LIMIT 100
            """,
            (user["id"], user["id"], f"%{q}%"),
        )

    return render_template("search.html", q=q, results=results)


@app.context_processor
def inject_invitation_count():
    user = current_user()
    if not user:
        return {"pending_invitation_count": 0}
    rows = db.query(
        """
        SELECT
          (SELECT count(*) FROM workspace_invitation
           WHERE invite_status = 'pending'
             AND (invitee_user_id = %s OR invitee_email = %s))
          +
          (SELECT count(*) FROM channel_invitation
           WHERE invite_status = 'pending' AND invitee_user_id = %s)
          AS n
        """,
        (user["id"], user["email"], user["id"]),
    )
    return {"pending_invitation_count": rows[0]["n"] if rows else 0}


if __name__ == "__main__":
    app.run(debug=True)
