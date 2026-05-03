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
    user = session.get("user")
    if user and not {"id", "username", "email"}.issubset(user):
        session.clear()
        return None
    return user

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

    membership = db.query(
        "SELECT is_admin FROM workspace_membership WHERE workspace_id = %s AND user_id = %s",
        (workspace_id, user["id"]),
    )
    if not membership:
        flash("You don't have access to that workspace.")
        return redirect(url_for("dashboard"))
    is_admin = membership[0]["is_admin"]

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
        is_admin=is_admin,
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


@app.route("/workspace/<workspace_id>/invite", methods=["GET", "POST"])
@login_required
def invite_to_workspace(workspace_id):
    user = current_user()

    is_admin = db.query(
        "SELECT 1 FROM workspace_membership WHERE workspace_id = %s AND user_id = %s AND is_admin = true",
        (workspace_id, user["id"]),
    )
    if not is_admin:
        flash("Only workspace admins can send invitations.")
        return redirect(url_for("workspace", workspace_id=workspace_id))

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
            return render_template("workspace_invite.html", workspace_id=workspace_id, workspace_name=workspace_name)

        existing = db.query("SELECT user_id FROM users WHERE user_email = %s", (invitee_email,))
        invitee_user_id = str(existing[0]["user_id"]) if existing else None

        if invitee_user_id:
            already = db.query(
                "SELECT 1 FROM workspace_membership WHERE workspace_id = %s AND user_id = %s",
                (workspace_id, invitee_user_id),
            )
            if already:
                flash(f"{invitee_email} is already a member of this workspace.")
                return render_template("workspace_invite.html", workspace_id=workspace_id, workspace_name=workspace_name)

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
            return render_template("workspace_invite.html", workspace_id=workspace_id, workspace_name=workspace_name)

        flash(f"Invitation sent to {invitee_email}.")
        return redirect(url_for("workspace", workspace_id=workspace_id))

    return render_template("workspace_invite.html", workspace_id=workspace_id, workspace_name=workspace_name)


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
            return render_template("channel_invite.html", channel_id=channel_id, channel=channel)

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
            return render_template("channel_invite.html", channel_id=channel_id, channel=channel)
        invitee_user_id = str(rows[0]["user_id"])

        if invitee_user_id == user["id"]:
            flash("You can't invite yourself.")
            return render_template("channel_invite.html", channel_id=channel_id, channel=channel)

        already = db.query(
            "SELECT 1 FROM channel_membership WHERE channel_id = %s AND user_id = %s",
            (channel_id, invitee_user_id),
        )
        if already:
            flash(f"{username} is already in this channel.")
            return render_template("channel_invite.html", channel_id=channel_id, channel=channel)

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
            return render_template("channel_invite.html", channel_id=channel_id, channel=channel)

        flash(f"Invitation sent to {username}.")
        return redirect(url_for("channel", channel_id=channel_id))

    return render_template("channel_invite.html", channel_id=channel_id, channel=channel)


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

    return render_template(
        "workspace_members.html",
        workspace_id=workspace_id,
        workspace_name=ws[0]["workspace_name"],
        is_admin=is_admin,
        members=members,
        stale_invites=stale_invites,
        current_user_id=user["id"],
    )


@app.route("/workspace/<workspace_id>/members/<member_id>/promote", methods=["POST"])
@login_required
def promote_member(workspace_id, member_id):
    user = current_user()

    is_admin = db.query(
        "SELECT 1 FROM workspace_membership WHERE workspace_id = %s AND user_id = %s AND is_admin = true",
        (workspace_id, user["id"]),
    )
    if not is_admin:
        flash("Only workspace admins can promote members.")
        return redirect(url_for("workspace_members", workspace_id=workspace_id))

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
