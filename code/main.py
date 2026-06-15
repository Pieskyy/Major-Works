import os
import secrets
from datetime import datetime, timedelta
from io import BytesIO
import base64
import threading
import json
import sqlite3 as sql

from flask import Flask, request, session, render_template, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp
from qrcode import QRCode
from werkzeug.utils import secure_filename

import user_management as dbHandler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database_files", "database.db")


def _get_db_connection():
    con = sql.connect(DB_PATH)
    con.row_factory = sql.Row
    return con


def get_stage(stage):
    con = _get_db_connection()
    cur = con.cursor()
    cur.execute("SELECT title, subtitle FROM stages WHERE stage = ?", (stage,))
    row = cur.fetchone()
    con.close()
    if not row:
        return None
    return {"title": row["title"], "subtitle": row["subtitle"] or ""}


def get_stage_topics(stage):
    con = _get_db_connection()
    cur = con.cursor()
    cur.execute("SELECT topic_id FROM topics WHERE stage = ? ORDER BY topic_id", (stage,))
    rows = cur.fetchall()
    con.close()
    return [{"id": row["topic_id"], "name": f"Topic {row['topic_id']}"} for row in rows]


def get_topic(stage, topic_id):
    con = _get_db_connection()
    cur = con.cursor()
    cur.execute(
        "SELECT title, summary, text, notes, image, formulas "
        "FROM topics WHERE stage = ? AND topic_id = ?",
        (stage, topic_id),
    )
    row = cur.fetchone()
    con.close()
    if row:
        return {
            "title": row["title"],
            "summary": row["summary"] or "",
            "text": row["text"] or "",
            "notes": row["notes"] or "",
            "image": row["image"] or "",
            "formulas": row["formulas"] or "",
        }
    return None


app = Flask(__name__)
csrf = CSRFProtect(app) # CSRF protection

# SECRET KEY (not really secure but whatever)
SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.secret_key = SECRET_KEY

# RATE LIMITING
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# SESSION MANAGEMENT - Set session to expire after 30 minutes of inactivity
app.permanent_session_lifetime = timedelta(minutes=30)

@app.before_request
def make_session_permanent():
    session.permanent = True


@app.context_processor
def inject_user_profile():
    """Injects `user_avatar` and `display_name` into templates when user is logged in."""
    username = session.get('username')
    if not username:
        return {}
    profiles_dir = os.path.join(os.getcwd(), "database_files", "profiles")
    profile_path = os.path.join(profiles_dir, f"{username}.json")
    try:
        if os.path.exists(profile_path):
            with open(profile_path, 'r', encoding='utf-8') as pf:
                data = json.load(pf)
                avatar = data.get('avatar')
                return { 'user_avatar': avatar, 'display_name': username }
    except Exception:
        pass
    return { 'user_avatar': None, 'display_name': username }
# SECURITY HEADERS - Set security headers to mitigate common web vulnerabilities
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY' # Prevent clickjacking
    response.headers['Content-Security-Policy'] = ( # CSP to prevent XSS and other injection attacks
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data: https:; "
        "frame-ancestors 'none'; "
        "form-action 'self';"
    )
    return response

# INPUT SANITIZATION FUNCTION
def sanitize_input(input_str, max_length=255, allow_html=False):
    if not input_str:
        return ""
    
    # Convert to string if not already
    input_str = str(input_str)
    
    # Remove null bytes and other dangerous characters
    input_str = input_str.replace('\x00', '').replace('\r', '').replace('\n', '')
    
    # Limit length to prevent buffer overflow
    input_str = input_str[:max_length]
    
    # Trim whitespace
    input_str = input_str.strip()
    
    if not allow_html:
        # Use HTML escaping for XSS prevention (same as make_web_safe)
        from hash import make_web_safe
        input_str = make_web_safe(input_str)
    
    return input_str

# URL WHITELIST FOR REDIRECTS
ALLOWED_REDIRECTS = ["/", "/signup.html", "/success.html"]

def get_topic_buttons(stage):
    return get_stage_topics(stage)


def is_valid_dob(value):
    # DOB is optional now; empty value is acceptable
    if not value:
        return True
    try:
        # HTML date inputs use YYYY-MM-DD
        datetime.strptime(value, '%Y-%m-%d')
        return True
    except ValueError:
        return False


# ROUTES 
@app.route("/welcome.html", methods=["GET"])
def welcome():
    return render_template("welcome.html")


@app.route("/success.html", methods=["GET"])
def success():
    # SECURITY FIX: Ensure user is authenticated before showing stage choices
    if 'username' not in session:
        return redirect("/")
    return render_template("success.html")

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if 'username' not in session:
        return redirect("/")

    username = session['username']
    profiles_dir = os.path.join(os.getcwd(), "database_files", "profiles")
    os.makedirs(profiles_dir, exist_ok=True)

    avatar_url = None
    bio_text = ""

    profile_path = os.path.join(profiles_dir, f"{username}.json")

    # Load existing profile if present
    try:
        import json
        if os.path.exists(profile_path):
            with open(profile_path, 'r', encoding='utf-8') as pf:
                data = json.load(pf)
                bio_text = data.get('bio', '')
                avatar = data.get('avatar')
                if avatar and os.path.exists(os.path.join(os.getcwd(), avatar.lstrip('/'))):
                    avatar_url = avatar
    except Exception:
        pass

    if request.method == 'POST':
        # Update bio
        bio = sanitize_input(request.form.get('bio', ''), max_length=2000)
        # Handle avatar upload (optional)
        file = request.files.get('avatar')
        saved_avatar = None
        if file and file.filename:
            filename = secure_filename(file.filename)
            uploads_dir = os.path.join(os.getcwd(), 'static', 'uploads')
            os.makedirs(uploads_dir, exist_ok=True)
            # Prefix with username to avoid collisions
            dest_name = f"{username}_avatar_{filename}"
            dest_path = os.path.join(uploads_dir, dest_name)
            file.save(dest_path)
            # URL path for templates
            saved_avatar = f"/static/uploads/{dest_name}"

        # Persist profile
        try:
            import json
            data = {'bio': bio, 'avatar': saved_avatar or avatar_url}
            with open(profile_path, 'w', encoding='utf-8') as pf:
                json.dump(data, pf)
            bio_text = bio
            avatar_url = data.get('avatar')
        except Exception:
            pass

    return render_template("profile.html", username=username, bio=bio_text, avatar_url=avatar_url)


@app.route("/stage<int:stage>")
def stage_page(stage):
    if 'username' not in session:
        return redirect("/")

    stage_content = get_stage(stage)
    if not stage_content:
        return redirect("/success.html")

    topics = get_topic_buttons(stage)
    return render_template(f"stage{stage}.html", stage=stage, stage_content=stage_content, topics=topics)


@app.route("/stage<int:stage>/topic/<int:topic_id>")
def stage_topic(stage, topic_id):
    if 'username' not in session:
        return redirect("/")

    stage_content = get_stage(stage)
    if not stage_content:
        return redirect("/success.html")

    db_topic = get_topic(stage, topic_id)
    if not db_topic:
        return redirect(f"/stage{stage}")

    notes_text = db_topic.get("notes") or db_topic.get("text", "")
    return render_template(
        "topic.html",
        stage=stage,
        page_title=db_topic.get("title"),
        page_summary=db_topic.get("summary"),
        section1_title="Notes",
        section1_text=notes_text,
        section2_title="Visual Example",
        section2_image=db_topic.get("image", ""),
        section3_title="Formulas",
        section3_formulas=db_topic.get("formulas", ""),
        stage_title=stage_content["title"]
    )


@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    url = request.args.get("url", "")
    if url not in ALLOWED_REDIRECTS:
        url = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        dob = request.form.get("dob", "")
        
        # Sanitize inputs to prevent XSS and injection attacks
        username = sanitize_input(username, max_length=50)
        dob = sanitize_input(dob, max_length=20)
        
        if not username:
            return render_template("signup.html", error="Username is required.", username=username, dob=dob)
        if not is_valid_dob(dob):
            return render_template("signup.html", error="Please enter your date of birth in YYYY-MM-DD format.", username=username, dob=dob)

        try:
            dbHandler.validate_password(password)  # Password validation
        except Exception as err:
            return render_template("weak_password.html", error=str(err), username=username, dob=dob)

        try:
            dbHandler.insertUser(username, password, dob)
            return render_template("index.html")
        except ValueError as err:
            # Handle username already exists error
            return render_template("signup_error.html", error=str(err))
    else:
        return render_template("signup.html")


@app.route("/", methods=["GET"])
def welcome_root():
    return render_template("welcome.html")


@app.route("/login", methods=["POST", "GET"])
@app.route("/index.html", methods=["POST", "GET"])
@limiter.limit("10 per minute")
def login():
    url = request.args.get("url", "")
    if url not in ALLOWED_REDIRECTS:
        url = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        # Sanitize inputs to prevent XSS and injection attacks
        username = sanitize_input(username, max_length=50)

        if dbHandler.retrieveUsers(username, password):
            session['username'] = username

            existing_secret = dbHandler.getUserTwoFASecret(username)
            if existing_secret:
                # User has 2FA enabled, require verification
                user_secret = existing_secret
                session['user_secret'] = user_secret
                return render_template("enable_2fa.html")  # No QR, just verify
            else:
                # No 2FA, login directly
                session['authenticated'] = True
                return redirect("/success.html")
        else:
            return render_template("index.html")
    else:
        return render_template("index.html")


@app.route("/enable_2fa.html", methods=["POST", "GET"])
@csrf.exempt
def enable_2fa():
    if request.method == "POST":
        otp_input = request.form.get("otp", "")
        user_secret = session.get("user_secret")
        username = session.get("username")

        if user_secret and username:
            totp = pyotp.TOTP(user_secret)
            if totp.verify(otp_input):
                dbHandler.setUserTwoFASecret(username, user_secret)
                return redirect("/success.html")
            else:
                return "Invalid OTP. Please try again.", 401
        else:
            return "Invalid OTP. Please try again.", 401

    return render_template("enable_2fa.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/setup_2fa")
def setup_2fa():
    if 'username' not in session:
        return redirect("/")
    username = session['username']
    existing_secret = dbHandler.getUserTwoFASecret(username)
    if existing_secret:
        return "2FA already enabled"
    user_secret = pyotp.random_base32()
    session['user_secret'] = user_secret
    totp = pyotp.TOTP(user_secret)
    otp_uri = totp.provisioning_uri(name=username, issuer_name="AdamsecurePWA")
    qr = QRCode()
    qr.add_data(otp_uri)
    qr.make(fit=True)
    stream = BytesIO()
    qr.make_image(fill='black', back_color='white').save(stream)
    qr_code_b64 = base64.b64encode(stream.getvalue()).decode('utf-8')
    return render_template("enable_2fa.html", qr_code=qr_code_b64, secret=user_secret)


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    print("http://0.0.0.0:5001")
    app.run(debug=False, host="0.0.0.0", port=5001)