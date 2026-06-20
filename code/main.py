import os
from datetime import datetime
import html
import sqlite3 as sql
from flask import Flask, request, session, render_template, redirect
from flask_wtf.csrf import CSRFProtect


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

    cur.execute("""
        SELECT topic_id, title
        FROM topics
        WHERE stage = ?
        ORDER BY topic_id
    """, (stage,))

    rows = cur.fetchall()
    con.close()

    return [
        {
            "id": row["topic_id"],
            "title": row["title"]
        }
        for row in rows
    ]


def get_topic(stage, topic_id):
    con = _get_db_connection()
    cur = con.cursor()
    cur.execute(
        "SELECT title, notes, image, formulas "
        "FROM topics WHERE stage = ? AND topic_id = ?",
        (stage, topic_id),
    )
    row = cur.fetchone()
    con.close()
    if row:
        return {
            "title": row["title"],
            "notes": row["notes"] or "",
            "image": row["image"] or "",
            "formulas": row["formulas"] or "",
        }
    return None


app = Flask(__name__)


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
        # Use HTML escaping for XSS prevention
        input_str = html.escape(input_str)
    
    return input_str

# URL WHITELIST FOR REDIRECTS
ALLOWED_REDIRECTS = ["/", "/success.html"]

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
@app.route("/index.html", methods=["GET"])
def welcome():
    return render_template("index.html")


@app.route("/success.html", methods=["GET"])
def success():
    return render_template("success.html")


@app.route("/search", methods=["GET"])
def search():
    query = sanitize_input(request.args.get("q", ""))
    results = []
    message = None

    if not query:
        message = "Please enter a search term."
    else:
        search_term = f"%{query}%"
        con = _get_db_connection()
        cur = con.cursor()
        cur.execute(
            """
            SELECT stage, topic_id AS id, title
            FROM topics
            WHERE title LIKE ? OR notes LIKE ? OR formulas LIKE ?
            ORDER BY stage, topic_id
            """,
            (search_term, search_term, search_term),
        )
        rows = cur.fetchall()
        con.close()
        results = [
            {
                "stage": row["stage"],
                "id": row["id"],
                "title": row["title"]
            }
            for row in rows
        ]

    return render_template("search.html", query=query, results=results, message=message)


@app.route("/stage<int:stage>")
def stage_page(stage):
    stage_content = get_stage(stage)
    if not stage_content:
        return redirect("/success.html")

    topics = get_topic_buttons(stage)
    return render_template(f"stage{stage}.html", stage=stage, stage_content=stage_content, topics=topics)


@app.route("/stage<int:stage>/topic/<int:topic_id>")
def stage_topic(stage, topic_id):
    stage_content = get_stage(stage)
    if not stage_content:
        return redirect("/success.html")

    db_topic = get_topic(stage, topic_id)
    if not db_topic:
        return redirect(f"/stage{stage}")

    notes_text = db_topic.get("notes", "")
    return render_template(
        "topic.html",
        stage=stage,
        page_title=db_topic.get("title"),
        section1_title="Notes",
        section1_text=notes_text,
        section2_title="Visual Example",
        section2_image=db_topic.get("image", ""),
        section3_title="Formulas",
        section3_formulas=db_topic.get("formulas", ""),
        stage_title=stage_content["title"]
    )


@app.route("/", methods=["GET"])
def welcome_root():
    return render_template("index.html")


@app.route("/index.html", methods=["GET"])
def login_page():
    return render_template("index.html")

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    print("http://0.0.0.0:5001")
    app.run(debug=False, host="0.0.0.0", port=5001)