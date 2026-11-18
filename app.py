import os, sqlite3, uuid, mimetypes
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "storage")
DB_PATH = os.path.join(BASE_DIR, "cloud_storage.db")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB per upload

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
            quota_mb INTEGER NOT NULL DEFAULT 500, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS folders(
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
            owner_id INTEGER NOT NULL, parent_id INTEGER,
            created_at TEXT NOT NULL, FOREIGN KEY(owner_id) REFERENCES users(id),
            FOREIGN KEY(parent_id) REFERENCES folders(id)
        );
        CREATE TABLE IF NOT EXISTS files(
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
            stored_name TEXT NOT NULL, folder_id INTEGER, owner_id INTEGER NOT NULL,
            size INTEGER NOT NULL, mime_type TEXT, version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            FOREIGN KEY(folder_id) REFERENCES folders(id),
            FOREIGN KEY(owner_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS shares(
            id INTEGER PRIMARY KEY AUTOINCREMENT, file_id INTEGER NOT NULL,
            shared_with INTEGER NOT NULL, permission TEXT NOT NULL DEFAULT 'view',
            created_at TEXT NOT NULL, UNIQUE(file_id, shared_with),
            FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY(shared_with) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
            action TEXT NOT NULL, details TEXT, created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)
        admin = con.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if not admin:
            con.execute("INSERT INTO users(username,password,role,quota_mb,created_at) VALUES(?,?,?,?,?)",
                        ("admin", generate_password_hash("Admin@123"), "admin", 5000, now()))
        demo = con.execute("SELECT id FROM users WHERE username='demo'").fetchone()
        if not demo:
            con.execute("INSERT INTO users(username,password,role,quota_mb,created_at) VALUES(?,?,?,?,?)",
                        ("demo", generate_password_hash("User@123"), "user", 500, now()))

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log(action, details=""):
    if session.get("user_id"):
        with db() as con:
            con.execute("INSERT INTO logs(user_id,action,details,created_at) VALUES(?,?,?,?)",
                        (session["user_id"], action, details, now()))

def current_user():
    if not session.get("user_id"):
        return None
    with db() as con:
        return con.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user["role"] != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

def used_bytes(user_id):
    with db() as con:
        row = con.execute("SELECT COALESCE(SUM(size),0) n FROM files WHERE owner_id=?", (user_id,)).fetchone()
    return row["n"]

@app.context_processor
def inject_user():
    return {"logged_user": current_user(), "used_bytes": used_bytes}

@app.route("/")
def index():
    return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username, password = request.form["username"].strip(), request.form["password"]
        if len(username) < 3 or len(password) < 6:
            flash("Username must be 3+ characters and password 6+ characters.", "error")
        else:
            try:
                with db() as con:
                    con.execute("INSERT INTO users(username,password,role,created_at) VALUES(?,?,?,?)",
                                (username, generate_password_hash(password), "user", now()))
                flash("Account created. Please sign in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is already taken.", "error")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        with db() as con:
            user = con.execute("SELECT * FROM users WHERE username=?", (request.form["username"].strip(),)).fetchone()
        if user and check_password_hash(user["password"], request.form["password"]):
            session.clear()
            session["user_id"] = user["id"]
            log("LOGIN", "Signed in")
            return redirect(url_for("dashboard"))
        flash("Incorrect username or password.", "error")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    log("LOGOUT", "Signed out")
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    with db() as con:
        own_files = con.execute("SELECT COUNT(*) n FROM files WHERE owner_id=?", (user["id"],)).fetchone()["n"]
        folders = con.execute("SELECT COUNT(*) n FROM folders WHERE owner_id=?", (user["id"],)).fetchone()["n"]
        shared = con.execute("""SELECT COUNT(*) n FROM shares s JOIN files f ON f.id=s.file_id
                              WHERE s.shared_with=?""", (user["id"],)).fetchone()["n"]
        recent = con.execute("""SELECT f.*,u.username owner FROM files f JOIN users u ON u.id=f.owner_id
                             WHERE f.owner_id=? OR f.id IN (SELECT file_id FROM shares WHERE shared_with=?)
                             ORDER BY f.updated_at DESC LIMIT 8""", (user["id"], user["id"])).fetchall()
    used = used_bytes(user["id"])
    return render_template("dashboard.html", own_files=own_files, folders=folders, shared=shared,
                           recent=recent, used=used, quota=user["quota_mb"]*1024*1024)

@app.route("/files")
@login_required
def files():
    folder_id = request.args.get("folder_id", type=int)
    user = current_user()
    with db() as con:
        if folder_id:
            folder = con.execute("SELECT * FROM folders WHERE id=? AND owner_id=?", (folder_id,user["id"])).fetchone()
            if not folder: abort(404)
            rows = con.execute("SELECT * FROM files WHERE folder_id=? AND owner_id=? ORDER BY name",
                               (folder_id,user["id"])).fetchall()
            subfolders = con.execute("SELECT * FROM folders WHERE parent_id=? AND owner_id=? ORDER BY name",
                                     (folder_id,user["id"])).fetchall()
        else:
            folder = None
            rows = con.execute("SELECT * FROM files WHERE folder_id IS NULL AND owner_id=? ORDER BY name",
                               (user["id"],)).fetchall()
            subfolders = con.execute("SELECT * FROM folders WHERE parent_id IS NULL AND owner_id=? ORDER BY name",
                                     (user["id"],)).fetchall()
    return render_template("files.html", files=rows, folders=subfolders, folder=folder)

@app.route("/folders/create", methods=["POST"])
@login_required
def create_folder():
    name = secure_filename(request.form["name"].strip())
    if not name:
        flash("Enter a valid folder name.", "error")
    else:
        with db() as con:
            con.execute("INSERT INTO folders(name,owner_id,parent_id,created_at) VALUES(?,?,?,?)",
                        (name, session["user_id"], request.form.get("parent_id") or None, now()))
        log("CREATE_FOLDER", name)
        flash("Folder created.", "success")
    return redirect(request.referrer or url_for("files"))

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files.get("file")
    if not file or not file.filename:
        flash("Choose a file first.", "error")
        return redirect(request.referrer or url_for("files"))
    user = current_user()
    data = file.read()
    if used_bytes(user["id"]) + len(data) > user["quota_mb"] * 1024 * 1024:
        flash("Storage limit reached. Delete files or ask the administrator to increase your quota.", "error")
        return redirect(request.referrer or url_for("files"))
    original = secure_filename(file.filename)
    stored = uuid.uuid4().hex + "_" + original
    with open(os.path.join(UPLOAD_DIR, stored), "wb") as out:
        out.write(data)
    folder_id = request.form.get("folder_id") or None
    with db() as con:
        con.execute("""INSERT INTO files(name,stored_name,folder_id,owner_id,size,mime_type,version,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,1,?,?)""",
                    (original, stored, folder_id, user["id"], len(data),
                     file.mimetype or mimetypes.guess_type(original)[0], now(), now()))
    log("UPLOAD", original)
    flash("File uploaded successfully.", "success")
    return redirect(request.referrer or url_for("files"))

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    user = current_user()
    with db() as con:
        row = con.execute("""SELECT f.* FROM files f LEFT JOIN shares s ON s.file_id=f.id AND s.shared_with=?
                           WHERE f.id=? AND (f.owner_id=? OR s.id IS NOT NULL)""",
                          (user["id"],file_id,user["id"])).fetchone()
    if not row: abort(404)
    log("DOWNLOAD", row["name"])
    return send_from_directory(UPLOAD_DIR, row["stored_name"], as_attachment=True, download_name=row["name"])

@app.route("/preview/<int:file_id>")
@login_required
def preview(file_id):
    user = current_user()
    with db() as con:
        row = con.execute("""SELECT f.* FROM files f LEFT JOIN shares s ON s.file_id=f.id AND s.shared_with=?
                           WHERE f.id=? AND (f.owner_id=? OR s.id IS NOT NULL)""",
                          (user["id"],file_id,user["id"])).fetchone()
    if not row: abort(404)
    log("PREVIEW", row["name"])
    return send_from_directory(UPLOAD_DIR, row["stored_name"], as_attachment=False,
                               download_name=row["name"], mimetype=row["mime_type"])

@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    with db() as con:
        row = con.execute("SELECT * FROM files WHERE id=? AND owner_id=?", (file_id,session["user_id"])).fetchone()
        if not row: abort(404)
        con.execute("DELETE FROM files WHERE id=?", (file_id,))
    try: os.remove(os.path.join(UPLOAD_DIR,row["stored_name"]))
    except OSError: pass
    log("DELETE", row["name"])
    flash("File deleted.", "success")
    return redirect(request.referrer or url_for("files"))

@app.route("/share/<int:file_id>", methods=["GET","POST"])
@login_required
def share(file_id):
    user = current_user()
    with db() as con:
        file_row = con.execute("SELECT * FROM files WHERE id=? AND owner_id=?", (file_id,user["id"])).fetchone()
        if not file_row: abort(404)
        users = con.execute("SELECT id,username FROM users WHERE id!=? ORDER BY username",(user["id"],)).fetchall()
        if request.method == "POST":
            target = request.form.get("user_id", type=int)
            permission = request.form.get("permission","view")
            if permission not in ("view","edit"): permission="view"
            if not target:
                flash("Choose a user.", "error")
            else:
                con.execute("""INSERT INTO shares(file_id,shared_with,permission,created_at) VALUES(?,?,?,?)
                            ON CONFLICT(file_id,shared_with) DO UPDATE SET permission=excluded.permission""",
                            (file_id,target,permission,now()))
                log("SHARE", f"{file_row['name']} shared with user {target} ({permission})")
                flash("File shared.", "success")
                return redirect(url_for("files"))
        shares = con.execute("""SELECT s.*,u.username FROM shares s JOIN users u ON u.id=s.shared_with
                             WHERE s.file_id=?""",(file_id,)).fetchall()
    return render_template("share.html", file=file_row, users=users, shares=shares)

@app.route("/shared")
@login_required
def shared():
    with db() as con:
        rows = con.execute("""SELECT f.*,u.username owner,s.permission FROM shares s
                           JOIN files f ON f.id=s.file_id JOIN users u ON u.id=f.owner_id
                           WHERE s.shared_with=? ORDER BY s.created_at DESC""",(session["user_id"],)).fetchall()
    return render_template("shared.html", files=rows)

@app.route("/reports")
@login_required
def reports():
    user = current_user()
    with db() as con:
        if user["role"] == "admin":
            storage = con.execute("""SELECT u.username,COUNT(f.id) file_count,COALESCE(SUM(f.size),0) bytes
                                  FROM users u LEFT JOIN files f ON f.owner_id=u.id GROUP BY u.id ORDER BY bytes DESC""").fetchall()
            uploads = con.execute("""SELECT f.name,u.username,f.size,f.created_at FROM files f JOIN users u
                                  ON u.id=f.owner_id ORDER BY f.created_at DESC LIMIT 100""").fetchall()
            shares = con.execute("""SELECT f.name,u.username owner,v.username recipient,s.permission,s.created_at
                                  FROM shares s JOIN files f ON f.id=s.file_id JOIN users u ON u.id=f.owner_id
                                  JOIN users v ON v.id=s.shared_with ORDER BY s.created_at DESC""").fetchall()
            activity = con.execute("""SELECT l.*,u.username FROM logs l LEFT JOIN users u ON u.id=l.user_id
                                   ORDER BY l.created_at DESC LIMIT 100""").fetchall()
        else:
            storage = con.execute("SELECT username,? file_count,? bytes FROM users WHERE id=?",
                                  (con.execute("SELECT COUNT(*) FROM files WHERE owner_id=?",(user["id"],)).fetchone()[0],
                                   used_bytes(user["id"]),user["id"])).fetchall()
            uploads = con.execute("SELECT name,? username,size,created_at FROM files WHERE owner_id=? ORDER BY created_at DESC",
                                  (user["username"],user["id"])).fetchall()
            shares = con.execute("""SELECT f.name,u.username owner,v.username recipient,s.permission,s.created_at
                                  FROM shares s JOIN files f ON f.id=s.file_id JOIN users u ON u.id=f.owner_id
                                  JOIN users v ON v.id=s.shared_with WHERE f.owner_id=? OR s.shared_with=?""",
                                  (user["id"],user["id"])).fetchall()
            activity = con.execute("SELECT l.*,? username FROM logs l WHERE user_id=? ORDER BY created_at DESC",
                                   (user["username"],user["id"])).fetchall()
    return render_template("reports.html", storage=storage, uploads=uploads, shares=shares, activity=activity)

@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    with db() as con:
        users = con.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    return render_template("admin_users.html", users=users)

@app.route("/admin/quota/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def update_quota(user_id):
    quota = max(1, min(100000, request.form.get("quota_mb",type=int) or 500))
    with db() as con:
        con.execute("UPDATE users SET quota_mb=? WHERE id=?", (quota,user_id))
    log("UPDATE_QUOTA", f"user {user_id}: {quota} MB")
    flash("Storage quota updated.", "success")
    return redirect(url_for("admin_users"))

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403
@app.errorhandler(404)
def missing(e):
    return render_template("error.html", code=404, message="The requested item was not found."), 404
@app.errorhandler(413)
def too_large(e):
    return render_template("error.html", code=413, message="Upload is larger than the 100 MB request limit."), 413

init_db()
if __name__ == "__main__":
    app.run(debug=True)
