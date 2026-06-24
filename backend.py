# -*- coding: utf-8 -*-
"""工作记录 - MySQL 后端 API（多用户版）"""
import uuid
import hashlib
import mysql.connector
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "123456",
    "database": "ta_records",
    "charset": "utf8mb4",
    "collation": "utf8mb4_unicode_ci",
}

def get_db():
    return mysql.connector.connect(**DB_CONFIG)

# ── 密码哈希 ─────────────────────────────────────────
def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

# ── Token 认证装饰器 ─────────────────────────────────
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "未登录，请先登录"}), 401
        token = auth_header[7:]
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            "SELECT s.user_id, u.username FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = %s",
            (token,),
        )
        row = cursor.fetchone()
        cursor.close()
        db.close()
        if not row:
            return jsonify({"error": "登录已过期，请重新登录"}), 401
        # 将 user_id 和 username 注入到请求中
        request.user_id = row["user_id"]
        request.username = row["username"]
        return f(*args, **kwargs)
    return decorated

# ── 健康检查 ──────────────────────────────────────────
@app.route("/api/health")
def health():
    return {"status": "ok"}

# ── 注册 ──────────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"error": "请提供数据"}), 400
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    if len(username) < 2:
        return jsonify({"error": "用户名至少2个字符"}), 400
    if len(password) < 4:
        return jsonify({"error": "密码至少4个字符"}), 400

    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
    if cursor.fetchone():
        cursor.close()
        db.close()
        return jsonify({"error": "用户名已被注册"}), 409

    pwd_hash = hash_password(password)
    cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, pwd_hash))
    user_id = cursor.lastrowid

    # 创建会话 token
    token = uuid.uuid4().hex
    cursor.execute("INSERT INTO sessions (user_id, token) VALUES (%s, %s)", (user_id, token))
    db.commit()
    cursor.close()
    db.close()

    return jsonify({"token": token, "username": username, "user_id": user_id}), 201

# ── 登录 ──────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "请提供数据"}), 400
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, password_hash FROM users WHERE username = %s", (username,)
    )
    user = cursor.fetchone()
    if not user:
        cursor.close()
        db.close()
        return jsonify({"error": "用户名或密码错误"}), 401

    if user["password_hash"] != hash_password(password):
        cursor.close()
        db.close()
        return jsonify({"error": "用户名或密码错误"}), 401

    user_id = user["id"]
    # 创建新会话 token
    token = uuid.uuid4().hex
    cursor.execute("INSERT INTO sessions (user_id, token) VALUES (%s, %s)", (user_id, token))
    db.commit()
    cursor.close()
    db.close()

    return jsonify({"token": token, "username": username, "user_id": user_id})

# ── 获取当前用户信息 ────────────────────────────────
@app.route("/api/auth/me", methods=["GET"])
@require_auth
def me():
    return jsonify({"username": request.username, "user_id": request.user_id})

# ── 登出 ──────────────────────────────────────────────
@app.route("/api/auth/logout", methods=["POST"])
@require_auth
def logout():
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:]
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM sessions WHERE token = %s", (token,))
    db.commit()
    cursor.close()
    db.close()
    return jsonify({"ok": True})

# ── 获取某月所有记录 ────────────────────────────────
@app.route("/api/records", methods=["GET"])
@require_auth
def get_records():
    user_id = request.user_id
    year = request.args.get("year", type=int)
    month = request.args.get("month", type=int)
    if not year or not month:
        return jsonify({"error": "year and month required"}), 400

    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, date_str, slot, role, countable, holiday, note, "
        "COALESCE(type,'') as type, COALESCE(leave_days,0) as leave_days "
        "FROM records WHERE year=%s AND month=%s AND user_id=%s ORDER BY date_str, id",
        (year, month, user_id),
    )
    rows = cursor.fetchall()
    cursor.close()
    db.close()

    result = []
    for r in rows:
        item = {
            "date": r["date_str"],
            "note": r["note"] or "",
            "_id": r["id"],
        }
        if r["type"] == "leave":
            item["type"] = r["type"]
            item["leave_days"] = float(r["leave_days"]) if r["leave_days"] else 0
            item["slot"] = r["slot"] or ""
        else:
            item["slot"] = r["slot"]
            item["role"] = r["role"]
            item["countable"] = float(r["countable"]) if r["countable"] is not None else 0
            item["holiday"] = bool(r["holiday"])
        result.append(item)
    return jsonify(result)

# ── 新增记录 ────────────────────────────────────────
@app.route("/api/records", methods=["POST"])
@require_auth
def add_record():
    user_id = request.user_id
    data = request.get_json()
    if not data:
        return jsonify({"error": "no data"}), 400

    date_str = data.get("date", "")
    if not date_str:
        return jsonify({"error": "date required"}), 400

    parts = date_str.split("-")
    year = int(parts[0])
    month = int(parts[1])
    record_type = data.get("type", "")

    db = get_db()
    cursor = db.cursor()

    if record_type == "leave":
        leave_days = data.get("leave_days", 0.5)
        note = data.get("note", "")
        slot = data.get("slot", "")
        cursor.execute(
            "INSERT INTO records (date_str, type, leave_days, note, slot, role, countable, holiday, year, month, user_id) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (date_str, "leave", leave_days, note, slot, "", 0, 0, year, month, user_id),
        )
    else:
        slot = data.get("slot", "AM")
        role = data.get("role", "assistant")
        countable = float(data.get("countable", 60)) if data.get("countable") else 0
        holiday = 1 if data.get("holiday", False) else 0
        note = data.get("note", "")
        cursor.execute(
            "INSERT INTO records (date_str, slot, role, countable, holiday, note, year, month, user_id) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (date_str, slot, role, countable, holiday, note, year, month, user_id),
        )
    db.commit()
    new_id = cursor.lastrowid
    cursor.close()
    db.close()

    return jsonify({"id": new_id, "ok": True}), 201

# ── 修改记录 ────────────────────────────────────────
@app.route("/api/records/<int:record_id>", methods=["PUT"])
@require_auth
def update_record(record_id):
    user_id = request.user_id
    data = request.get_json()
    if not data:
        return jsonify({"error": "no data"}), 400

    db = get_db()
    cursor = db.cursor()

    # 验证记录属于当前用户
    cursor.execute("SELECT id FROM records WHERE id=%s AND user_id=%s", (record_id, user_id))
    if not cursor.fetchone():
        cursor.close()
        db.close()
        return jsonify({"error": "记录不存在"}), 404

    if "date" in data:
        parts = data["date"].split("-")
        year = int(parts[0])
        month = int(parts[1])
        cursor.execute(
            "UPDATE records SET date_str=%s, year=%s, month=%s WHERE id=%s",
            (data["date"], year, month, record_id),
        )

    fields = {"slot": "slot", "role": "role", "note": "note"}
    for key, col in fields.items():
        if key in data:
            cursor.execute(f"UPDATE records SET {col}=%s WHERE id=%s", (data[key], record_id))

    if "countable" in data:
        cursor.execute(
            "UPDATE records SET countable=%s WHERE id=%s",
            (float(data["countable"]), record_id),
        )
    if "holiday" in data:
        cursor.execute(
            "UPDATE records SET holiday=%s WHERE id=%s",
            (1 if data["holiday"] else 0, record_id),
        )
    if "leave_days" in data:
        cursor.execute(
            "UPDATE records SET leave_days=%s WHERE id=%s",
            (data["leave_days"], record_id),
        )

    db.commit()
    affected = cursor.rowcount
    cursor.close()
    db.close()

    return jsonify({"ok": True, "affected": affected})

# ── 删除记录 ────────────────────────────────────────
@app.route("/api/records/<int:record_id>", methods=["DELETE"])
@require_auth
def delete_record(record_id):
    user_id = request.user_id
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM records WHERE id=%s AND user_id=%s", (record_id, user_id))
    db.commit()
    cursor.close()
    db.close()
    return jsonify({"ok": True})


if __name__ == "__main__":
    print("工作记录后端启动：http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
