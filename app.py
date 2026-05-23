"""
app.py - エンドツーエンド暗号化チャットアプリ

設計方針:
    - RSA鍵ペアはブラウザ側で生成（Web Crypto API）
    - 秘密鍵はlocalStorageに保存し、さらにPBKDF2でサーバーにバックアップ（v2）
    - 公開鍵はサーバーに登録
    - メッセージの暗号化・復号はブラウザ側で行う
    - サーバーは暗号化されたデータの保存・転送のみ担当

    → サーバー管理者でもメッセージを読めない（エンドツーエンド暗号化）

v1からの変更点:
    - AES-CBC → AES-GCM（crypto.js側の変更）
    - 登録時に encrypted_private_key も同時に保存するよう変更（v2）
    - /api/account/encrypted-key エンドポイントを追加（秘密鍵バックアップ用）
"""

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from functools import wraps
from database import init_db, get_db
from datetime import timedelta

import os
import re
import bcrypt
import psycopg2
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

_secret_key = os.environ.get("SECRET_KEY")
if not _secret_key:
    raise RuntimeError("環境変数 SECRET_KEY が設定されていません。起動できません。")
app.secret_key = _secret_key

app.permanent_session_lifetime = timedelta(hours=2)

with app.app_context():
    init_db()


# ================================================================
# ユーティリティ
# ================================================================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


# ================================================================
# ページルーティング
# ================================================================

@app.route("/")
@login_required
def index():
    return render_template("chat.html")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/register")
def register_page():
    return render_template("register.html")


# ================================================================
# 認証 API
# ================================================================

@app.route("/api/register", methods=["POST"])
def register():
    """
    ユーザー登録 API。

    ブラウザ側で生成したRSA公開鍵と、PBKDF2で暗号化したRSA秘密鍵を
    同時に受け取ってDBに保存する。
    平文の秘密鍵はサーバーに送らない。

    v2変更: encrypted_private_key を登録時に同時に保存することで
    セッションなしでもバックアップが完了する。
    """
    data                  = request.get_json()
    username              = data.get("username",              "").strip()
    password              = data.get("password",              "").strip()
    public_key            = data.get("public_key",            "").strip()
    encrypted_private_key = data.get("encrypted_private_key", "").strip()

    if not username or not password or not public_key:
        return jsonify({"error": "全ての項目を入力してください"}), 400

    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({"error": "ユーザー名は英数字とアンダースコアのみ使用できます"}), 400

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, password, public_key, encrypted_private_key)"
            " VALUES (%s, %s, %s, %s)",
            (username, hash_password(password), public_key, encrypted_private_key or None)
        )
        conn.commit()
        cur.close()
        return jsonify({"message": "登録成功"})
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "このユーザー名は既に使われています"}), 400
    except Exception as e:
        conn.rollback()
        logger.error("register error: %s", e)
        return jsonify({"error": "登録に失敗しました"}), 500
    finally:
        conn.close()


@app.route("/api/login", methods=["POST"])
def login():
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user or not check_password(password, user["password"]):
        return jsonify({"error": "ユーザー名またはパスワードが違います"}), 401

    session.permanent  = True
    session["user_id"]  = user["id"]
    session["username"] = user["username"]
    return jsonify({"message": "ログイン成功"})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "ログアウトしました"})


# ================================================================
# ユーザー API
# ================================================================

@app.route("/api/users", methods=["GET"])
@login_required
def get_users():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT id, username FROM users WHERE id != %s ORDER BY username",
        (session["user_id"],)
    )
    users = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([dict(u) for u in users])


@app.route("/api/users/<int:user_id>/public-key", methods=["GET"])
@login_required
def get_public_key(user_id):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT public_key FROM users WHERE id=%s", (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user:
        return jsonify({"error": "ユーザーが見つかりません"}), 404
    return jsonify({"public_key": user["public_key"]})


# ================================================================
# メッセージ API
# ================================================================

@app.route("/api/messages/<int:partner_id>", methods=["GET"])
@login_required
def get_messages(partner_id):
    conn = get_db()
    cur  = conn.cursor()
    cur.execute("""
        SELECT
            m.id,
            m.sender_id,
            m.receiver_id,
            m.content,
            m.encrypted_key,
            m.encrypted_key_for_sender,
            m.created_at,
            u.username AS sender_name
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        WHERE
            (m.sender_id = %s AND m.receiver_id = %s)
            OR
            (m.sender_id = %s AND m.receiver_id = %s)
        ORDER BY m.created_at ASC
    """, (
        session["user_id"], partner_id,
        partner_id, session["user_id"]
    ))
    messages = cur.fetchall()
    cur.close()
    conn.close()

    return jsonify([{
        "id":                      m["id"],
        "sender_id":               m["sender_id"],
        "receiver_id":             m["receiver_id"],
        "content":                 m["content"],
        "encrypted_key":           m["encrypted_key"],
        "encrypted_key_for_sender": m["encrypted_key_for_sender"],
        "created_at":              str(m["created_at"]),
        "sender_name":             m["sender_name"],
        "is_mine":                 m["sender_id"] == session["user_id"],
    } for m in messages])


@app.route("/api/messages", methods=["POST"])
@login_required
def send_message():
    data                  = request.get_json()
    receiver_id           = data.get("receiver_id")
    content               = data.get("content",                "").strip()
    encrypted_key         = data.get("encrypted_key",          "").strip()
    encrypted_key_for_sender = data.get("encrypted_key_for_sender", "").strip()

    if not receiver_id or not content or not encrypted_key:
        return jsonify({"error": "データが不足しています"}), 400

    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "INSERT INTO messages (sender_id, receiver_id, content, encrypted_key, encrypted_key_for_sender)"
        " VALUES (%s, %s, %s, %s, %s)",
        (session["user_id"], receiver_id, content, encrypted_key, encrypted_key_for_sender or None)
    )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "送信しました"})


@app.route("/api/me", methods=["GET"])
@login_required
def get_me():
    return jsonify({
        "id":       session["user_id"],
        "username": session["username"],
    })


# ================================================================
# アカウント API
# ================================================================

@app.route("/api/account/username", methods=["PUT"])
@login_required
def change_username():
    data         = request.get_json()
    new_username = data.get("username", "").strip()

    if not new_username:
        return jsonify({"error": "ユーザー名を入力してください"}), 400

    if not re.match(r'^[a-zA-Z0-9_]+$', new_username):
        return jsonify({"error": "ユーザー名は英数字とアンダースコアのみ使用できます"}), 400

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET username=%s WHERE id=%s",
            (new_username, session["user_id"])
        )
        conn.commit()
        cur.close()
        session["username"] = new_username
        return jsonify({"message": "ユーザー名を変更しました"})
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "このユーザー名は既に使われています"}), 400
    except Exception as e:
        conn.rollback()
        logger.error("change_username error: %s", e)
        return jsonify({"error": "変更に失敗しました"}), 500
    finally:
        conn.close()


@app.route("/api/account/password", methods=["PUT"])
@login_required
def change_password():
    data         = request.get_json()
    old_password = data.get("old_password", "").strip()
    new_password = data.get("new_password", "").strip()

    if not old_password or not new_password:
        return jsonify({"error": "全ての項目を入力してください"}), 400

    if len(new_password) < 8:
        return jsonify({"error": "新しいパスワードは8文字以上にしてください"}), 400

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT password FROM users WHERE id=%s", (session["user_id"],))
        user = cur.fetchone()

        if not check_password(old_password, user["password"]):
            return jsonify({"error": "現在のパスワードが違います"}), 401

        cur.execute(
            "UPDATE users SET password=%s WHERE id=%s",
            (hash_password(new_password), session["user_id"])
        )
        conn.commit()
        cur.close()
        return jsonify({"message": "パスワードを変更しました"})
    except Exception as e:
        conn.rollback()
        logger.error("change_password error: %s", e)
        return jsonify({"error": "変更に失敗しました"}), 500
    finally:
        conn.close()


@app.route("/api/account/encrypted-key", methods=["PUT"])
@login_required
def save_encrypted_key():
    """
    ログインパスワードから派生した鍵で暗号化されたRSA秘密鍵を
    サーバーに保存するAPI。パスワード変更時などに使用。
    サーバーはパスワードも派生鍵も知らないため、中身を読めない。
    """
    data          = request.get_json()
    encrypted_key = data.get("encrypted_key", "").strip()

    if not encrypted_key:
        return jsonify({"error": "データが不足しています"}), 400

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET encrypted_private_key=%s WHERE id=%s",
            (encrypted_key, session["user_id"])
        )
        conn.commit()
        cur.close()
        return jsonify({"message": "秘密鍵をバックアップしました"})
    except Exception as e:
        conn.rollback()
        logger.error("save_encrypted_key error: %s", e)
        return jsonify({"error": "保存に失敗しました"}), 500
    finally:
        conn.close()


@app.route("/api/account/encrypted-key", methods=["GET"])
@login_required
def get_encrypted_key():
    """
    暗号化されたRSA秘密鍵をサーバーから取得するAPI。
    機種変更後のログイン時にブラウザが呼び出す。
    サーバーは暗号化されたデータを返すだけで中身は読めない。
    """
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT encrypted_private_key FROM users WHERE id=%s",
        (session["user_id"],)
    )
    user = cur.fetchone()
    cur.close()
    conn.close()
    return jsonify({"encrypted_key": user["encrypted_private_key"]})


@app.route("/api/account", methods=["DELETE"])
@login_required
def delete_account():
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id=%s", (session["user_id"],))
        conn.commit()
        cur.close()
        session.clear()
        return jsonify({"message": "アカウントを削除しました"})
    except Exception as e:
        conn.rollback()
        logger.error("delete_account error: %s", e)
        return jsonify({"error": "削除に失敗しました"}), 500
    finally:
        conn.close()


# ================================================================
# エントリーポイント
# ================================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=False, port=8080)
