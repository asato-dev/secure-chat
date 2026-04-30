"""
app.py - エンドツーエンド暗号化チャットアプリ

設計方針:
    - RSA鍵ペアはブラウザ側で生成（Web Crypto API）
    - 秘密鍵はブラウザのlocalStorageのみに保存（サーバーに送らない）
    - 公開鍵はサーバーに登録
    - メッセージの暗号化・復号はブラウザ側で行う
    - サーバーは暗号化されたデータの保存・転送のみ担当

    → サーバー管理者でもメッセージを読めない（エンドツーエンド暗号化）
"""

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from functools import wraps
from database import init_db, get_db
from datetime import timedelta

import os
import bcrypt
import psycopg2
import logging

# ログ設定（エラーの記録）
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

#SECRET_KEY が設定されていない場合はアプリを起動しない
_secret_key = os.environ.get("SECRET_KEY")
if not _secret_key:
    raise RuntimeError("環境変数 SECRET_KEY が設定されていません。起動できません。")
app.secret_key = _secret_key

# セッションの有効期限を2時間に設定
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

    ブラウザ側で生成したRSA公開鍵も受け取ってDBに保存する。
    秘密鍵はブラウザのlocalStorageのみに保存し、サーバーには送らない。
    """
    data       = request.get_json()
    username   = data.get("username",   "").strip()
    password   = data.get("password",   "").strip()
    public_key = data.get("public_key", "").strip()

    if not username or not password or not public_key:
        return jsonify({"error": "全ての項目を入力してください"}), 400

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, password, public_key) VALUES (%s, %s, %s)",
            (username, hash_password(password), public_key)
        )
        conn.commit()
        cur.close()
        return jsonify({"message": "登録成功"})
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "このユーザー名は既に使われています"}), 400
    except Exception as e:
        conn.rollback()
        logger.error("register error: %s", e)  # エラーをログに記録
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

    #permanent=True でセッション有効期限を適用する
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
    """
    自分以外のユーザー一覧を返す API。
    チャット相手を選ぶために使用する。
    """
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
    """
    指定ユーザーのRSA公開鍵を返す API。

    メッセージ送信時にブラウザが受信者の公開鍵を取得するために使用する。
    公開鍵でAES鍵を暗号化し、受信者の秘密鍵でのみ復号できるようにする。
    """
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
    """
    指定ユーザーとの会話を取得する API。

    サーバーは暗号化されたデータをそのまま返すだけ。
    復号はブラウザ側でlocalStorageの秘密鍵を使って行う。
    """
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
    """
    メッセージ送信 API。

    ブラウザ側で暗号化済みのデータを受け取ってDBに保存するだけ。
    サーバーは平文を一切扱わない。

    受け取るデータ:
        receiver_id:   受信者のユーザーID
        content:       AES-CBCで暗号化されたメッセージ本文
        encrypted_key: 受信者の公開鍵でRSA暗号化されたAES鍵
    """
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
    """現在ログイン中のユーザー情報を返す API。"""
    return jsonify({
        "id":       session["user_id"],
        "username": session["username"],
    })


@app.route("/api/account", methods=["DELETE"])
@login_required
def delete_account():
    """
    自分のアカウントを削除する API。

    users テーブルの CASCADE 設定により、
    関連するメッセージも自動的に削除される。
    削除後はセッションをクリアする。
    """
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
        logger.error("delete_account error: %s", e)  #エラーをログに記録
        return jsonify({"error": "削除に失敗しました"}), 500
    finally:
        conn.close()


# ================================================================
# エントリーポイント
# ================================================================

if __name__ == "__main__":
    # host="0.0.0.0" で同じWi-Fi内の他デバイスからもアクセス可能
    app.run(host="0.0.0.0", debug=False, port=8080)