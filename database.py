"""
database.py - データベース接続・初期化モジュール

PostgreSQL への接続と、チャットアプリが必要とするテーブルの初期作成を行う。

テーブル設計:
    users:    ユーザー情報 + RSA公開鍵 + 暗号化済みRSA秘密鍵（v2追加）
              秘密鍵はlocalStorageに保存し、さらにPBKDF2でバックアップ

    messages: 暗号化されたメッセージ
              content:       AES-GCMで暗号化されたメッセージ本文（v2: CBC→GCM）
              encrypted_key: 受信者の公開鍵でRSA暗号化されたAES鍵
              → サーバーはメッセージの中身を読めない
"""

import os
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")


def get_db():
    """
    データベース接続を生成して返す。
    呼び出し元は使用後に conn.close() を呼ぶこと。
    """
    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=psycopg2.extras.RealDictCursor
    )


def init_db():
    """アプリが必要とするテーブルを初期作成する。"""
    conn = get_db()
    cur  = conn.cursor()

    # ユーザーテーブル
    # public_key:            ブラウザで生成したRSA公開鍵（PEM形式）
    # encrypted_private_key: ログインパスワードから派生した鍵で暗号化されたRSA秘密鍵
    #                        フォーマット: Base64( Salt[16byte] + IV[12byte] + 暗号文 )
    #                        サーバーはパスワードも派生鍵も知らないため復号できない
    #                        機種変更・キャッシュ削除後の秘密鍵復元に使用（v2追加）
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id                    SERIAL PRIMARY KEY,
            username              TEXT NOT NULL UNIQUE,
            password              TEXT NOT NULL,
            public_key            TEXT,
            encrypted_private_key TEXT,
            created_at            TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
    """)

    # メッセージテーブル
    # sender_id:                送信者
    # receiver_id:              受信者
    # content:                  AES-256-GCMで暗号化されたメッセージ本文（v2: CBC→GCM）
    #                           フォーマット: Base64( IV[12byte] + 暗号文+認証タグ )
    # encrypted_key:            受信者のRSA公開鍵で暗号化されたAES鍵
    #                           フォーマット: Base64( RSA-OAEP(AES鍵[32byte]) )
    # encrypted_key_for_sender: 送信者のRSA公開鍵で暗号化されたAES鍵
    #                           送信者が自分のメッセージを復号するために使用
    # → サーバーは暗号化されたデータを保存するだけで中身を読めない
    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id                       SERIAL PRIMARY KEY,
            sender_id                INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            receiver_id              INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            content                  TEXT    NOT NULL,
            encrypted_key            TEXT    NOT NULL,
            encrypted_key_for_sender TEXT,
            created_at               TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
    """)

    conn.commit()
    cur.close()
    conn.close()
