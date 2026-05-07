# 🔐 SecureChat

エンドツーエンド暗号化（E2EE）対応のリアルタイムチャットアプリケーション

---

## 概要

SecureChat は、**サーバー管理者でもメッセージを読むことができない**エンドツーエンド暗号化を実装したチャットアプリです。メッセージの暗号化・復号はすべてブラウザ側で行われ、サーバーは暗号化済みデータの保存・転送のみを担当します。

---

## 主な機能

- **エンドツーエンド暗号化（E2EE）** — メッセージはサーバーに届く前にブラウザで暗号化される
- **ユーザー認証** — bcrypt によるパスワードハッシュ化
- **リアルタイムチャット** — ポーリングによる新着メッセージの自動取得
- **アカウント管理** — ユーザー名・パスワードの変更、アカウント削除
- **XSS対策** — ユーザー入力のエスケープ処理
- **セッション管理** — 有効期限付きセッション（2時間）

---

## 暗号化の仕組み

### ハイブリッド暗号方式

```
送信時:
  ① ブラウザで RSA-2048 鍵ペアを生成（登録時に1回のみ）
  ② 秘密鍵 → ブラウザの localStorage にのみ保存（サーバーには送らない）
  ③ 公開鍵 → サーバーに登録

メッセージ送信時:
  ① AES-256-CBC 鍵（32byte）をランダム生成
  ② メッセージを AES で暗号化
  ③ 同じ AES 鍵を受信者の RSA 公開鍵で暗号化（encrypted_key）
  ④ 同じ AES 鍵を送信者自身の RSA 公開鍵でも暗号化（encrypted_key_for_sender）
  ⑤ 暗号化済みデータをサーバーに送信
```

サーバーが保持するのは暗号文のみであり、AES 鍵も RSA で暗号化された状態で保存されます。

---

## 技術スタック

| カテゴリ | 技術 |
|----------|------|
| バックエンド | Python / Flask |
| データベース | PostgreSQL（psycopg2） |
| 認証 | bcrypt（パスワードハッシュ化） |
| 暗号化 | Web Crypto API（RSA-OAEP, AES-CBC） |
| フロントエンド | Vanilla JavaScript / HTML / CSS |
| 本番環境 | Gunicorn |
| 環境変数管理 | python-dotenv |

---

## ディレクトリ構成

```
.
├── app.py          # Flask アプリ本体・API エンドポイント
├── database.py     # DB 接続・テーブル初期化
├── requirements.txt
├── templates/
│   ├── chat.html       # チャット画面
│   ├── login.html      # ログイン画面
│   └── register.html   # ユーザー登録画面
└── static/
    └── crypto.js   # ブラウザ側暗号化モジュール
```

---

## セットアップ

### 必要環境

- Python 3.10 以上
- PostgreSQL

### インストール

```bash
# リポジトリをクローン
git clone https://github.com/asato-div/securechat.git
cd securechat

# 依存関係をインストール
pip install -r requirements.txt
```

### 環境変数の設定

`.env` ファイルをプロジェクトルートに作成します。

```env
DATABASE_URL=postgresql://user:password@localhost:5432/securechat
SECRET_KEY=your-secret-key-here
```

### 起動

```bash
# 開発環境
python app.py

# 本番環境（Gunicorn）
gunicorn app:app --bind 0.0.0.0:8080
```

ブラウザで `http://localhost:8080` にアクセス。

---

## API エンドポイント

| メソッド | パス | 説明 |
|--------|------|------|
| POST | `/api/register` | ユーザー登録（公開鍵を含む） |
| POST | `/api/login` | ログイン |
| POST | `/api/logout` | ログアウト |
| GET  | `/api/me` | ログイン中ユーザー情報 |
| GET  | `/api/users` | ユーザー一覧 |
| GET  | `/api/users/:id/public-key` | 公開鍵の取得 |
| GET  | `/api/messages/:partner_id` | メッセージ履歴の取得 |
| POST | `/api/messages` | メッセージ送信 |
| PUT  | `/api/account/username` | ユーザー名変更 |
| PUT  | `/api/account/password` | パスワード変更 |
| DELETE | `/api/account` | アカウント削除 |

---

## セキュリティ上の考慮点

- **秘密鍵はサーバーに送信されない** — localStorage にのみ保存
- **サーバーはメッセージを復号できない** — 暗号化済みデータのみを保管
- **SQLインジェクション対策** — プレースホルダを使用したパラメータ化クエリ
- **XSS対策** — ユーザー入力を DOM 挿入前にエスケープ
- **パスワードの安全な保存** — bcrypt によるハッシュ化（ソルト付き）
- **セッション有効期限** — 2時間で自動失効
- **入力バリデーション** — ユーザー名は英数字・アンダースコアのみ許可

### 既知の制約

- 秘密鍵は localStorage に保存されるため、**別デバイスからは過去のメッセージを復号できない**
- ブラウザの localStorage をクリアすると秘密鍵が失われる

---

## ライセンス

MIT
