---
name: security-check
description: 公開（デプロイ）前のセキュリティ点検。秘密情報の混入、ブラウザに配られるキー、Supabase の RLS、入力の検証、回数制限、依存パッケージの脆弱性を SECURITY_CHECKLIST.md に沿って調べ、結果を表で報告する。「公開前にチェックして」「セキュリティを確認して」と頼まれたときに使う。
---

# 公開前のセキュリティ点検

`SECURITY_CHECKLIST.md` の項目を、次の順で点検します。`.env` などの秘密ファイルは開かないでください（ハーネスが止めます）。

## 手順

1. **秘密情報**
   - `node scripts/security/scan-secrets.mjs --all` を実行する。
   - `git ls-files` で `.env`・`*.pem`・`service-account*.json` などが管理に入っていないか確かめる。
   - ソースコードを `NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|PUBLIC_` で検索し、AI の API キー・secret/service_role キー・データベースの接続文字列が公開側の名前になっていないか確かめる。
   - `dangerouslyAllowBrowser` や、クライアント側のファイル（`"use client"` やブラウザで動く画面）から AI の API を直接呼んでいる箇所がないか確かめる。
   - ビルドの方法が分かる場合は、ビルド後に `node scripts/security/scan-secrets.mjs --dir <出力フォルダ>` を実行する（Next.js は `.next/static`、Vite は `dist`）。
2. **ログインとデータの持ち主**
   - `supabase/migrations/` の各 `create table` に、`enable row level security` とポリシーがあるか確かめる。
   - API ルート・サーバーアクションで、ログイン中のユーザーを確かめずにデータを読み書きしている箇所、URL やリクエストの ID をそのまま使っている箇所を探す。
   - `firestore.rules` / `storage.rules` があれば、`if true` やテストモードの期限付きルールが残っていないか確かめる。
3. **入力と表示**: `dangerouslySetInnerHTML`・`innerHTML`・文字列連結の SQL・`eval` を検索する。API ルートの入力検証の有無を確かめる。
4. **お金と使われすぎ**: AI 呼び出し・ログイン・登録の API に回数制限があるか、`max_tokens` などの上限があるか、Stripe の Webhook で署名を検証しているかを確かめる。
5. **依存パッケージ**: `package-lock.json` があれば `npm audit --audit-level=high` を実行する。見覚えのないパッケージ名がないか `package.json` を確かめる。
6. **公開の設定**: `next.config.*` などでセキュリティヘッダーを設定しているか、CORS を `*` にしていないか、エラー時にスタックトレースを返していないかを確かめる。

## 報告の形

最後に、次の形の表で報告してください。

| 項目 | 結果 | 見つかった場所 | 次にすること |
|---|---|---|---|
| A2 コードにキーがない | ✅ 問題なし / ⚠️ 要確認 / ❌ 問題あり | ファイル名:行 | 具体的な操作 |

- コードを読むだけでは判断できない項目（ホスティングの環境変数、Supabase の Security Advisor、2 段階認証、予算アラートなど）は「利用者が確認」とし、確認する画面の場所を書く。
- ❌ の項目は、修正してよいか利用者に確認してから直す。
