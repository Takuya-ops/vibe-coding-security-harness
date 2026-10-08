# バイブコーディング用セキュリティ・ハーネス（サンプル）

AI コーディングツール（Claude Code・Codex など）でアプリを作るときに、次のような事故を自動で止める・指摘するための設定ファイル一式です。

- チャットに API キーを貼る → **AI に送る前に止める**
- AI が `.env` を読む・`cat .env` を実行する → **止める**
- コードにキーを直書きする、`NEXT_PUBLIC_` / `VITE_` などブラウザに配られる名前で秘密のキーを使う → **書き込みを止める**
- RLS（行レベルセキュリティ）のないテーブルを作る、Firebase のルールを「誰でも読み書きできる」にする → **書いた後に指摘して直させる**
- プロジェクト外の一括削除、`curl ... | sh` → **止める**／新しいパッケージの追加、`git push --force`、DB の初期化、本番へのデプロイ → **人に確認する**
- `.env` やキー入りのファイルをコミットする → **コミット前に止める**

Node.js（18 以上）だけで動き、追加のパッケージは要りません。
記事「AIで作ったアプリ、そのまま公開して大丈夫？ バイブコーディングのセキュリティ対策と、AIに守らせるハーネス」のサンプルです。

## 5 つの関所

| 関所 | 止める・指摘するもの | 仕組み |
|---|---|---|
| 1 送信する前 | メッセージに含まれる API キー・トークン・秘密鍵 | UserPromptSubmit フック |
| 2 実行する前 | `.env` の読み書き、危ないコマンド、キーの直書き・公開名 | PreToolUse フック、権限の deny |
| 3 書いた後 | RLS のないテーブル、誰でも読み書きできるルール | PostToolUse フック |
| 4 コミットする前 | `.env`・秘密鍵のファイル、キーが書かれたファイル | `.githooks/pre-commit`（gitleaks があれば併用） |
| 5 push した後 | 履歴を含めた秘密情報、依存パッケージの脆弱性 | GitHub Actions、Dependabot |

土台として、`AGENTS.md`（`CLAUDE.md` から取り込み）で AI に最初からルールを読ませます。

## 何が入っているか

| ファイル | 役割 | 対応ツール |
|---|---|---|
| `AGENTS.md` | AI が最初に読むセキュリティのルール（本体） | Codex・Cursor・GitHub Copilot ほか |
| `CLAUDE.md` | `@AGENTS.md` を取り込む（Claude Code 用の入口） | Claude Code |
| `.claude/settings.json` | `.env` の読み取り禁止、フックの登録、bypass モードの禁止 | Claude Code |
| `.codex/config.toml` / `hooks.json` / `rules/` | サンドボックス、フックの登録、危ないコマンドの扱い | Codex CLI |
| `scripts/security/rules.mjs` | 判定ロジック（秘密情報・危ないコマンド・公開名のキー・RLS） | 共通 |
| `scripts/security/hook.mjs` | AI ツールのフックから呼ばれる入口 | Claude Code・Codex |
| `scripts/security/scan-secrets.mjs` | ファイル・ステージ済みの変更・ビルド成果物を検査 | 共通 |
| `scripts/security/setup.sh` | 初期設定（コミット前チェックの有効化、`.gitignore` の確認など） | 共通 |
| `.githooks/pre-commit` | コミット前に秘密情報を検査 | Git |
| `.github/workflows/security.yml` / `dependabot.yml` | push 後の再検査、依存パッケージの監視 | GitHub |
| `.claude/skills/` と `.agents/skills/` の `security-check` | 公開前の点検手順（`/security-check`） | Claude Code・Codex |
| `SECURITY_CHECKLIST.md` | 公開前チェックリスト（8 分野・37 項目） | 人と AI |
| `.gitignore` / `.env.example` | 秘密ファイルを Git に入れない設定と、キー名の見本 | 共通 |

## 使い方

### A. 新しくアプリを作る場合

1. このページ上部の **Use this template** → **Create a new repository** で、自分のリポジトリを作る
2. 作ったリポジトリを手元に clone し、そのフォルダで AI ツールにアプリを作らせる
3. 下の「初期設定」を行う

### B. 作りかけのプロジェクトに入れる場合（Mac / Linux）

プロジェクトのフォルダ（`package.json` がある場所）で実行します。すでにあるファイル（`.gitignore` など）は上書きしません。

```bash
git clone --depth 1 https://github.com/Takuya-ops/vibe-coding-security-harness.git /tmp/vibe-harness
rsync -a --ignore-existing --exclude .git --exclude README.md --exclude LICENSE /tmp/vibe-harness/ ./
```

Windows の場合は、このページの **Code → Download ZIP** で取得し、中身（`.claude` など、名前が `.` で始まるフォルダも含む）をプロジェクトのフォルダにコピーします。

### 初期設定

1. プロジェクトのフォルダで実行する（コミット前チェックの有効化、`.gitignore` に `.env` があるかの確認、判定ルールのテスト）
   ```bash
   sh scripts/security/setup.sh
   ```
2. `.env` をエディタで開き、キーの値を自分で書き込む（AI には書かせない）
3. **Claude Code**：プロジェクトのフォルダで起動してフォルダを信頼し、`/hooks` にフックが表示されるか確認する
4. **Codex**：初回起動時にプロジェクトを**信頼**し、`/hooks` でフックを承認する。信頼しないと `.codex/` の設定・フック・ルールは 1 つも読み込まれない
5. **GitHub**：Settings → Code security で Dependabot alerts と push protection を確認する。組織（Organization）のリポジトリで gitleaks-action を使う場合は、gitleaks.io の無料ライセンスキーを `GITLEAKS_LICENSE` として Secrets に登録する
6. **動作確認**：AI に「ターミナルで cat .env を実行して」と頼み、止められることを確かめる

フックの判定だけを手で試すこともできます（終了コードが 2 なら「止める」と判定できています）。

```bash
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat .env"}}' | node scripts/security/hook.mjs
echo "終了コード: $?"
```

## 確かめた環境

2026 年 10 月 8 日、macOS・Node.js 22.23.2 で確認しました。

- Claude Code 2.1.288 / 2.1.294：キーの貼り付け、`.env` の読み取り・`cat .env`、`NEXT_PUBLIC_` での直書き、RLS のないテーブル、パッケージの追加（確認ダイアログ）、bypass モードの禁止
- Codex CLI 0.159.2（プロジェクトを信頼済みにした場合）：`cat .env`、キーの貼り付け、`NEXT_PUBLIC_` での直書き、RLS のないテーブル
- Git の pre-commit：`.env` の強制追加、キーの直書き

Cursor と GitHub Copilot は `AGENTS.md` を読みますが、フックの動作は確かめていません。

## 自分で直すとき

- 止めたいファイル名・コマンドは `scripts/security/rules.mjs` に追加し、`node --test scripts/security/rules.test.mjs` で確かめる
- 誤検知で止まる場合は、プロンプトの値を `<YOUR_API_KEY>` のような書き方にするか、`rules.mjs` のパターンを調整する

## 限界

- 文字列のパターンで判定しているので、すべての書き方を止められるわけではありません（例：スクリプトがファイル名を組み立てて読む）。OS のレベルで止めたい場合は、Claude Code のサンドボックス（`/sandbox`）や Codex の権限プロファイルを併用してください（併用は未検証）
- 送信を止めても、入力したキーは Claude Code の入力履歴（`~/.claude/history.jsonl`）に残ります。貼ってしまったキーは無効化して作り直してください
- 設定ファイルを書き換えれば、フックも bypass モードの禁止も外せます。ハーネスは見落としを減らす道具で、点検の代わりにはなりません
- フックは「実行されるプログラム」です。他人が配布したハーネスは、このリポジトリも含めて、中身を読んでから使ってください

## ライセンス

MIT License（`LICENSE` を参照）
