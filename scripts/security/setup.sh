#!/bin/sh
# セキュリティ・ハーネスの初期設定。プロジェクトのフォルダで 1 回だけ実行する。
#   sh scripts/security/setup.sh
set -e
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

echo "== セキュリティ・ハーネスの設定 =="

# 1. Node.js（フックとチェックの実行に必要）
if ! command -v node >/dev/null 2>&1; then
  echo "✗ Node.js が見つかりません。https://nodejs.org から LTS 版を入れてから、もう一度実行してください。"
  exit 1
fi
echo "✓ Node.js $(node --version)"

# 2. Git の管理下か
if [ ! -d .git ]; then
  git init -q
  echo "✓ git init を実行しました"
fi

# 3. コミット前チェック（.githooks/pre-commit）を有効にする
chmod +x .githooks/pre-commit scripts/security/*.mjs 2>/dev/null || true
git config core.hooksPath .githooks
echo "✓ コミット前の秘密情報チェックを有効にしました（core.hooksPath=.githooks）"

# 4. .env が Git に入っていないか
if git ls-files --error-unmatch .env >/dev/null 2>&1; then
  echo "✗ .env が Git の管理に入っています。次を実行して外し、中のキーは作り直してください:"
  echo "    git rm --cached .env && git commit -m \"Stop tracking .env\""
else
  echo "✓ .env は Git の管理に入っていません"
fi

# 5. .gitignore で .env などが無視されるか（既存の .gitignore を使っている場合に足りない行を足す）
if ! git check-ignore -q .env 2>/dev/null; then
  printf '\n# セキュリティ・ハーネス: 秘密情報を Git に入れない\n.env\n.env.*\n!.env.example\n.dev.vars\n*.pem\n*.key\n.claude/settings.local.json\n' >> .gitignore
  echo "✓ .gitignore に .env などの行を追加しました"
else
  echo "✓ .gitignore で .env が無視されています"
fi

# 6. .env がなければ、ひな形からコピーする（値は自分で書き込む）
if [ ! -f .env ] && [ -f .env.example ]; then
  cp .env.example .env
  echo "✓ .env.example をコピーして .env を作りました。キーの値は .env をエディタで開いて自分で書き込んでください。"
fi

# 7. ハーネス自体のテスト
node --test scripts/security/rules.test.mjs >/dev/null 2>&1 && echo "✓ 判定ルールのテストに合格" || echo "✗ 判定ルールのテストに失敗しました（node --test scripts/security/rules.test.mjs で詳細）"

# 8. gitleaks（任意）
if command -v gitleaks >/dev/null 2>&1; then
  echo "✓ gitleaks $(gitleaks version) も使います"
else
  echo "・gitleaks は未インストールです（任意）。入れるとより多くの種類のキーを検出できます: brew install gitleaks"
fi

echo "== 完了 =="
