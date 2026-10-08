// ハーネスの判定ロジック本体。
// Claude Code・Codex のフックと Git の pre-commit から共通で使う。
// 依存パッケージなし（Node.js 18 以上だけで動く）。
//
// 返り値はどれも「問題なし = null」「問題あり = { action, reason }」の形。
//   action: "block" … 止める（AI には実行させない）
//           "ask"   … 人に確認する

import path from "node:path";

// ────────────────────────────────────────────────
// 1. 秘密情報（APIキー・トークン・秘密鍵）の検出
// ────────────────────────────────────────────────

// 「値の例」としてよく使われる文字列。これらは本物のキーとみなさない。
const PLACEHOLDER =
  /^(?:<[^>]*>|\$\{[^}]*\}|\$[A-Z_]+|your[-_ ]?|xxx+|\*{3,}|\.{3}|…|example|changeme|change[-_]me|dummy|placeholder|sample|replace[-_]?me|todo|none|null|undefined|password|secret|redacted)/i;

// 先頭の文字で種類が分かるキー。名前は利用者に見せる説明。
const SECRET_PATTERNS = [
  { name: "Anthropic（Claude）の API キー", re: /sk-ant-[a-z]{2,8}\d{2}-[A-Za-z0-9_-]{20,}/g },
  { name: "OpenAI の API キー", re: /sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}/g },
  { name: "OpenAI 形式の API キー", re: /\bsk-[A-Za-z0-9]{32,}\b/g },
  { name: "Google の API キー（Gemini・Firebase など）", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: "AWS のアクセスキー", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: "GitHub のトークン", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b/g },
  { name: "Stripe のシークレットキー", re: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}\b/g },
  { name: "Stripe の Webhook シークレット", re: /\bwhsec_[0-9A-Za-z]{20,}\b/g },
  { name: "Supabase のシークレットキー", re: /\bsb_secret_[A-Za-z0-9_-]{20,}\b/g },
  { name: "Slack のトークン", re: /\bxox[abposr]-[0-9A-Za-z-]{10,}\b/g },
  { name: "Slack / Discord の Webhook URL", re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{20,}|https:\/\/(?:discord|discordapp)\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{20,}/g },
  { name: "Hugging Face のトークン", re: /\bhf_[A-Za-z0-9]{30,}\b/g },
  { name: "秘密鍵（PEM 形式）", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g },
  {
    name: "パスワード入りのデータベース接続文字列",
    re: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?):\/\/[^:\s/@]+:([^@\s]{6,})@[^\s'"`]+/g,
    check: (m) => !PLACEHOLDER.test(m[1]) && !/^(?:postgres|root|admin|pass(?:word)?|localhost)$/i.test(m[1]),
  },
  {
    name: "Supabase の service_role キー",
    re: /\beyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,}/g,
    check: (m) => jwtRole(m[1]) === "service_role",
  },
];

// 「NAME=値」形式（.env の中身を貼った場合など）。名前に KEY・SECRET などが入るものだけ見る。
const ASSIGNMENT =
  /\b([A-Za-z][A-Za-z0-9_]*?(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)[A-Za-z0-9_]*)["']?\s*[:=]\s*["'`]?([^\s"'`,;]{12,})/gi;

function jwtRole(payloadPart) {
  try {
    const json = Buffer.from(payloadPart.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    return JSON.parse(json).role ?? null;
  } catch {
    return null;
  }
}

// 文字の散らばり具合（エントロピー）。ランダムなキーほど高い。
function entropy(s) {
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  return Object.values(freq).reduce((h, n) => h - (n / s.length) * Math.log2(n / s.length), 0);
}

function looksRandom(value) {
  if (PLACEHOLDER.test(value)) return false;
  if (/^(?:process\.env|import\.meta\.env|os\.environ|Deno\.env|env\(|getenv)/i.test(value)) return false;
  if (/^[a-z]+(?:[._-][a-z]+)*$/i.test(value)) return false; // 英単語だけ（例: my-app-name）
  if (/^https?:\/\//.test(value) && !/@/.test(value)) return false; // ただの URL
  return /[0-9]/.test(value) && /[A-Za-z]/.test(value) && entropy(value) >= 3.3;
}

// 見つけた値は先頭だけ残して伏せる（メッセージにキーそのものを出さないため）。
export function mask(value) {
  return value.length <= 8 ? "****" : `${value.slice(0, 6)}…（${value.length}文字）`;
}

/** 文字列の中から秘密情報らしきものを探す。 */
export function findSecrets(text, { assignments = true } = {}) {
  if (!text) return [];
  const found = [];
  const seen = new Set();
  for (const p of SECRET_PATTERNS) {
    for (const m of text.matchAll(p.re)) {
      if (p.check && !p.check(m)) continue;
      if (seen.has(m[0])) continue;
      seen.add(m[0]);
      found.push({ name: p.name, sample: mask(m[0]) });
    }
  }
  if (assignments) {
    for (const m of text.matchAll(ASSIGNMENT)) {
      const value = m[2];
      if (seen.has(value) || [...seen].some((s) => s.includes(value) || value.includes(s))) continue;
      if (!looksRandom(value)) continue;
      seen.add(value);
      found.push({ name: `${m[1]} に書かれた値`, sample: mask(value) });
    }
  }
  return found;
}

// ────────────────────────────────────────────────
// 2. 触ってはいけないファイル
// ────────────────────────────────────────────────

const SENSITIVE_FILES = [
  { re: /(?:^|\/)\.env(?:\.[^/]*)?$/, allow: /\.env\.(?:example|sample|template|defaults?|schema)$/, label: "API キーなどの置き場所" },
  { re: /(?:^|\/)\.dev\.vars(?:\.[^/]*)?$/, allow: /\.example$/, label: "Cloudflare のローカル用シークレットの置き場所" },
  { re: /\.(?:pem|key|p12|pfx|jks|keystore)$/i, label: "秘密鍵・証明書のファイル" },
  { re: /(?:^|\/)id_(?:rsa|ed25519|ecdsa|dsa)$/, label: "SSH の秘密鍵" },
  { re: /(?:^|\/)\.ssh\//, allow: /\.pub$|known_hosts$/, label: "SSH の設定・鍵" },
  { re: /(?:^|\/)\.aws\/(?:credentials|config)$/, label: "AWS の認証情報" },
  { re: /(?:^|\/)\.(?:netrc|pgpass)$/, label: "パスワードの保存ファイル" },
  { re: /(?:^|\/)(?:service[-_]?account[^/]*|credentials|client_secret[^/]*|firebase-adminsdk[^/]*)\.json$/i, label: "サービスアカウント・認証情報の JSON" },
  { re: /(?:^|\/)secrets?\.(?:json|ya?ml|toml)$/i, label: "シークレットの設定ファイル" },
  { re: /(?:^|\/)\.codex\/auth\.json$|(?:^|\/)\.claude\/\.credentials\.json$|(?:^|\/)\.config\/gh\/hosts\.yml$/, label: "AI ツール・GitHub CLI のログイン情報" },
];

/** パスが秘密情報の入ったファイルなら説明を返す。 */
export function sensitiveFileLabel(p) {
  if (!p || typeof p !== "string") return null;
  const norm = p.replace(/\\/g, "/");
  for (const f of SENSITIVE_FILES) {
    if (f.re.test(norm) && !(f.allow && f.allow.test(norm))) return f.label;
  }
  return null;
}

export function checkFileAccess(filePath) {
  const label = sensitiveFileLabel(filePath);
  if (!label) return null;
  return {
    action: "block",
    reason:
      `${path.basename(filePath)} は${label}です。AI はこのファイルを読んだり書き換えたりしません。` +
      `キーの値が必要な作業は、キーの「名前」だけを使ってコードを書き（例: process.env.OPENAI_API_KEY）、` +
      `値の設定は利用者に .env を開いて自分で書き込むよう依頼してください。`,
  };
}

// ────────────────────────────────────────────────
// 3. コードに書き込む内容のチェック
// ────────────────────────────────────────────────

// ブラウザに配られる環境変数の接頭辞（フレームワークごと）
const PUBLIC_PREFIX = "(?:NEXT_PUBLIC|VITE|EXPO_PUBLIC|NUXT_PUBLIC|REACT_APP|GATSBY|PUBLIC)_";
// 公開してはいけない種類のキーを表す単語
const SECRET_WORD =
  "(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_AI|GROQ|MISTRAL|DEEPSEEK|XAI|PERPLEXITY|REPLICATE|ELEVENLABS|RESEND|SENDGRID|TWILIO|DATABASE_URL|DB_URL|ADMIN)";
const PUBLIC_SECRET = new RegExp(`\\b${PUBLIC_PREFIX}[A-Z0-9_]*${SECRET_WORD}[A-Z0-9_]*`, "g");

export function checkWrite(filePath, content) {
  const access = checkFileAccess(filePath);
  if (access) return access;
  if (!content) return null;

  const problems = [];

  const secrets = findSecrets(content);
  if (secrets.length) {
    problems.push(
      `コードに秘密情報を直接書こうとしています（${secrets.map((s) => `${s.name}: ${s.sample}`).join("、")}）。` +
        `値は .env に置き、コードでは process.env.名前 のように名前で読み込んでください。`
    );
  }

  const exposed = [...new Set(content.match(PUBLIC_SECRET) || [])];
  if (exposed.length) {
    problems.push(
      `${exposed.join("、")} は、名前の先頭（NEXT_PUBLIC_ や VITE_ など）のせいでブラウザに配られ、` +
        `アプリを開いた人なら誰でも見られます。この種類のキーは接頭辞を付けずにサーバー側（API ルートなど）だけで使ってください。`
    );
  }

  if (/dangerouslyAllowBrowser\s*:\s*true/.test(content)) {
    problems.push(
      "dangerouslyAllowBrowser: true は API キーをブラウザに渡す設定です。" +
        "AI の API はサーバー側の処理（API ルート・サーバーアクション・Edge Functions など）から呼び出してください。"
    );
  }

  if (!problems.length) return null;
  return { action: "block", reason: problems.join("\n") };
}

// 書き込んだ後に「直したほうがよい点」を AI に伝える（止めはしない）。
export function reviewWrittenFile(filePath, content) {
  if (!content) return null;
  const notes = [];
  const name = (filePath || "").replace(/\\/g, "/");

  if (/\.sql$/i.test(name) && /\bcreate\s+table\b/i.test(content) && !/enable\s+row\s+level\s+security/i.test(content)) {
    notes.push(
      `${path.basename(name)} でテーブルを作っていますが、行レベルセキュリティ（RLS）が有効になっていません。` +
        "Supabase では alter table ... enable row level security; と、本人のデータだけを扱えるポリシー（auth.uid() を使う）を同じマイグレーションに追加してください。"
    );
  }
  if (/\.sql$/i.test(name) && /\bgrant\s+(?:all|insert|update|delete)\b[^;]*\bto\s+(?:anon|public)\b/i.test(content)) {
    notes.push(
      "未ログインの利用者（anon / public）に書き込みや削除の権限（GRANT）を与えています。必要な権限だけにし、RLS のポリシーで行ごとに絞ってください。"
    );
  }
  if (/(?:firestore|storage|database)\.rules$|\.rules\.json$/i.test(name)) {
    if (/allow\s+(?:read|write|read\s*,\s*write)\s*(?::\s*if\s+true\s*;|;)/i.test(content) || /"\.(?:read|write)"\s*:\s*true/.test(content)) {
      notes.push("セキュリティルールが「誰でも読める・書ける」状態です。request.auth を使ってログインした本人だけに絞ってください。");
    }
    if (/request\.time\s*<\s*timestamp\.date\(/.test(content)) {
      notes.push("テストモードのルール（期限付きで全員に公開）が残っています。公開前に本番用のルールへ書き換えてください。");
    }
  }
  if (/Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]/.test(content) && /credentials/i.test(content)) {
    notes.push("CORS を「すべてのサイトから許可（*）」にしたまま認証情報を扱っています。許可するサイトを自分のドメインに限定してください。");
  }
  if (!notes.length) return null;
  return { reason: notes.join("\n") };
}

// ────────────────────────────────────────────────
// 4. 実行するコマンドのチェック
// ────────────────────────────────────────────────

// よく使う公式のパッケージ実行（npx など）。これ以外は確認する。
const KNOWN_RUNNERS = new Set([
  "create-next-app", "create-vite", "create-expo-app", "create-react-router", "create-astro", "nuxi", "sv",
  "next", "vite", "expo", "eas-cli", "supabase", "vercel", "netlify-cli", "wrangler", "firebase-tools",
  "prisma", "drizzle-kit", "shadcn", "shadcn-ui", "eslint", "prettier", "tsc", "typescript", "tsx",
  "vitest", "jest", "playwright", "@playwright/test", "gitleaks", "npm-check-updates", "serve", "http-server",
]);

// シェルの文字列をおおまかに単語へ分ける（引用符は外す）。
function words(cmd) {
  return (cmd.match(/"[^"]*"|'[^']*'|[^\s;&|<>()]+/g) || []).map((w) => w.replace(/^["']|["']$/g, ""));
}

// コマンドを ; && || | で区切った、それぞれの部分。
function segments(cmd) {
  return cmd.split(/;|&&|\|\||\n/).map((s) => s.trim()).filter(Boolean);
}

function block(reason) {
  return { action: "block", reason };
}
function ask(reason) {
  return { action: "ask", reason };
}

/**
 * シェルコマンドを調べる。
 * @param {string} cmd 実行しようとしているコマンド
 * @param {string} cwd プロジェクトのフォルダ
 */
export function checkCommand(cmd, cwd = process.cwd()) {
  if (!cmd || typeof cmd !== "string") return null;
  const w = words(cmd);

  // (a) 秘密のファイルに触れる（引用符・かっこ・= の中に書かれた名前も拾う。例: python -c "open('.env')"）
  const pathTokens = cmd.split(/[\s"'`;&|<>(){}\[\]=,\\]+/).filter(Boolean);
  for (const token of new Set([...w, ...pathTokens])) {
    const label = sensitiveFileLabel(token);
    if (label) {
      return block(
        `このコマンドは ${token}（${label}）に触れます。AI は .env などのキーの置き場所を読み書きしません。` +
          `値の確認や書き込みが必要なら、利用者に手で操作するよう依頼してください。`
      );
    }
  }

  // (b) 環境変数をまとめて画面に出す・キーを表示する
  if (/(?:^|[\s;&|(])(?:printenv|env|export\s+-p|set)\s*(?:$|[|;&>])/.test(cmd) || /\bprocess\.env\s*\)/.test(cmd) || /os\.environ\s*\)/.test(cmd)) {
    return block("環境変数の一覧を表示すると、読み込まれている API キーが AI の会話に流れ込みます。必要な変数があるかだけを確かめたいなら、利用者に確認を依頼してください。");
  }
  if (/\b(?:echo|printf|print|cat)\b[^|;&]*\$\{?[A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASS)\b/i.test(cmd)) {
    return block("キーの値を画面に表示しようとしています。表示された値は AI の会話の記録に残ります。値は表示せず、名前だけで扱ってください。");
  }

  // (c) ネットから取ってきたスクリプトをそのまま実行する
  if (/\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|node|perl)\b/.test(cmd)) {
    return block("インターネットから取得したスクリプトを中身を確かめずに実行しようとしています。利用者が公式サイトの手順を確認してから、自分で実行してください。");
  }

  for (const seg of segments(cmd)) {
    const sw = words(seg);
    const head = sw[0] === "sudo" ? sw[1] : sw[0];

    // (d) ファイルの一括削除
    if (head === "rm" && sw.some((t) => /^-[a-zA-Z]*[rR]/.test(t) || t === "--recursive")) {
      const targets = sw.slice(sw.indexOf("rm") + 1).filter((t) => !t.startsWith("-"));
      const home = process.env.HOME || "~";
      const dangerous = targets.find((t) => {
        if (/^(?:\/|~|~\/|\$HOME|\$\{HOME\}|\*|\.|\.\/?|\.\.\/?.*|\/\*|~\/\*)$/.test(t)) return true;
        if (t.startsWith("~") || t.startsWith("$HOME") || t.startsWith(home)) {
          const abs = path.resolve(t.replace(/^~|^\$HOME|^\$\{HOME\}/, home));
          return !abs.startsWith(path.resolve(cwd) + path.sep);
        }
        if (path.isAbsolute(t)) return !path.resolve(t).startsWith(path.resolve(cwd) + path.sep);
        return false;
      });
      if (dangerous) return block(`rm で ${dangerous} をまとめて消そうとしています。プロジェクトの外やフォルダ全体の削除は AI には実行させません。`);
      return ask(`rm でフォルダごと削除します（${targets.join(" ")}）。消してよいものか確認してください。`);
    }

    if (head === "git") {
      const sub = sw[1];
      if (sub === "push" && sw.some((t) => /^(?:--force|-f|--force-with-lease|--mirror|--delete|-d)$/.test(t) || /^\+/.test(t))) {
        return ask("git push の強制上書き・削除です。GitHub 上の履歴が消えることがあります。実行してよいか確認してください。");
      }
      if (sub === "reset" && sw.includes("--hard")) return ask("git reset --hard は、保存（コミット）していない変更をすべて消します。実行してよいか確認してください。");
      if (sub === "clean" && sw.some((t) => /^-[a-zA-Z]*f/.test(t))) return ask("git clean は Git で管理していないファイル（.env を含む）を消します。実行してよいか確認してください。");
      if ((sub === "checkout" || sub === "restore") && sw.includes(".")) return ask("作業中の変更を元に戻すコマンドです。保存していない変更が消えます。実行してよいか確認してください。");
      if (sub === "add" && sw.some((t) => sensitiveFileLabel(t))) return block(".env などをコミットしようとしています。");
      if (sub === "filter-repo" || sub === "filter-branch") return ask("Git の履歴を書き換えるコマンドです。実行してよいか確認してください。");
    }

    // (e) データベースを消す・初期化する
    if (/\b(?:drop\s+(?:table|database|schema)|truncate\s+(?:table\s+)?\w)/i.test(seg) || /\bdelete\s+from\s+[\w."]+\s*(?:;|$|["'])/i.test(seg)) {
      return ask("データベースのテーブルやデータをまとめて消す SQL です。本番のデータでないか、バックアップがあるかを確認してください。");
    }
    if (/\bterraform\s+(?:destroy\b|apply\b.*-destroy\b)/.test(seg)) {
      return ask("terraform destroy はクラウド上のサーバーやデータベースを丸ごと消します。対象が本番でないか、バックアップがあるかを確認してください。");
    }
    if (/\bsupabase\s+db\s+(?:reset|push)\b/.test(seg) || /\bprisma\s+(?:migrate\s+reset|db\s+push\b.*--force-reset)/.test(seg) || /\bdrizzle-kit\s+push\b/.test(seg)) {
      return ask("データベースの構造を書き換える（または初期化する）コマンドです。接続先が本番でないか確認してください。");
    }

    // (f) 本番への公開・パッケージの公開
    if (
      /\bvercel\b.*(?:--prod|\bdeploy\b.*--prod)/.test(seg) || /\bnetlify\s+deploy\b.*--prod/.test(seg) ||
      /\bwrangler\s+(?:deploy|publish)\b/.test(seg) || /\bfirebase\s+deploy\b/.test(seg) ||
      /\b(?:npm|pnpm|yarn)\s+publish\b/.test(seg) || /\beas\s+submit\b/.test(seg)
    ) {
      return ask("本番環境への公開（またはパッケージの公開）です。公開前チェックリストを確認してから実行してください。");
    }

    // (g) 新しいパッケージの追加（存在しない・偽物のパッケージ対策）
    const pm = sw[0];
    const sub = sw[1];
    let pkgs = [];
    if ((pm === "npm" && ["i", "install", "add"].includes(sub)) || (["pnpm", "yarn", "bun"].includes(pm) && sub === "add")) {
      pkgs = sw.slice(2).filter((t) => !t.startsWith("-"));
    } else if ((pm === "pip" || pm === "pip3") && sub === "install") {
      if (!sw.includes("-r") && !sw.includes("-e") && !sw.includes(".")) pkgs = sw.slice(2).filter((t) => !t.startsWith("-"));
    } else if ((pm === "uv" || pm === "poetry") && sub === "add") {
      pkgs = sw.slice(2).filter((t) => !t.startsWith("-"));
    } else if (["npx", "bunx"].includes(pm) || (pm === "pnpm" && sub === "dlx")) {
      const name = (pm === "pnpm" ? sw[2] : sw.slice(1).find((t) => !t.startsWith("-"))) || "";
      const base = name.replace(/@[^@/]*$/, "") || name;
      if (name && !KNOWN_RUNNERS.has(base)) pkgs = [name];
    }
    if (pkgs.length) {
      return ask(
        `新しいパッケージ（${pkgs.join("、")}）を取り込みます。AI は実在しない名前を作ることがあり、その名前で偽物が公開されている場合があります。` +
          `npmjs.com（Python は pypi.org）で、名前のつづり・週間ダウンロード数・最終更新日・公式リポジトリを確認してから許可してください。`
      );
    }
  }

  return null;
}

// ────────────────────────────────────────────────
// 5. AI に送るメッセージ（プロンプト）のチェック
// ────────────────────────────────────────────────

export function checkPrompt(text) {
  const secrets = findSecrets(text);
  if (!secrets.length) return null;
  return {
    action: "block",
    reason:
      `メッセージに秘密情報らしき文字列が入っていたため、AI には送らずに止めました（${secrets
        .map((s) => `${s.name}: ${s.sample}`)
        .join("、")}）。\n` +
      "・キーは .env に自分で書き込み、AI には「OPENAI_API_KEY という名前で .env に入れた」のように名前だけを伝えてください。\n" +
      "・別のチャットや画面共有ですでに貼ってしまったキーは、発行元の管理画面で無効化して作り直してください。\n" +
      "・本物のキーでない（説明用の例）なら、値を <YOUR_API_KEY> のように書き換えてから送ってください。",
  };
}
