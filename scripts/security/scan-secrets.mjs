#!/usr/bin/env node
// 秘密情報がファイルに紛れ込んでいないかを調べる。
//   node scripts/security/scan-secrets.mjs --staged      コミットしようとしているファイル（pre-commit で使う）
//   node scripts/security/scan-secrets.mjs --all         Git で管理しているすべてのファイル
//   node scripts/security/scan-secrets.mjs --dir .next   フォルダの中身（ビルド後の成果物の確認に使う）
// 見つかったら終了コード 1 で終わる。
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { findSecrets, sensitiveFileLabel } from "./rules.mjs";

const args = process.argv.slice(2);
const mode = args[0] || "--staged";
const MAX_BYTES = 2 * 1024 * 1024; // 2MB より大きいファイルは飛ばす
const SKIP_DIRS = new Set(["node_modules", ".git"]);
const TEXT_EXT = /\.(?:[cm]?[jt]sx?|json|ya?ml|toml|env|txt|md|mdx|html?|css|scss|vue|svelte|astro|py|rb|go|rs|java|kt|swift|dart|php|sh|sql|ini|cfg|conf|xml|plist|properties|map|rules)$|(?:^|\/)[^.]+$/i;

const git = (...a) => execFileSync("git", a, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });

function listFiles() {
  if (mode === "--staged") {
    return git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").split("\0").filter(Boolean);
  }
  if (mode === "--all") return git("ls-files", "-z").split("\0").filter(Boolean);
  if (mode === "--dir") {
    const root = args[1] || ".";
    const out = [];
    const walk = (d) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        if (SKIP_DIRS.has(e.name)) continue;
        const p = path.join(d, e.name);
        if (e.isDirectory()) walk(p);
        else out.push(p);
      }
    };
    walk(root);
    return out;
  }
  console.error("使い方: scan-secrets.mjs --staged | --all | --dir <フォルダ>");
  process.exit(2);
}

function readContent(file) {
  if (mode === "--staged") {
    // コミットされる中身（ステージ済みの版）を読む
    return execFileSync("git", ["show", `:${file}`], { maxBuffer: MAX_BYTES * 2 });
  }
  return fs.readFileSync(file);
}

const problems = [];
for (const file of listFiles()) {
  const label = sensitiveFileLabel(file);
  if (label) {
    problems.push(`${file}: Git に入れてはいけないファイルです（${label}）`);
    continue;
  }
  if (!TEXT_EXT.test(file)) continue;
  let buf;
  try {
    buf = readContent(file);
  } catch {
    continue;
  }
  if (buf.length > MAX_BYTES || buf.includes(0)) continue; // 大きいファイル・バイナリは飛ばす
  const text = buf.toString("utf8");
  // テストコードやドキュメントの説明用の例は誤検知しやすいので、代入形式の検出は使わない
  const isDoc = /\.(?:md|mdx|txt)$/i.test(file) || /(?:^|\/)(?:__tests__|test|tests|fixtures?)\/|\.(?:test|spec)\.[cm]?[jt]sx?$/.test(file);
  for (const s of findSecrets(text, { assignments: !isDoc })) {
    problems.push(`${file}: ${s.name}（${s.sample}）`);
  }
}

if (problems.length) {
  console.error("\n[セキュリティ・ハーネス] 秘密情報らしきものが見つかりました:\n");
  for (const p of problems) console.error(`  ✗ ${p}`);
  console.error(
    "\n対処:\n" +
      "  1. 値を .env に移し、コードでは process.env.名前 で読み込む\n" +
      "  2. .env などは git rm --cached <ファイル> で Git の管理から外す（.gitignore に入っているか確認）\n" +
      "  3. すでに GitHub へ push したキーは、発行元の管理画面ですぐに無効化して作り直す\n" +
      "  誤検知の場合だけ、git commit --no-verify で今回のチェックを飛ばせます。\n"
  );
  process.exit(1);
}
if (mode !== "--staged") console.log("[セキュリティ・ハーネス] 秘密情報は見つかりませんでした。");
