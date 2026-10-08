#!/usr/bin/env node
// AI コーディングツールのフックから呼ばれる入口（Claude Code・Codex 共通）。
//   Claude Code: .claude/settings.json の hooks から  node .../hook.mjs
//   Codex:       .codex/hooks.json から               node .../hook.mjs --agent codex
// 標準入力で受け取った JSON を rules.mjs で調べ、問題があれば止める。
//
// 止め方は「理由を標準エラーに出して終了コード 2」で統一している（どのツールでも「ブロック」になる）。
// 「人に確認する（ask）」は Claude Code だけが対応しているので、他のツールでは止める扱いにする。
import fs from "node:fs";
import path from "node:path";
import { checkPrompt, checkFileAccess, checkWrite, checkCommand, reviewWrittenFile } from "./rules.mjs";

const agent = process.argv.includes("--agent") ? process.argv[process.argv.indexOf("--agent") + 1] : "claude";
const TAG = "[セキュリティ・ハーネス]";
let input = {};
try {
  input = JSON.parse(fs.readFileSync(0, "utf8") || "{}");
} catch (e) {
  process.stderr.write(`${TAG} 入力を読み取れませんでした: ${e.message}\n`);
  process.exit(0);
}
const event = String(input.hook_event_name || "").toLowerCase();
const tool = input.tool_name || "";
const ti = input.tool_input || {};
const cwd = input.cwd || process.cwd();

function stop(reason) {
  process.stderr.write(`${TAG} ${reason}\n`);
  process.exit(2);
}

function decide(result) {
  if (!result) return;
  if (result.action === "ask") {
    if (agent === "claude" && !process.env.CURSOR_PROJECT_DIR) {
      // Claude Code: 利用者に確認画面を出す
      process.stdout.write(
        JSON.stringify({
          hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: `${TAG} ${result.reason}` },
        })
      );
      process.exit(0);
    }
    stop(`${result.reason}\nこのツールでは確認画面を出せないため止めました。実行する内容と理由を利用者に説明し、利用者が自分のターミナルで実行するよう依頼してください。`);
  }
  stop(result.reason);
}

// Codex の apply_patch（ファイル編集）の中身から、ファイル名と追加される行を取り出す。
function parsePatch(patch) {
  const files = [];
  let cur = null;
  for (const line of String(patch).split("\n")) {
    const m = line.match(/^\*\*\* (Add|Update|Delete) File: (.+)$/) || line.match(/^\*\*\* Move to: (.+)$/);
    if (m) {
      cur = { path: (m[2] || m[1]).trim(), added: [] };
      files.push(cur);
    } else if (cur && line.startsWith("+") && !line.startsWith("+++")) {
      cur.added.push(line.slice(1));
    }
  }
  return files.map((f) => ({ path: path.resolve(cwd, f.path), content: f.added.join("\n") }));
}

try {
  if (event === "userpromptsubmit" || event === "beforesubmitprompt") {
    const r = checkPrompt(input.prompt || "");
    if (r && agent === "claude" && event === "userpromptsubmit" && !process.env.CURSOR_PROJECT_DIR) {
      // Claude Code: 止めたメッセージ（キー入り）を画面に再表示しない
      process.stdout.write(
        JSON.stringify({
          decision: "block",
          reason: `${TAG} ${r.reason}`,
          hookSpecificOutput: { hookEventName: "UserPromptSubmit", suppressOriginalPrompt: true },
        })
      );
      process.exit(0);
    }
    decide(r);
  }

  if (event === "pretooluse") {
    if (tool === "Bash" || tool === "Shell") decide(checkCommand(typeof ti.command === "string" ? ti.command : [].concat(ti.command || []).join(" "), cwd));
    if (tool === "Read" || tool === "NotebookRead") decide(checkFileAccess(ti.file_path || ti.notebook_path));
    if (tool === "Grep" || tool === "Glob") decide(checkFileAccess(ti.path) || checkFileAccess(ti.glob) || checkFileAccess(ti.pattern));
    if (tool === "Write") decide(checkWrite(ti.file_path, ti.content));
    if (tool === "Edit") decide(checkWrite(ti.file_path, ti.new_string));
    if (tool === "MultiEdit") decide(checkWrite(ti.file_path, (ti.edits || []).map((e) => e.new_string).join("\n")));
    if (tool === "NotebookEdit") decide(checkWrite(ti.notebook_path, ti.new_source));
    if (tool === "Delete") decide(checkFileAccess(ti.file_path || ti.path));
    if (tool === "apply_patch") for (const f of parsePatch(ti.command)) decide(checkWrite(f.path, f.content));
  }

  if (event === "posttooluse") {
    const targets =
      tool === "apply_patch"
        ? parsePatch(ti.command).map((f) => f.path)
        : ["Write", "Edit", "MultiEdit"].includes(tool) && ti.file_path
          ? [ti.file_path]
          : [];
    const notes = [];
    for (const file of targets) {
      if (!fs.existsSync(file)) continue;
      const r = reviewWrittenFile(file, fs.readFileSync(file, "utf8"));
      if (r) notes.push(r.reason);
    }
    // 終了コード 2 で、書き込み後の指摘を AI に伝える（書き込みは取り消されない）
    if (notes.length) stop(`書き込みは完了しましたが、次の点を直してください。\n${notes.join("\n")}`);
  }
} catch (e) {
  // 判定そのものが失敗したときは作業を止めず、理由だけ表示する
  process.stderr.write(`${TAG} チェック中にエラーが起きました: ${e.message}\n`);
  process.exit(0);
}
process.exit(0);
