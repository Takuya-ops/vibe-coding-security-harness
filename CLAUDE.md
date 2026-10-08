# CLAUDE.md

このプロジェクトのセキュリティのルールは AGENTS.md にまとめています（Codex・Cursor と共通）。必ず従ってください。

@AGENTS.md

## Claude Code 向けの補足

- `.claude/settings.json` のフックが、秘密情報の貼り付け・`.env` の読み取り・危ないコマンドを止めます。止められたら別の方法で回避しようとせず、理由を利用者に伝えてください。
- 公開前の点検は `/security-check` で行えます（`.claude/skills/security-check/SKILL.md`）。
