# Install & quickstart (Claude Code users)

## Make your Claude use it
Drop this `sbom-kb/` folder into one of:
- **Personal** (available in every project): `~/.claude/skills/sbom-kb/`
- **Project**: `<your-project>/.claude/skills/sbom-kb/`

Claude Code auto-discovers it from the `SKILL.md` frontmatter. Then ask, e.g.
*"use sbom-kb to build an SBOM KB for <target>"* or *"show the pre-auth-reachable n-days"*.
(Not using the skill system? It's just files -- `cat SKILL.md` and run the scripts directly.)

## 30-second smoke test
```bash
cd sbom-kb
# Build a KB for your target (edit CONFIG in build_sbom.py first, or set env vars):
SBOM_HOST=myhost SBOM_PKGS_CUR=pkgs-current.txt SBOM_PKGS_SUCC=pkgs-patched.txt ./scripts/rebuild.sh
./scripts/q.sh                                   # the money query
./scripts/q.sh "SELECT * FROM v_completeness"
```

## Then
- **Build a KB for your target** -- edit the `CONFIG` block in `scripts/build_sbom.py` (or set
  `SBOM_HOST` / `SBOM_PKGS_CUR` / `SBOM_PKGS_SUCC`), then `./scripts/rebuild.sh`. Full workflow in
  `SKILL.md`.

## Requirements
- `python3` (standard library only). `sqlite3` CLI optional -- `q.sh` falls back to python.
- *Building* a fresh KB needs ssh access to a live host of your target build (for `ldd` +
  version-grep). *Querying* needs nothing.
