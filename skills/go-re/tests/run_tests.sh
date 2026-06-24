#!/usr/bin/env bash
# go-re test suite — builds hermetic, STRIPPED (-s -w) Go fixtures and checks all 4 subcommands.
# Proves the value prop: fixtures have no ELF symtab, yet gore still works (via .gopclntab).
set -u
ROOT="$(cd "$(dirname "$(readlink -f "$0")")/../../.." && pwd)"   # disasm-codemode root
GORE="$ROOT/skills/go-re/gore"
command -v go >/dev/null 2>&1 || { echo "SKIP: go not installed"; exit 0; }
[ -x "$GORE" ] || (cd "$ROOT/skills/go-re/src" && go build -o ../gore .) || { echo "build failed"; exit 1; }

PASS=0; FAIL=0
ok(){ if eval "$2" >/dev/null 2>&1; then echo "  ok   $1"; PASS=$((PASS+1)); else echo "  FAIL $1"; FAIL=$((FAIL+1)); fi; }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/a" "$TMP/b"
cat > "$TMP/a/main.go" <<'GO'
package main
import "fmt"
//go:noinline
func alpha(x int) int { return x + 1 }
//go:noinline
func beta(x int) int { return alpha(x) * 2 }
//go:noinline
func gamma() string { return "hello" }
func main() { fmt.Println(beta(3), gamma()) }
GO
cat > "$TMP/b/main.go" <<'GO'
package main
import "fmt"
//go:noinline
func alpha(x int) int { return x + 2 }   // CHANGED body
//go:noinline
func beta(x int) int { return alpha(x) * 2 }
//go:noinline
func gamma() string { return "hello" }
//go:noinline
func delta() int { return 99 }            // ADDED
func main() { fmt.Println(beta(3), gamma(), delta()) }
GO
( cd "$TMP/a" && go mod init fx >/dev/null 2>&1 && go build -ldflags "-s -w" -o "$TMP/v1" . ) || { echo "fixture v1 build failed"; exit 1; }
( cd "$TMP/b" && go mod init fx >/dev/null 2>&1 && go build -ldflags "-s -w" -o "$TMP/v2" . ) || { echo "fixture v2 build failed"; exit 1; }
printf 'int main(){return 0;}\n' > "$TMP/c.c"; cc -o "$TMP/cbin" "$TMP/c.c" 2>/dev/null || cp /bin/true "$TMP/cbin"

echo "go-re test suite:"
ok "fixtures are stripped (no .symtab) — the -s -w case" '! readelf -S "$TMP/v1" 2>/dev/null | grep -q "\.symtab"'
LIST=$("$GORE" list "$TMP/v1" 'main\.(alpha|beta|gamma|main)$')
ok "list finds main.alpha"                  'echo "$LIST" | grep -q "main\.alpha$"'
ok "list finds main.beta"                   'echo "$LIST" | grep -q "main\.beta$"'
ok "list format = addr size name"           'echo "$LIST" | grep -qE "^0x[0-9a-f]+  [0-9]+  main\.alpha$"'
AADDR=$(echo "$LIST" | awk "/main\.alpha\$/{print \$1; exit}")
ok "addr resolves <alpha-addr> -> main.alpha" '"$GORE" addr "$TMP/v1" "$AADDR" | grep -q "main\.alpha$"'
ok "xref <alpha-addr> -> caller main.beta"    '"$GORE" xref "$TMP/v1" "$AADDR" | grep -q "main\.beta$"'
D=$("$GORE" diff "$TMP/v1" "$TMP/v2")
ok "diff: main.alpha CHANGED"               'echo "$D" | grep -q "^CHANGED main\.alpha$"'
ok "diff: main.delta ADDED"                 'echo "$D" | grep -q "^ADDED main\.delta$"'
ok "diff: header counts present"            'echo "$D" | grep -qE "^# a=[0-9]+ b=[0-9]+ CHANGED=[0-9]+ added=[0-9]+ removed=[0-9]+$"'
ok "diff identical -> CHANGED=0"            '"$GORE" diff "$TMP/v1" "$TMP/v1" | grep -q "CHANGED=0 added=0 removed=0"'
ok "non-Go binary -> error + nonzero exit"  '! "$GORE" list "$TMP/cbin" "."'
ok "missing file -> nonzero exit"           '! "$GORE" list "$TMP/nope" "."'
ok "bad usage -> nonzero exit"              '! "$GORE" diff "$TMP/v1"'

echo "  ---- $PASS passed, $FAIL failed ----"
[ "$FAIL" -eq 0 ]
