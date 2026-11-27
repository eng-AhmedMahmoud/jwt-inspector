#!/usr/bin/env bash
# The merge gate, step for step what Jenkins runs (Jenkinsfile). Run it from
# anywhere: bash scripts/ci-local.sh
#
# There is no build: `wrangler deploy` uploads the repo root as Worker static
# assets (wrangler.jsonc "assets.directory": "."), minus what .assetsignore
# lists. So the gate checks what a deploy ships.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "ci-local: FAIL: $*" >&2; exit 1; }

# 1. The page.
[ -f index.html ] || fail "index.html is missing"
grep -Eqi '<title>[^<]*[^[:space:]<][^<]*</title>' index.html || fail "index.html has no <title>"
echo "ci-local: index.html has a <title>"

# 2. The Worker config parses (JSONC: drop // comments, then JSON.parse).
node -e '
  const fs = require("fs");
  const src = fs.readFileSync("wrangler.jsonc", "utf8").replace(/(^|[^:"])\/\/.*$/gm, "$1");
  const cfg = JSON.parse(src);
  if (!cfg.name) throw new Error("no name");
  if (!cfg.assets || !cfg.assets.directory) throw new Error("no assets.directory");
  const routes = (cfg.routes || []).map((r) => r.pattern).join(", ");
  console.log(`ci-local: wrangler.jsonc parses (${cfg.name} -> ${routes || "no routes"})`);
' || fail "wrangler.jsonc does not parse"

# 3. No Vercel config anywhere in the checkout. The site deploys to Cloudflare.
vercel_cfg="$(find . -path ./.git -prune -o -path ./node_modules -prune -o \
  \( -name vercel.json -o -name vercel.ts -o -name .vercelignore \) -print)"
[ -z "$vercel_cfg" ] || fail "Vercel config found (this site deploys to Cloudflare): $vercel_cfg"
echo "ci-local: no Vercel config"

# 4. What a deploy ships: tracked and new files, minus .assetsignore (the same
#    gitignore-style patterns wrangler applies).
[ -f .assetsignore ] || fail ".assetsignore is missing"
shipped="$(comm -23 \
  <(git ls-files -co --exclude-standard | sort -u) \
  <(git ls-files -co -i --exclude-from=.assetsignore | sort -u))"
[ -n "$shipped" ] || fail "nothing would ship"
grep -qx index.html <<<"$shipped" || fail "index.html would not ship (.assetsignore)"

leaked="$(grep -E '^(Jenkinsfile|\.nvmrc|scripts/)' <<<"$shipped" || true)"
[ -z "$leaked" ] || fail "repo tooling would ship as public assets; add it to .assetsignore: $leaked"
echo "ci-local: Jenkinsfile, scripts/ and .nvmrc stay out of the Worker assets"

web=()
while IFS= read -r f; do
  case "$f" in *.html|*.js|*.css) web+=("$f") ;; esac
done <<<"$shipped"
if [ "${#web[@]}" -gt 0 ] && grep -nE 'vercel\.app|vercel-storage\.com|/_vercel/' "${web[@]}"; then
  fail "a shipped file points at a Vercel host (above)"
fi
echo "ci-local: no Vercel host in ${#web[@]} shipped html/js/css files"

echo "ci-local: all steps passed"
