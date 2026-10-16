#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

release_tmp=$(mktemp -d /tmp/vulngym-agent-release.XXXXXX)
case "$release_tmp" in
  /tmp/vulngym-agent-release.*) ;;
  *)
    echo "unsafe temporary directory: $release_tmp" >&2
    exit 2
    ;;
esac

cleanup() {
  case "$release_tmp" in
    /tmp/vulngym-agent-release.*) rm -rf -- "$release_tmp" ;;
  esac
}
trap cleanup EXIT

git archive HEAD | tar -x -C "$release_tmp"
cd "$release_tmp"

echo "Clean archive: $release_tmp"
echo "Tracked files: $(find "$release_tmp" -type f | wc -l)"
echo "Secret-like files: $(find "$release_tmp" -type f \( -name .env -o -name '*.key' -o -name '*.pem' \) | wc -l)"

python3 scripts/show_demo.py > /tmp/vulngym-agent-demo-check.txt
echo "Offline demo: PASS ($(wc -l < /tmp/vulngym-agent-demo-check.txt) lines)"

PYTHONPATH=src python3 -m unittest discover -s tests -t . -q
python3 scripts/verify_delivery.py

PYTHONPATH=src python3 -m vulngym_agent --help > /tmp/vulngym-agent-cli-help.txt
for command in validate run-semantic build-submission render-report; do
  grep -q "$command" /tmp/vulngym-agent-cli-help.txt
done
echo "CLI entry point: PASS"
echo "CLEAN ARCHIVE CHECK: PASS"
