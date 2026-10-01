#!/bin/bash
#
# ATS Solutions - SPF Flattener installer
# Thin wrapper around install.php, which does the real work.
# install.php is also directly runnable: php install.php
#
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v php >/dev/null 2>&1; then
  echo "Error: php is not installed." >&2
  exit 1
fi

exec php "$DIR/install.php"
