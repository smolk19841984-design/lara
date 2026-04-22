#!/bin/sh
# fix_jb_perms.sh — Filza/terminal helper to set ownership and perms
# Usage: run as root (Filza "Run as root" or in terminal with su)

DIRS="/var/jb /var/tmp/jb /var/mobile/jb /var/tmp/lara-stage-jb /var/mobile/lara-stage-jb"

echo "Starting fix_jb_perms.sh — ensure you run this as root"

for d in $DIRS; do
  echo "----- $d -----"
  if [ -e "$d" ]; then
    echo "Exists:"
    ls -ld "$d"
  else
    echo "Not exists — creating: $d"
    mkdir -p "$d" || echo "mkdir failed for $d"
  fi

  echo "Setting owner -> mobile:mobile"
  chown -R mobile:mobile "$d" 2>/dev/null || echo "chown failed for $d (need root)"

  echo "Setting mode -> 0755"
  chmod -R 0755 "$d" 2>/dev/null || echo "chmod failed for $d (need root)"

  echo "Result:"
  ls -ld "$d" || true
  echo
done

echo "Done."
