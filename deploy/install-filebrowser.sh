#!/bin/bash
# Installs File Browser as the decoy drive: listening on loopback only, no
# sign-up, an admin account and one ordinary account per tunnel user.
# Usage: install-filebrowser.sh [port] [user ...]
# Passwords are written to /root/filebrowser-accounts.txt.
set -euo pipefail
PORT="${1:-18080}"
shift || true
USERS=("$@")
VERSION=v2.63.23
DB=/var/lib/filebrowser/filebrowser.db
ROOT=/srv/drive
ACCOUNTS=/root/filebrowser-accounts.txt

case "$(uname -m)" in
	x86_64) ARCH=amd64 ;;
	aarch64) ARCH=arm64 ;;
	*) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/fb.tgz" "https://github.com/filebrowser/filebrowser/releases/download/$VERSION/linux-$ARCH-filebrowser.tar.gz"
tar -xzf "$tmp/fb.tgz" -C "$tmp" filebrowser
install -m 755 "$tmp/filebrowser" /usr/local/bin/filebrowser
filebrowser version

id filebrowser >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin filebrowser
mkdir -p /var/lib/filebrowser "$ROOT"/{文档,照片,备份}
pw() { openssl rand -base64 18 | tr -d '/+=' | cut -c1-20; }

if [ ! -f "$DB" ]; then
	filebrowser -d "$DB" config init >/dev/null
	filebrowser -d "$DB" config set --address 127.0.0.1 --port "$PORT" --root "$ROOT" --signup=false >/dev/null
	ADMIN_PW=$(pw)
	filebrowser -d "$DB" users add admin "$ADMIN_PW" --perm.admin >/dev/null
	echo "admin $ADMIN_PW" > "$ACCOUNTS"
	# Something to look at: an encrypted backup set, the kind of content the
	# tunnel traffic is meant to resemble.
	for i in 1 2 3; do
		head -c $((RANDOM * 64 + 1048576)) /dev/urandom > "$ROOT/备份/$(openssl rand -hex 16).bin"
	done
	echo "# 个人资料" > "$ROOT/文档/README.md"
fi
for u in "${USERS[@]}"; do
	if ! grep -q "^$u " "$ACCOUNTS" 2>/dev/null; then
		UPW=$(pw)
		filebrowser -d "$DB" users add "$u" "$UPW" --scope "/$u" >/dev/null
		mkdir -p "$ROOT/$u/备份"
		# A user's own view should not be empty: the client logs in and lists it.
		for i in 1 2; do
			head -c $((RANDOM * 48 + 786432)) /dev/urandom > "$ROOT/$u/备份/$(date -d "-$((i * 3)) day" +%Y%m%d)-$(openssl rand -hex 4).bin"
		done
		echo "$u $UPW" >> "$ACCOUNTS"
	fi
done
chmod 600 "$ACCOUNTS"
chown -R filebrowser:filebrowser /var/lib/filebrowser "$ROOT"

cat > /etc/systemd/system/filebrowser.service <<EOF
[Unit]
Description=File Browser
After=network.target

[Service]
ExecStart=/usr/local/bin/filebrowser -d $DB
User=filebrowser
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now filebrowser
sleep 1
curl -fsS -o /dev/null -w "File Browser on 127.0.0.1:$PORT: HTTP %{http_code}\n" "http://127.0.0.1:$PORT/"
echo "accounts: $ACCOUNTS"
