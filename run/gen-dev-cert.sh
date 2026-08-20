#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cert_dir="${repo_root}/source/certs"
days="${1:-825}"

mkdir -p "${cert_dir}"

if [[ -f "${cert_dir}/dev.crt" && -f "${cert_dir}/dev.key" ]]; then
  echo "dev cert already exists at ${cert_dir}/dev.crt — remove it first to regenerate"
  exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${cert_dir}/dev.key" \
  -out "${cert_dir}/dev.crt" \
  -days "${days}" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "${cert_dir}/dev.key"
echo "wrote ${cert_dir}/dev.crt and ${cert_dir}/dev.key (self-signed, ${days} days)"
