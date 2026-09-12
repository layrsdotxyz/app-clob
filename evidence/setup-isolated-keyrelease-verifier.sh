#!/usr/bin/env bash
set -euo pipefail

dnf install -y postgresql15-server >/var/log/layrs-pg-install.log 2>&1
test -s /var/lib/pgsql/data/PG_VERSION || postgresql-setup --initdb >/var/log/layrs-pg-init.log 2>&1
systemctl enable --now postgresql >/dev/null

for role in layrsv2_worker_role layrsv2_api_role layrsv2_auditor_role layrsv2_operator; do
  if ! sudo -u postgres psql -Atc "SELECT 1 FROM pg_roles WHERE rolname='${role}'" | grep -qx 1; then
    sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE ROLE ${role}" >/dev/null
  fi
done
if ! sudo -u postgres psql -Atc "SELECT 1 FROM pg_roles WHERE rolname='direct_runtime'" | grep -qx 1; then
  sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE ROLE direct_runtime LOGIN SUPERUSER" >/dev/null
fi
if ! sudo -u postgres psql -Atc "SELECT 1 FROM pg_database WHERE datname='layrs_direct'" | grep -qx 1; then
  sudo -u postgres createdb -O direct_runtime layrs_direct
fi
sudo -u postgres psql -v ON_ERROR_STOP=1 -c \
  "ALTER ROLE direct_runtime PASSWORD 'layrs_isolated_df846b8_only'" >/dev/null

if [[ ! -s /var/lib/pgsql/data/server.crt || ! -s /var/lib/pgsql/data/server.key ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' \
    -keyout /var/lib/pgsql/data/server.key \
    -out /var/lib/pgsql/data/server.crt >/dev/null 2>&1
  chown postgres:postgres /var/lib/pgsql/data/server.crt /var/lib/pgsql/data/server.key
  chmod 600 /var/lib/pgsql/data/server.key
  chmod 644 /var/lib/pgsql/data/server.crt
fi
sed -i '/^ssl = /d;/^ssl_cert_file = /d;/^ssl_key_file = /d' /var/lib/pgsql/data/postgresql.conf
cat >>/var/lib/pgsql/data/postgresql.conf <<'PGCONF'
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
PGCONF
grep -q '^hostssl layrs_direct direct_runtime 127.0.0.1/32 scram-sha-256$' /var/lib/pgsql/data/pg_hba.conf || \
  sed -i '1ihostssl layrs_direct direct_runtime 127.0.0.1/32 scram-sha-256' /var/lib/pgsql/data/pg_hba.conf
systemctl restart postgresql

sudo -u postgres psql -v ON_ERROR_STOP=1 -d layrs_direct -f /tmp/layrs-direct-ddl.sql >/var/log/layrs-direct-ddl.log
sudo -u postgres psql -v ON_ERROR_STOP=1 -d layrs_direct <<'SQL' >/dev/null
INSERT INTO layrs_direct_v1.direct_execution_writer_fence(
  epoch_id, old_writer_fence_evidence_sha256, old_writer_authorized,
  target_writer_enabled, activation_id
) VALUES (
  'layrs-opening-epoch-20260911-941107537728c98b',
  'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364',
  false, true, 'layrs-direct-df846b8-keyrelease-20260913'
) ON CONFLICT (epoch_id) DO UPDATE SET
  old_writer_fence_evidence_sha256=EXCLUDED.old_writer_fence_evidence_sha256,
  old_writer_authorized=false,
  target_writer_enabled=true,
  activation_id=EXCLUDED.activation_id;

INSERT INTO layrs_direct_v1.direct_execution_writer_grants(
  activation_id, epoch_id, old_writer_fence_evidence_sha256,
  expires_at_unix, grant_json
) VALUES (
  'layrs-direct-df846b8-keyrelease-20260913',
  'layrs-opening-epoch-20260911-941107537728c98b',
  'b991e41682d01c546e11c03bca79a8e141b4f6d892a3afb6a5a0fe6720182364',
  1789497789,
  convert_from(pg_read_binary_file('/tmp/layrs-writer-grant.json'),'UTF8')::jsonb
) ON CONFLICT (activation_id) DO NOTHING;
SQL

rm -f /tmp/layrs-direct-ddl.sql /tmp/setup-verifier.sh
sudo -u postgres psql -d layrs_direct -Atc \
  "SELECT old_writer_authorized,target_writer_enabled,activation_id FROM layrs_direct_v1.direct_execution_writer_fence"
