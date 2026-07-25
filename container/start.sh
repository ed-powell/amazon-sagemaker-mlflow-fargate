#!/usr/bin/env bash
set -euo pipefail

# MySQL 8 creates the RDS master user with caching_sha2_password. pymysql 1.0.2
# completes the first connection (RSA handshake) but fails the follow-up
# SQLAlchemy connection's caching_sha2 handshake with "Access denied" (1045).
# Avoid it by creating a dedicated mysql_native_password app user and connecting
# both stores as that user. Also create the separate mlflow_auth database (auth
# and tracking stores both use Alembic's default alembic_version table and can't
# share one DB). The first connection (master user) works via the RSA path.
python - <<'PY'
import os, pymysql
pw = os.environ["PASSWORD"]
db = os.environ["DATABASE"]
conn = pymysql.connect(host=os.environ["HOST"], port=int(os.environ["PORT"]),
                       user=os.environ["USERNAME"], password=pw)
cur = conn.cursor()
for stmt in [
    "CREATE DATABASE IF NOT EXISTS mlflow_auth",
    f"CREATE USER IF NOT EXISTS 'mlflowapp'@'%' IDENTIFIED WITH mysql_native_password BY '{pw}'",
    f"ALTER USER 'mlflowapp'@'%' IDENTIFIED WITH mysql_native_password BY '{pw}'",
    f"GRANT ALL PRIVILEGES ON `{db}`.* TO 'mlflowapp'@'%'",
    "GRANT ALL PRIVILEGES ON `mlflow_auth`.* TO 'mlflowapp'@'%'",
    "FLUSH PRIVILEGES",
]:
    cur.execute(stmt)
conn.commit(); conn.close()
print("startup: ensured mlflow_auth database + mlflowapp (native_password) user")
PY

DB_USER=mlflowapp

cat > /mlflow/auth.ini <<EOF
[mlflow]
default_permission = READ
database_uri = mysql+pymysql://${DB_USER}:${PASSWORD}@${HOST}:${PORT}/mlflow_auth
admin_username = ${ADMIN_USERNAME}
admin_password = ${ADMIN_PASSWORD}
authorization_function = mlflow.server.auth:authenticate_request_basic_auth
EOF
export MLFLOW_AUTH_CONFIG_PATH=/mlflow/auth.ini

python - <<'PY'
import sys, traceback
from mlflow.server.auth.config import read_auth_config
from mlflow.server.auth.sqlalchemy_store import SqlAlchemyStore
cfg = read_auth_config()
try:
    SqlAlchemyStore().init_db(cfg.database_uri)
    print("startup: auth store init_db OK")
except Exception:
    print("startup: auth store init_db FAILED:", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)
PY

exec mlflow server \
    --host 0.0.0.0 \
    --port 5000 \
    --default-artifact-root "${BUCKET}" \
    --backend-store-uri "mysql+pymysql://${DB_USER}:${PASSWORD}@${HOST}:${PORT}/${DATABASE}" \
    --app-name basic-auth \
    --workers 1 \
    --gunicorn-opts "--timeout 180 --capture-output --log-level debug"
