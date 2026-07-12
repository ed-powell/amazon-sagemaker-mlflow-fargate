#!/usr/bin/env bash
set -euo pipefail

# The basic-auth store needs its OWN database (it and the tracking store both
# migrate with Alembic's default "alembic_version" table and would collide in a
# shared DB). RDS only provisions the initial database, so create it here.
python - <<'PY'
import os, pymysql
conn = pymysql.connect(
    host=os.environ["HOST"], port=int(os.environ["PORT"]),
    user=os.environ["USERNAME"], password=os.environ["PASSWORD"],
)
conn.cursor().execute("CREATE DATABASE IF NOT EXISTS mlflow_auth")
conn.commit()
conn.close()
print("startup: ensured mlflow_auth database")
PY

# Generate the basic-auth config (configparser does no env-var substitution).
cat > /mlflow/auth.ini <<EOF
[mlflow]
default_permission = READ
database_uri = mysql+pymysql://${USERNAME}:${PASSWORD}@${HOST}:${PORT}/mlflow_auth
admin_username = ${ADMIN_USERNAME}
admin_password = ${ADMIN_PASSWORD}
authorization_function = mlflow.server.auth:authenticate_request_basic_auth
EOF
export MLFLOW_AUTH_CONFIG_PATH=/mlflow/auth.ini

# Initialize the auth store up front. gunicorn swallows the worker-boot
# traceback, so doing this here makes any failure visible in CloudWatch.
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
    --backend-store-uri "mysql+pymysql://${USERNAME}:${PASSWORD}@${HOST}:${PORT}/${DATABASE}" \
    --app-name basic-auth \
    --workers 1 \
    --gunicorn-opts "--timeout 180 --capture-output --log-level debug"
