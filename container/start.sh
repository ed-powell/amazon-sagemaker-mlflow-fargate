#!/usr/bin/env bash
set -euo pipefail

# Create the separate auth database and a dedicated application DB user, then
# launch MLflow. Two connection subtleties on RDS MySQL 8 drive this design:
#
#  1. The RDS master user uses caching_sha2_password, which pymysql fails to
#     re-authenticate over the auth store's SQLAlchemy connections (1045). So we
#     use a dedicated mysql_native_password user for the store connections.
#  2. MLflow's auth store round-trips the DB URL through configparser (auth.ini)
#     AND through Alembic's own configparser-based config during migration; a
#     password containing '%' (which configparser treats as interpolation) gets
#     corrupted, again yielding 1045. To avoid the whole class of problem we give
#     the app user a freshly generated, purely alphanumeric (hex) password.
#
# The separate mlflow_auth database is required because the auth and tracking
# stores both migrate with Alembic's default alembic_version table.
python - <<'PY'
import os, secrets, pymysql
master_pw = os.environ["PASSWORD"]
db = os.environ["DATABASE"]
app_pw = secrets.token_hex(24)  # 48 hex chars: no %, @, :, / -> safe everywhere
conn = pymysql.connect(host=os.environ["HOST"], port=int(os.environ["PORT"]),
                       user=os.environ["USERNAME"], password=master_pw)
cur = conn.cursor()
for stmt in [
    "CREATE DATABASE IF NOT EXISTS mlflow_auth",
    f"CREATE USER IF NOT EXISTS 'mlflowapp'@'%' IDENTIFIED WITH mysql_native_password BY '{app_pw}'",
    f"ALTER USER 'mlflowapp'@'%' IDENTIFIED WITH mysql_native_password BY '{app_pw}'",
    f"GRANT ALL PRIVILEGES ON `{db}`.* TO 'mlflowapp'@'%'",
    "GRANT ALL PRIVILEGES ON `mlflow_auth`.* TO 'mlflowapp'@'%'",
    "FLUSH PRIVILEGES",
]:
    cur.execute(stmt)
conn.commit()
conn.close()
with open("/mlflow/app_pw", "w") as f:
    f.write(app_pw)
print("startup: ensured mlflow_auth database + mlflowapp (native_password) user")
PY

APP_PW="$(cat /mlflow/app_pw)"
DB_USER=mlflowapp

# admin_password is the login password (stored in the users table), read once by
# configparser -- escape '%' as '%%' so a '%' in the secret survives.
ADMIN_PW_INI="${ADMIN_PASSWORD//%/%%}"

cat > /mlflow/auth.ini <<EOF
[mlflow]
default_permission = READ
database_uri = mysql+pymysql://${DB_USER}:${APP_PW}@${HOST}:${PORT}/mlflow_auth
admin_username = ${ADMIN_USERNAME}
admin_password = ${ADMIN_PW_INI}
authorization_function = mlflow.server.auth:authenticate_request_basic_auth
EOF
export MLFLOW_AUTH_CONFIG_PATH=/mlflow/auth.ini

# Initialize the auth store up front so any error is visible in CloudWatch
# (gunicorn swallows the worker-boot traceback).
export PYTHONUNBUFFERED=1
python - <<'PY'
import sys, traceback
from sqlalchemy import create_engine, text
from alembic.script import ScriptDirectory
from mlflow.server.auth.config import read_auth_config
from mlflow.server.auth.sqlalchemy_store import SqlAlchemyStore
from mlflow.server.auth.db.models import Base
from mlflow.server.auth.db.utils import _get_alembic_config

cfg = read_auth_config()
try:
    # MLflow's auth migration (migrate_if_needed -> upgrade -> env.py) builds a
    # fresh NullPool engine that fails to authenticate to this RDS (1045), even
    # though every pooled connection we make succeeds. Work around it by
    # pre-creating the auth schema from the ORM models and stamping the
    # alembic_version table to head, so migrate_if_needed sees the DB already at
    # head and SKIPS the upgrade. The store's own pooled engine (used right after
    # for creating the admin user) connects normally.
    eng = create_engine(cfg.database_uri)
    Base.metadata.create_all(eng)
    head = ScriptDirectory.from_config(_get_alembic_config(cfg.database_uri)).get_current_head()
    with eng.begin() as conn:
        conn.execute(text(
            "CREATE TABLE IF NOT EXISTS alembic_version "
            "(version_num VARCHAR(32) NOT NULL, PRIMARY KEY (version_num))"
        ))
        if conn.execute(text("SELECT COUNT(*) FROM alembic_version")).scalar() == 0:
            conn.execute(text("INSERT INTO alembic_version (version_num) VALUES (:v)"), {"v": head})
    eng.dispose()
    print("startup: pre-created auth schema, stamped alembic to %s" % head, flush=True)

    SqlAlchemyStore().init_db(cfg.database_uri)
    print("startup: auth store init_db OK", flush=True)
except Exception:
    print("startup: auth store init FAILED:", flush=True)
    traceback.print_exc()
    sys.stdout.flush()
    sys.exit(1)
PY

exec mlflow server \
    --host 0.0.0.0 \
    --port 5000 \
    --default-artifact-root "${BUCKET}" \
    --backend-store-uri "mysql+pymysql://${DB_USER}:${APP_PW}@${HOST}:${PORT}/${DATABASE}" \
    --app-name basic-auth \
    --workers 1 \
    --gunicorn-opts "--timeout 180 --capture-output"
