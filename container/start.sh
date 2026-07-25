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
from sqlalchemy import create_engine, text
pw = os.environ["PASSWORD"]
db = os.environ["DATABASE"]
host = os.environ["HOST"]; port = int(os.environ["PORT"])
conn = pymysql.connect(host=host, port=port, user=os.environ["USERNAME"], password=pw)
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
conn.commit()
cur.execute("SELECT user, host, plugin FROM mysql.user WHERE user='mlflowapp'")
print("DIAG mlflowapp accounts:", cur.fetchall())
print("DIAG password length:", len(pw))
conn.close()

# (A) direct pymysql as mlflowapp, no database
try:
    c = pymysql.connect(host=host, port=port, user="mlflowapp", password=pw); c.close()
    print("DIAG (A) direct pymysql mlflowapp (no db): OK")
except Exception as e:
    print("DIAG (A) direct pymysql mlflowapp (no db) FAILED:", repr(e)[:140])

# (B) direct pymysql as mlflowapp, with database
try:
    c = pymysql.connect(host=host, port=port, user="mlflowapp", password=pw, database="mlflow_auth"); c.close()
    print("DIAG (B) direct pymysql mlflowapp (mlflow_auth): OK")
except Exception as e:
    print("DIAG (B) direct pymysql mlflowapp (mlflow_auth) FAILED:", repr(e)[:140])

# (C) SQLAlchemy as mlflowapp (the failing path)
try:
    e = create_engine(f"mysql+pymysql://mlflowapp:{pw}@{host}:{port}/mlflow_auth")
    with e.connect() as cx: cx.execute(text("SELECT 1"))
    print("DIAG (C) SQLAlchemy mlflowapp: OK")
except Exception as ex:
    print("DIAG (C) SQLAlchemy mlflowapp FAILED:", repr(ex)[:140])
PY

# Connect the stores as the native_password app user, not the master user.
DB_USER=mlflowapp

# MLflow reads auth.ini with configparser, which does %-interpolation on values.
# If the password contains '%' it gets corrupted (yielding a wrong password and
# a 1045 "Access denied"), so escape '%' as '%%' -- configparser turns it back
# into a single '%'. (The tracking store's URI is on the command line below and
# is not read through configparser, so it needs no escaping.)
PW_INI="${PASSWORD//%/%%}"
ADMIN_PW_INI="${ADMIN_PASSWORD//%/%%}"

cat > /mlflow/auth.ini <<EOF
[mlflow]
default_permission = READ
database_uri = mysql+pymysql://${DB_USER}:${PW_INI}@${HOST}:${PORT}/mlflow_auth
admin_username = ${ADMIN_USERNAME}
admin_password = ${ADMIN_PW_INI}
authorization_function = mlflow.server.auth:authenticate_request_basic_auth
EOF
export MLFLOW_AUTH_CONFIG_PATH=/mlflow/auth.ini

# Initialize the auth store up front so any error is visible in CloudWatch
# (gunicorn swallows the worker-boot traceback).
python - <<'PY'
import os, sys, traceback
from sqlalchemy.engine import make_url
from mlflow.server.auth.config import read_auth_config
from mlflow.server.auth.sqlalchemy_store import SqlAlchemyStore
cfg = read_auth_config()
raw = os.environ["PASSWORD"]
parsed = make_url(cfg.database_uri).password
print(f"DIAG configparser pw: env_len={len(raw)} parsed_len={len(parsed)} match={parsed == raw}")
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
