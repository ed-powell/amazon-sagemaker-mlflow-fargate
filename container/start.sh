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
cur.execute("SELECT user, host, plugin FROM mysql.user WHERE user='mlflowapp'")
print("DIAG mlflowapp:", cur.fetchall(), "app_pw_len:", len(app_pw))
conn.close()
with open("/mlflow/app_pw", "w") as f:
    f.write(app_pw)
print("startup: ensured mlflow_auth database + mlflowapp (native_password) user")

url = f"mysql+pymysql://mlflowapp:{app_pw}@{os.environ['HOST']}:{os.environ['PORT']}/mlflow_auth"
# (1) direct pymysql as mlflowapp
try:
    c = pymysql.connect(host=os.environ["HOST"], port=int(os.environ["PORT"]),
                        user="mlflowapp", password=app_pw, database="mlflow_auth"); c.close()
    print("DIAG (1) direct pymysql mlflowapp: OK")
except Exception as e:
    print("DIAG (1) direct pymysql mlflowapp FAILED:", repr(e)[:150])
# (2) plain SQLAlchemy create_engine + connect
try:
    from sqlalchemy import create_engine, text
    e = create_engine(url)
    with e.connect() as cx: cx.execute(text("SELECT 1"))
    print("DIAG (2) plain create_engine mlflowapp: OK")
except Exception as ex:
    print("DIAG (2) plain create_engine mlflowapp FAILED:", repr(ex)[:150])
# (3) MLflow's own engine helper (the exact failing path)
try:
    from mlflow.store.db.utils import create_sqlalchemy_engine_with_retry
    create_sqlalchemy_engine_with_retry(url)
    print("DIAG (3) create_sqlalchemy_engine_with_retry mlflowapp: OK")
except Exception as ex:
    print("DIAG (3) create_sqlalchemy_engine_with_retry FAILED:", repr(ex)[:150])
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
from sqlalchemy import engine_from_config
from sqlalchemy.engine import make_url
from mlflow.server.auth.config import read_auth_config
from mlflow.server.auth.sqlalchemy_store import SqlAlchemyStore
from mlflow.server.auth.db.utils import _get_alembic_config
from mlflow.store.db.utils import create_sqlalchemy_engine_with_retry

cfg = read_auth_config()
app_pw = open("/mlflow/app_pw").read()

def pwlen(u):
    try:
        return len(make_url(u).password or "")
    except Exception as e:
        return "parse-err:%r" % e

# Reproduce the exact Alembic path that fails: engine.url -> render_as_string ->
# alembic config -> get_section -> engine_from_config -> connect.
eng = create_sqlalchemy_engine_with_retry(cfg.database_uri)
rendered = eng.url.render_as_string(hide_password=False)
acfg = _get_alembic_config(rendered)
section = acfg.get_section(acfg.config_ini_section, {})
sec_url = section.get("sqlalchemy.url", "<none>")
print("DIAG app_pw_len=%d  rendered_pwlen=%s pct_in_rendered=%s  section_pwlen=%s pct_in_section=%s"
      % (len(app_pw), pwlen(rendered), "%" in rendered, pwlen(sec_url), "%" in sec_url), flush=True)
try:
    e2 = engine_from_config(section, prefix="sqlalchemy.")
    with e2.connect():
        pass
    print("DIAG alembic-style engine_from_config: OK", flush=True)
except Exception as ex:
    print("DIAG alembic-style engine_from_config FAILED: %r" % (ex,), flush=True)

try:
    SqlAlchemyStore().init_db(cfg.database_uri)
    print("startup: auth store init_db OK", flush=True)
except Exception:
    print("startup: auth store init_db FAILED:", flush=True)
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
    --gunicorn-opts "--timeout 180 --capture-output --log-level debug"
