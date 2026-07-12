FROM python:3.10.12

RUN pip install \
    mlflow==2.6.0 \
    pymysql==1.0.2 \
    boto3 && \
    mkdir /mlflow/

EXPOSE 5000

# The basic-auth store and the tracking store both run Alembic migrations using
# the default "alembic_version" table, so they CANNOT share one database (the
# second store to migrate fails to recognize the other's revision and the worker
# crashes on boot). Give auth its OWN database ("mlflow_auth") on the same RDS
# instance so accounts still persist across Fargate task restarts. We create it
# on startup since RDS only provisions the single initial database.
#
# Then generate the basic-auth config from injected env vars (configparser does
# no env substitution), pointing at that auth DB, and launch the auth-enabled app.
CMD python -c "import os, pymysql; c=pymysql.connect(host=os.environ['HOST'], port=int(os.environ['PORT']), user=os.environ['USERNAME'], password=os.environ['PASSWORD']); c.cursor().execute('CREATE DATABASE IF NOT EXISTS mlflow_auth'); c.commit(); c.close()" && \
    printf '%s\n' \
    '[mlflow]' \
    'default_permission = READ' \
    "database_uri = mysql+pymysql://${USERNAME}:${PASSWORD}@${HOST}:${PORT}/mlflow_auth" \
    "admin_username = ${ADMIN_USERNAME}" \
    "admin_password = ${ADMIN_PASSWORD}" \
    'authorization_function = mlflow.server.auth:authenticate_request_basic_auth' \
    > /mlflow/auth.ini && \
    MLFLOW_AUTH_CONFIG_PATH=/mlflow/auth.ini mlflow server \
    --host 0.0.0.0 \
    --port 5000 \
    --default-artifact-root ${BUCKET} \
    --backend-store-uri mysql+pymysql://${USERNAME}:${PASSWORD}@${HOST}:${PORT}/${DATABASE} \
    --app-name basic-auth \
    --workers 1 \
    --gunicorn-opts "--timeout 180"
