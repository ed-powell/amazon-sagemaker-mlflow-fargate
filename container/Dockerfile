FROM python:3.10.12

RUN pip install \
    mlflow==2.6.0 \
    pymysql==1.0.2 \
    boto3 && \
    mkdir /mlflow/

EXPOSE 5000

# Generate the basic-auth config at runtime from injected env vars (configparser
# does no env substitution), then launch the auth-enabled app. The auth tables
# live in the same RDS database as the tracking store so accounts persist across
# Fargate task restarts (the default sqlite auth DB would be lost on every restart).
CMD printf '%s\n' \
    '[mlflow]' \
    'default_permission = READ' \
    "database_uri = mysql+pymysql://${USERNAME}:${PASSWORD}@${HOST}:${PORT}/${DATABASE}" \
    "admin_username = ${ADMIN_USERNAME}" \
    "admin_password = ${ADMIN_PASSWORD}" \
    'authorization_function = mlflow.server.auth:authenticate_request_basic_auth' \
    > /mlflow/auth.ini && \
    MLFLOW_AUTH_CONFIG_PATH=/mlflow/auth.ini mlflow server \
    --host 0.0.0.0 \
    --port 5000 \
    --default-artifact-root ${BUCKET} \
    --backend-store-uri mysql+pymysql://${USERNAME}:${PASSWORD}@${HOST}:${PORT}/${DATABASE} \
    --app-name basic-auth
