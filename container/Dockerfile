FROM python:3.10.12

RUN pip install \
    mlflow==2.6.0 \
    pymysql==1.0.2 \
    cryptography \
    boto3 && \
    mkdir /mlflow/

# Startup script: creates the separate auth database, generates the basic-auth
# config, initializes the auth store (surfacing any error to CloudWatch), then
# launches the auth-enabled MLflow server as a single gunicorn worker.
COPY start.sh /mlflow/start.sh
RUN chmod +x /mlflow/start.sh

EXPOSE 5000

CMD ["/mlflow/start.sh"]
