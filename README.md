## Manage your machine learning lifecycle with MLflow and Amazon SageMaker

**Note:** SageMaker now supports a fully managed MLflow. We recommend you follow this [blog post for the latest](https://aws.amazon.com/blogs/machine-learning/accelerating-generative-ai-development-with-fully-managed-mlflow-3-0-on-amazon-sagemaker-ai/).

### Overview

In this repository we show how to deploy MLflow on AWS Fargate and how to use it during your ML project
with [Amazon SageMaker](https://aws.amazon.com/sagemaker). You will use Amazon SageMaker to develop, train, tune and
deploy a Scikit-Learn based ML model (Random Forest) and track experiment runs and models with MLflow.

This implementation shows how to do the following:

* Host a serverless MLflow server on AWS Fargate with S3 as artifact store and RDS and backend stores
* Track experiment runs running on SageMaker with MLflow
* Register models trained in SageMaker in the MLflow model registry
* Deploy an MLflow model into a SageMaker endpoint

### MLflow tracking server
You can set a central MLflow tracking server during your ML project. By using this remote MLflow server, data scientists
will be able to manage experiments and models in a collaborative manner.
An MLflow tracking server also has two components for storage: a ```backend store``` and an ```artifact store```. This
implementation uses an Amazon S3 bucket as artifact store and an Amazon RDS instance for MySQL as backend store.

![](media/architecture-mlflow.png)

### Architecture

The CDK stack in [app.py](app.py) provisions the following resources:

* **VPC** (`10.0.0.0/24`, 2 AZs) with public, private-with-egress, and isolated subnets, plus a free S3 gateway endpoint.
* **NAT instance** (`t3.nano`) providing outbound internet access for the private subnet (e.g. ECR image pulls) — a low-cost
  replacement for a managed NAT gateway.
* **Amazon S3 bucket** — the MLflow artifact store.
* **Amazon RDS for MySQL** (`t3.micro`, single-AZ, 20 GB) — the MLflow backend store *and* the basic-auth user/permission store.
* **Amazon ECS on AWS Fargate** — one task (0.25 vCPU / 1 GB) running the MLflow server container, fronted by a
  **Network Load Balancer**. The container image is stored in **Amazon ECR**.
* **AWS Secrets Manager** — holds the auto-generated database password (also reused as the initial admin password).
* **CloudWatch Logs** — container logs under the `mlflow` stream prefix.

The MLflow server runs with `--app-name basic-auth`, so the Network Load Balancer endpoint requires a username and password
(see [Enabling native user authentication](#enabling-native-user-authentication)).

### Prerequisites

We will use [the AWS CDK](https://cdkworkshop.com/) to deploy the MLflow server.

To go through this example, make sure you have the following:
* An AWS account where the service will be deployed
* [AWS CDK installed and configured](https://docs.aws.amazon.com/cdk/latest/guide/getting_started.html). Make sure to have the credentials and permissions to deploy the stack into your account
* **Node.js 22 or newer** — the CDK CLI used here (`aws-cdk-lib==2.150.0`) requires Node `^22.0.0`. Node 20 reached end-of-life on 2026-04-30 and the CLI will refuse to run on it.
* [Docker](https://www.docker.com) to build and push the MLflow container image to ECR
* This [Github repository](https://github.com/aws-samples/amazon-sagemaker-mlflow-fargate) cloned into your environment to follow the steps

### Deploying the stack

You can view the CDK stack details in [app.py](https://github.com/aws-samples/amazon-sagemaker-mlflow-fargate/blob/main/app.py).
Execute the following commands to install CDK and make sure you have the right dependencies:

```
npm install -g aws-cdk@2.150.0
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
```

> **Important — install into the venv.** `cdk synth`/`cdk deploy` run `python3 app.py`, so `aws-cdk-lib` must be installed in the *same* interpreter the `cdk` CLI invokes. Keep the `.venv` activated when running CDK, and prefer `python3 -m pip install -r requirements.txt` over a bare `pip3` to avoid installing into a different Python (a common cause of `ModuleNotFoundError: No module named 'aws_cdk'`).

Once this is installed, you can execute the following commands to deploy the inference service into your account:

```
ACCOUNT_ID=$(aws sts get-caller-identity --query Account | tr -d '"')
AWS_REGION=$(aws configure get region)
cdk bootstrap aws://${ACCOUNT_ID}/${AWS_REGION}
cdk deploy --parameters ProjectName=mlflow --require-approval never
```

The first 2 commands will get your account ID and current AWS region using the AWS CLI on your computer. ```cdk
bootstrap``` and ```cdk deploy``` will build the container image locally, push it to ECR, and deploy the stack. 

The stack will take a few minutes to launch the MLflow server on AWS Fargate, with an S3 bucket and a MySQL database on
RDS. You can then use the load balancer URI present in the stack outputs to access the MLflow UI over plain
HTTP on port 80 (i.e. `http://<load balancer URI>`):
![](media/load-balancer.png)
![](media/mlflow-interface.png)

**N.B:** In this illustrative example stack, the load balancer is launched on a public subnet and is internet facing.
For security purposes, you may want to provision an internal load balancer in your VPC private subnets where there is no
direct connectivity from the outside world. Here is a blog post explaining how to achieve
this: [Access Private applications on AWS Fargate using Amazon API Gateway PrivateLink](https://aws.amazon.com/blogs/compute/access-private-applications-on-aws-fargate-using-amazon-api-gateway-privatelink/)

### Minimal-cost resource sizing

This stack has been tuned down from the original sample to run an MLflow server at the lowest practical cost,
following Amazon's recommended minimal Fargate sizing (CPU `256` / `1024 MiB`). The changes in `app.py` are:

| Resource | Original | Minimal | Notes |
|---|---|---|---|
| Fargate task | 4 vCPU / 8 GB | **`cpu=256` (0.25 vCPU) / `1024 MiB`** | Amazon recommended minimal size. In Fargate `256` CPU units = 0.25 vCPU. Bump `memory_limit_mib` to `2048` if you see OOM kills under heavy artifact logging. |
| RDS instance | `m5.large` | **`t3.micro`** (`BURSTABLE3`/`MICRO`) + `allocated_storage=20` | The MLflow metadata DB is tiny; a burstable instance is ample. |
| NAT | managed NAT gateway (~$32/mo) | **NAT instance** `t3.nano` via `NatProvider.instance_v2()` (~$4/mo) | Requires `aws-cdk-lib>=2.123.0`; this stack pins `2.150.0`. You are responsible for patching the NAT instance, and it is single-AZ. |
| Autoscaling | `max_capacity=2` | **`max_capacity=1`** | Single task keeps cost predictable. |

For heavier or production workloads, scale these values back up.

#### Monthly cost estimate

The table below estimates the steady-state monthly cost of the resources this stack provisions, assuming the service runs
24/7 in **us-east-1** at **on-demand** pricing with **light usage**. Prices are approximate (as of early 2026), vary by
region, and change over time — use the [AWS Pricing Calculator](https://calculator.aws/) for an authoritative figure.

| Resource | Configuration | Est. monthly cost |
|---|---|---|
| AWS Fargate | 1 task, 0.25 vCPU + 1 GB, 730 hrs | ~$11 |
| Amazon RDS (MySQL) | `db.t3.micro`, single-AZ + 20 GB gp2 storage | ~$15 |
| Network Load Balancer | 1 NLB (base + light LCU usage) | ~$18 |
| NAT instance | `t3.nano` + 8 GB EBS | ~$5 |
| Public IPv4 addresses | NAT instance + NLB (AWS charges $0.005/hr each) | ~$4–8 |
| AWS Secrets Manager | 1 secret (`dbPassword`) | ~$0.40 |
| CloudWatch Logs | container logs, light volume | ~$1 |
| Amazon ECR | container image storage (~1–2 GB) | ~$0.20 |
| Amazon S3 | artifact store (usage-based) | ~$1+ |
| **Total** | | **~$55/mo** |

Notes and exclusions:
* **Data transfer** is not included and is usage-dependent (NAT instance egress, NLB/internet traffic, cross-AZ traffic).
* **S3** cost grows with the size of logged artifacts and models.
* The **NLB is the single largest fixed item**; if you only need access from inside the VPC you could remove it and reach
  the Fargate task directly to save ~$18/mo.
* Costs scale roughly linearly if you raise `max_capacity` (more Fargate tasks), enable RDS Multi-AZ, or increase the task size.
* This is down from roughly **~$300/mo** for the original sample (4 vCPU / 8 GB Fargate, `m5.large` RDS, managed NAT gateway).

### Enabling native user authentication

This stack enables MLflow's built-in [basic authentication](https://mlflow.org/docs/latest/auth/index.html) so the server
requires a username and password. It is turned on by launching the server with `--app-name basic-auth` (see the
[container Dockerfile](container/Dockerfile)).

**How it is configured:**
* The Dockerfile generates an auth config file at container start from injected environment variables and points MLflow at it
  via `MLFLOW_AUTH_CONFIG_PATH`.
* The auth tables (`users`, `experiment_permissions`, `registered_model_permissions`) are stored in the **same RDS database**
  as the tracking backend, so accounts and permissions persist across Fargate task restarts. (The MLflow default of a local
  SQLite auth DB would be lost on every restart.)
* An admin account is created automatically on first start. The username is `admin` (set via `ADMIN_USERNAME` in `app.py`) and
  the **initial admin password reuses the auto-generated `dbPassword` secret** in AWS Secrets Manager.

**After deploying:**

1. Retrieve the initial admin password:
   ```
   aws secretsmanager get-secret-value --secret-id dbPassword --query SecretString --output text
   ```
2. Open the load balancer URL, log in as `admin` with that password, and **change it immediately**
   (user menu in the UI, or the `/api/2.0/mlflow/users/update-password` endpoint).
3. Add additional users with the Python client:
   ```python
   import os
   from mlflow.server import get_app_client

   os.environ["MLFLOW_TRACKING_USERNAME"] = "admin"
   os.environ["MLFLOW_TRACKING_PASSWORD"] = "<admin password>"
   client = get_app_client("basic-auth", tracking_uri="http://<YOUR LOAD BALANCER URI>")
   client.create_user(username="alice", password="<password>")
   ```
   You can also use the `/signup` page in the UI or the REST endpoints under `/api/2.0/mlflow/users/...`.
4. Every tracking client (notebooks, CI, SageMaker) must now send credentials:
   ```
   export MLFLOW_TRACKING_URI=http://<YOUR LOAD BALANCER URI>
   export MLFLOW_TRACKING_USERNAME=alice
   export MLFLOW_TRACKING_PASSWORD=<password>
   ```

**Security notes:**
* Basic-auth credentials are only base64-encoded. The Network Load Balancer in this stack terminates **plain HTTP**, so logins
  travel unencrypted. For anything beyond a private VPC/dev setup, add TLS (an ACM certificate on the load balancer, or front the
  service with an ALB/CloudFront).
* `default_permission` is set to `READ` in the Dockerfile's auth config — any authenticated user can read all experiments.
  Change it to `NO_PERMISSIONS` if you want users isolated by default.

### Managing an ML lifecycle with Amazon SageMaker and MLflow

You now have a remote MLflow tracking server running accessible through
a [REST API](https://mlflow.org/docs/latest/rest-api.html#rest-api) via
the [load balancer uri](https://mlflow.org/docs/latest/quickstart.html#quickstart-logging-to-remote-server). 
You can use the MLflow Tracking API to log parameters, metrics, and models when running your machine learning project with Amazon
SageMaker. For this you will need install the MLflow library when running your code on Amazon SageMaker and set the
remote tracking uri to be your load balancer address.

The following python API command allows you to point your code executing on SageMaker to your MLflow remote server:

```
import mlflow
mlflow.set_tracking_uri('<YOUR LOAD BALANCER URI>')
```

Connect to your notebook instance and set the remote tracking URI.
![](media/architecture-experiments.png)

### Running an example lab

This describes how to develop, train, tune and deploy a Random Forest model using Scikit-learn with
the [SageMaker Python SDK](https://sagemaker.readthedocs.io/en/stable/frameworks/sklearn/using_sklearn.html). We use
the [Boston Housing dataset](https://scikit-learn.org/stable/datasets/index.html#boston-dataset), present
in [Scikit-Learn](https://scikit-learn.org/stable/index.html.), and log our machine learning runs into MLflow. You can
find the original lab in
the [SageMaker Examples](https://github.com/aws/amazon-sagemaker-examples/tree/fb04396d2e7ceeb135b0b0a516e54c97922ca0d8/sagemaker-python-sdk/scikit_learn_randomforest)
repository for more details on using custom Scikit-learn scipts with Amazon SageMaker.

Follow the step-by-step guide by executing the notebooks in the following folders:

* lab/1_track_experiments.ipynb
* lab/2_track_experiments_hpo.ipynb
* lab/3_deploy_model.ipynb

### User access control

This stack enables MLflow's built-in basic authentication and per-user permissions (see
[Enabling native user authentication](#enabling-native-user-authentication) above), so users must log in and an admin can
grant or restrict access to individual experiments and registered models. Note that this feature is marked experimental by
MLflow and provides authentication/authorization only — for stronger model governance or audit requirements you may still
want additional controls. Earlier releases of this sample noted that open-source MLflow had no access control; that gap is
addressed here via the `basic-auth` app introduced in MLflow 2.5.

### Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

### License

This library is licensed under the MIT-0 License. See the LICENSE file.

