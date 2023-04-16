# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json
import os
from aws_cdk import (
    aws_ec2 as ec2,
    aws_s3 as s3,
    aws_ecs as ecs,
    aws_rds as rds,
    aws_iam as iam,
    aws_secretsmanager as sm,
    aws_ecs_patterns as ecs_patterns,
    aws_certificatemanager as acm,
    aws_elasticloadbalancingv2 as elbv2,
    aws_route53 as route53,
    aws_route53_targets as route53_targets,
    aws_servicediscovery as cloudmap,
    App,
    Stack,
    CfnParameter,
    CfnOutput,
    Aws,
    RemovalPolicy,
    Duration,
    Environment,
    Fn
)
from constructs import Construct

class MLflowStack(Stack):
    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        # ==============================
        # ======= CFN PARAMETERS =======
        # ==============================
        project_name_param = CfnParameter(scope=self, id="ProjectName", type="String")
        db_name = "mlflowdb"
        port = 3306
        username = "master"
        bucket_name = f"{project_name_param.value_as_string}-artifacts-{Aws.ACCOUNT_ID}"
        cluster_name = "mlflow-cluster"
        service_name = "mlflow-service"
        domain_name = os.environ["MLFLOW_DOMAIN_NAME"]
        certificate_arn = os.environ.get("MLFLOW_CERTIFICATE_ARN")
        mlf_username = os.environ["MLFLOW_USERNAME"]
        mlf_password = os.environ["MLFLOW_PASSWORD"]
        UseHttps = False
        BypassEnable = False

        # ==================================================
        # ================= IAM ROLE =======================
        # ==================================================
        role = iam.Role(
            scope=self,
            id="TASKROLE",
            assumed_by=iam.ServicePrincipal(service="ecs-tasks.amazonaws.com"),
        )
        role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3FullAccess")
        )
        role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonECS_FullAccess")
        )
        role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AWSCloudMapFullAccess")
        )

        # ==================================================
        # ================== SECRET ========================
        # ==================================================
        db_password_secret = sm.Secret(
            scope=self,
            id="DBSECRET",
            secret_name="dbPassword",
            generate_secret_string=sm.SecretStringGenerator(
                password_length=20, exclude_punctuation=True
            ),
        )

        # ==================================================
        # ==================== VPC =========================
        # ==================================================
        public_subnet = ec2.SubnetConfiguration(
            name="Public", subnet_type=ec2.SubnetType.PUBLIC, cidr_mask=28
        )
        private_subnet = ec2.SubnetConfiguration(
            name="Private", subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS, cidr_mask=28
        )
        isolated_subnet = ec2.SubnetConfiguration(
            name="DB", subnet_type=ec2.SubnetType.PRIVATE_ISOLATED, cidr_mask=28
        )

        vpc = ec2.Vpc(
            scope=self,
            id="VPC",
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/24"),
            max_azs=2,
            nat_gateway_provider=ec2.NatProvider.gateway(),
            nat_gateways=1,
            subnet_configuration=[public_subnet, private_subnet, isolated_subnet],
        )
        vpc.add_gateway_endpoint(
            "S3Endpoint", service=ec2.GatewayVpcEndpointAwsService.S3
        )
        # ==================================================
        # ================= S3 BUCKET ======================
        # ==================================================
        artifact_bucket = s3.Bucket(
            scope=self,
            id="ARTIFACTBUCKET",
            bucket_name=bucket_name,
            public_read_access=False,
        )
        # # ==================================================
        # # ================== DATABASE  =====================
        # # ==================================================
        # Creates a security group for AWS RDS
        sg_rds = ec2.SecurityGroup(
            scope=self, id="SGRDS", vpc=vpc, security_group_name="sg_rds"
        )
        # Adds an ingress rule which allows resources in the VPC's CIDR to access the database.
        sg_rds.add_ingress_rule(
            peer=ec2.Peer.ipv4("10.0.0.0/24"), connection=ec2.Port.tcp(port)
        )

        database = rds.DatabaseInstance(
            scope=self,
            id="MYSQL",
            database_name=db_name,
            port=port,
            credentials=rds.Credentials.from_username(
                username=username, password=db_password_secret.secret_value
            ),
            engine=rds.DatabaseInstanceEngine.mysql(
                version=rds.MysqlEngineVersion.VER_8_0_26
            ),
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.SMALL
            ),
            vpc=vpc,
            security_groups=[sg_rds],
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
            ),
            # multi_az=True,
            removal_policy=RemovalPolicy.DESTROY,
            deletion_protection=False,
        )

        # ==================================================
        # =============== FARGATE SERVICE ==================
        # ==================================================
        cluster = ecs.Cluster(
            scope=self, id="CLUSTER", cluster_name=cluster_name, vpc=vpc
        )
        cluster.add_default_cloud_map_namespace(
            name="local"
        )

        task_definition = ecs.FargateTaskDefinition(
            scope=self,
            id="MLflowTask",
            task_role=role,
            cpu=4 * 1024,
            memory_limit_mib=8 * 1024,
        )

        container = task_definition.add_container(
            id="MLflowContainer",
            container_name="mlflow-server",
            image=ecs.ContainerImage.from_asset(directory="container"),
            environment={
                "BUCKET": f"s3://{artifact_bucket.bucket_name}",
                "HOST": database.db_instance_endpoint_address,
                "PORT": str(port),
                "DATABASE": db_name,
                "USERNAME": username,
            },
            secrets={"PASSWORD": ecs.Secret.from_secrets_manager(db_password_secret)},
            logging=ecs.LogDriver.aws_logs(stream_prefix="mlflow"),
        )
        port_mapping = ecs.PortMapping(
            container_port=5000, host_port=5000, protocol=ecs.Protocol.TCP
        )
        container.add_port_mappings(port_mapping)

        fargate_service = ecs_patterns.NetworkLoadBalancedFargateService(
            scope=self,
            id="MLFLOW",
            service_name=service_name,
            cluster=cluster,
            task_definition=task_definition,
            listener_port=5000,
            cloud_map_options=ecs.CloudMapOptions(
                dns_record_type=cloudmap.DnsRecordType.A,
                name=service_name
            )
        )

        # Setup security group
        if False:
            fargate_service.service.connections.security_groups[0].add_ingress_rule(
                peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
                connection=ec2.Port.tcp(5000),
                description="Allow inbound from VPC for mlflow",
            )

        # Setup autoscaling policy
        scaling = fargate_service.service.auto_scale_task_count(max_capacity=2)
        scaling.scale_on_cpu_utilization(
            id="AUTOSCALING",
            target_utilization_percent=70,
            scale_in_cooldown=Duration.seconds(60),
            scale_out_cooldown=Duration.seconds(60),
        )

        # ==================================================
        # =============== NGINX FARGATE SERVICE ============
        # ==================================================

        nginx_task_definition = ecs.FargateTaskDefinition(
            scope=self,
            id="NginxTask",
            task_role=role,
            cpu=4 *1024,
            memory_limit_mib=8 * 1024,
        )

        nginx_container = nginx_task_definition.add_container(
            id="NginxContainer",
            image=ecs.ContainerImage.from_asset(directory="proxy",
                                                build_args={"MLF_USERNAME": mlf_username,
                                                            "MLF_PASSWORD": mlf_password}
                                                ),
            logging=ecs.LogDriver.aws_logs(stream_prefix="nginx")
        )
        nginx_container.add_port_mappings(
            ecs.PortMapping(container_port=8080, host_port=8080)
        )

        nginx_service = ecs_patterns.NetworkLoadBalancedFargateService(
            scope=self,
            id="NginxReverseProxy",
            service_name="nginx-proxy",
            cluster=cluster,
            task_definition=nginx_task_definition,
            listener_port=8080,
            cloud_map_options=ecs.CloudMapOptions(
                dns_record_type=cloudmap.DnsRecordType.A,
                name="nginx-proxy"
            )
        )
        nginx_service.service.connections.security_groups[0].add_ingress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(8080),
            description="Allow inbound from VPC for nginx",
        )

        # Setup autoscaling policy
        scaling = nginx_service.service.auto_scale_task_count(max_capacity=2)
        scaling.scale_on_cpu_utilization(
            id="AUTOSCALING",
            target_utilization_percent=70,
            scale_in_cooldown=Duration.seconds(60),
            scale_out_cooldown=Duration.seconds(60),
        )

        # ==================================================
        # ===============  HTTPS Support  ==================
        # ==================================================
        if UseHttps:
            # Create a hosted zone in Route 53 for the domain name
            hosted_zone = route53.PublicHostedZone(self, "MLFlowPublicHostedZone", zone_name=domain_name)

            # Create an A record alias that maps the domain name to the Fargate load balancer's DNS name
            route53.ARecord(self, "AliasRecord",
                        zone=hosted_zone,
                        record_name=f"{domain_name}.",
                        target=route53.RecordTarget.from_alias(
                            alias_target=route53_targets.LoadBalancerTarget(nginx_service.load_balancer)),
                        ttl=Duration.seconds(300))

            # Create a certificate for HTTPS support, or use existing one specified as arn
            if certificate_arn:
                certificate = acm.Certificate.from_certificate_arn(self,
                    "MLFLOW_Certificate",
                    certificate_arn
                )
            else:
                certificate = acm.Certificate(self,
                    "MLFLOW_Certificate",
                    domain_name=domain_name,
                    validation=acm.CertificateValidation.from_dns(hosted_zone)
                )

            # Create a target group for the Fargate service
            target_group = elbv2.ApplicationTargetGroup(
                self,
                "MlfTargetGroup",
                vpc=vpc,
                port=8080,
                targets=[nginx_service.service],
                protocol=elbv2.ApplicationProtocol.HTTP,
                health_check=elbv2.HealthCheck(
                    path="/",
                    protocol=elbv2.Protocol.HTTP
                )
            )

            # Create an HTTPS listener on port 443
            nginx_service.load_balancer.add_listener(
                "MlfHttpsListener",
                port=443,
                protocol=elbv2.ApplicationProtocol.HTTPS,
                certificates=[certificate],
                default_target_groups=[target_group]
            )

            nginx_service.service.connections.security_groups[0].add_ingress_rule(
                peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
                connection=ec2.Port.tcp(443),
                description="Allow inbound from VPC for nginx on https port",
            )

        # ==================================================
        # =================== OUTPUTS ======================
        # ==================================================
        CfnOutput(
            scope=self,
            id="LoadBalancerDNS",
            value=fargate_service.load_balancer.load_balancer_dns_name,
        )
        CfnOutput(
            scope=self,
            id="NginxReverseProxyDNS",
            value=nginx_service.load_balancer.load_balancer_dns_name,
        )
        if UseHttps:
            CfnOutput(
                scope=self,
                id="LoadBalancerNameServers",
                value=Fn.select(0, hosted_zone.hosted_zone_name_servers),
                description=f"NameServers used for {domain_name}"
            )

app = App()
MLflowStack(app, "MLflowStack", env=Environment(
    account=os.environ["CDK_DEFAULT_ACCOUNT"],
    region=os.environ["CDK_DEFAULT_REGION"]))
app.synth()

