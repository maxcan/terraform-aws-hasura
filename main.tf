# -----------------------------------------------------------------------------
# Service role allowing AWS to manage resources required for ECS
# -----------------------------------------------------------------------------

resource "aws_iam_service_linked_role" "ecs_service" {
  aws_service_name = "ecs.amazonaws.com"
  count            = var.create_iam_service_linked_role ? 1 : 0
}

# -----------------------------------------------------------------------------
# Create the certificate
# -----------------------------------------------------------------------------

resource "aws_acm_certificate" "hasura" {
  domain_name       = "${var.hasura_subdomain}.${var.domain}"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

# -----------------------------------------------------------------------------
# Validate the certificate
# -----------------------------------------------------------------------------

data "aws_route53_zone" "hasura" {
  name = "${var.domain}."
}

resource "aws_route53_record" "hasura_validation" {


  for_each = {
    for dvo in aws_acm_certificate.hasura.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  depends_on = [aws_acm_certificate.hasura]
  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.hasura.zone_id

}

resource "aws_acm_certificate_validation" "hasura" {
  certificate_arn         = aws_acm_certificate.hasura.arn
  validation_record_fqdns = aws_route53_record.hasura_validation.*.fqdn
}

# -----------------------------------------------------------------------------
# Create VPC
# -----------------------------------------------------------------------------

# Fetch AZs in the current region
data "aws_availability_zones" "available" {
}

resource "aws_vpc" "hasura" {
  cidr_block           = "172.17.0.0/16"
  enable_dns_hostnames = var.vpc_enable_dns_hostnames

  tags = {
    Name = "hasura"
  }
}

# Create var.az_count private subnets for RDS, each in a different AZ
resource "aws_subnet" "hasura_private" {
  count             = var.az_count
  cidr_block        = cidrsubnet(aws_vpc.hasura.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  vpc_id            = aws_vpc.hasura.id

  tags = {
    Name = "hasura #${count.index} (private)"
  }
}

# Create var.az_count public subnets for Hasura, each in a different AZ
resource "aws_subnet" "hasura_public" {
  count                   = var.az_count
  cidr_block              = cidrsubnet(aws_vpc.hasura.cidr_block, 8, var.az_count + count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  vpc_id                  = aws_vpc.hasura.id
  map_public_ip_on_launch = true

  tags = {
    Name = "hasura #${var.az_count + count.index} (public)"
  }
}

# IGW for the public subnet
resource "aws_internet_gateway" "hasura" {
  vpc_id = aws_vpc.hasura.id

  tags = {
    Name = "hasura"
  }
}

# Route the public subnet traffic through the IGW
resource "aws_route" "internet_access" {
  route_table_id         = aws_vpc.hasura.main_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.hasura.id
}

# -----------------------------------------------------------------------------
# Create security groups
# -----------------------------------------------------------------------------

# Internet to ALB
resource "aws_security_group" "hasura_alb" {
  name        = "hasura-alb"
  description = "Allow access on port 443 only to ALB"
  vpc_id      = aws_vpc.hasura.id

  ingress {
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ALB TO ECS
resource "aws_security_group" "hasura_ecs" {
  name        = "hasura-tasks"
  description = "allow inbound access from the ALB only"
  vpc_id      = aws_vpc.hasura.id

  ingress {
    protocol        = "tcp"
    from_port       = "8080"
    to_port         = "8080"
    security_groups = [aws_security_group.hasura_alb.id]
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ECS to RDS
resource "aws_security_group" "hasura_rds" {
  name        = "hasura-rds"
  description = "allow inbound access from the hasura tasks only"
  vpc_id      = aws_vpc.hasura.id

  ingress {
    protocol        = "tcp"
    from_port       = "5432"
    to_port         = "5432"
    security_groups = concat([aws_security_group.hasura_ecs.id], var.additional_db_security_groups)
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# -----------------------------------------------------------------------------
# Create RDS
# -----------------------------------------------------------------------------

resource "aws_db_subnet_group" "hasura" {
  name       = var.hasura_unique_identifier
  subnet_ids = aws_subnet.hasura_private.*.id
}

resource "aws_db_instance" "hasura" {
  name                   = var.rds_db_name
  identifier             = var.hasura_unique_identifier
  username               = var.rds_username
  password               = var.rds_password
  port                   = "5432"
  engine                 = "postgres"
  engine_version         = var.rds_version
  instance_class         = var.rds_instance
  allocated_storage      = "10"
  storage_encrypted      = false
  vpc_security_group_ids = [aws_security_group.hasura_rds.id]
  db_subnet_group_name   = aws_db_subnet_group.hasura.name
  parameter_group_name   = var.rds_parameter_group_name
  multi_az               = var.multi_az
  storage_type           = "gp2"
  publicly_accessible    = false

  # snapshot_identifier       = "hasura"
  allow_major_version_upgrade = false
  auto_minor_version_upgrade  = false
  apply_immediately           = true
  maintenance_window          = "sun:02:00-sun:04:00"
  skip_final_snapshot         = false
  copy_tags_to_snapshot       = true
  backup_retention_period     = 7
  backup_window               = "04:00-06:00"
  final_snapshot_identifier   = var.hasura_unique_identifier

  lifecycle {
    prevent_destroy = true
  }
}

# -----------------------------------------------------------------------------
# Create ECS cluster
# -----------------------------------------------------------------------------

resource "aws_ecs_cluster" "hasura" {
  name = var.ecs_cluster_name
}

# -----------------------------------------------------------------------------
# Create logging
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "hasura" {
  name = "/ecs/${replace(var.hasura_subdomain, "/[^-A-Za-z0-9_]/g", "_")}"
}

# -----------------------------------------------------------------------------
# Create IAM for logging
# -----------------------------------------------------------------------------

data "aws_iam_policy_document" "hasura_log_publishing" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:PutLogEventsBatch",
    ]

    resources = ["arn:aws:logs:${var.region}:*:log-group:/ecs/*:*"]
    # resources = ["arn:aws:logs:${var.region}:*:log-group:/ecs/${var.hasura_unique_identifier}:*"]
  }
}

resource "aws_iam_policy" "hasura_log_publishing" {
  name        = "${var.hasura_unique_identifier}-log-pub"
  path        = "/"
  description = "Allow publishing to cloudwach"

  policy = data.aws_iam_policy_document.hasura_log_publishing.json
}

data "aws_iam_policy_document" "hasura_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "hasura_role" {
  name               = "${var.hasura_unique_identifier}-role"
  path               = "/system/"
  assume_role_policy = data.aws_iam_policy_document.hasura_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "hasura_role_log_publishing" {
  role       = aws_iam_role.hasura_role.name
  policy_arn = aws_iam_policy.hasura_log_publishing.arn
}

# -----------------------------------------------------------------------------
# Create a task definition
# -----------------------------------------------------------------------------

locals {
  ecs_environment = [
    {
      name  = "HASURA_GRAPHQL_ADMIN_SECRET",
      value = "${var.hasura_admin_secret}"
    },
    {
      name  = "HASURA_GRAPHQL_DATABASE_URL",
      value = "postgres://${var.rds_username}:${var.rds_password}@${aws_db_instance.hasura.endpoint}/${var.rds_db_name}"
    },
    {
      name  = "HASURA_GRAPHQL_ENABLE_CONSOLE",
      value = "${var.hasura_console_enabled}"
    },
    {
      name  = "HASURA_GRAPHQL_CORS_DOMAIN",
      value = "https://${var.app_subdomain}.${var.domain}:443, https://${var.app_subdomain}.${var.domain}"
    },
    {
      name  = "HASURA_GRAPHQL_PG_CONNECTIONS",
      value = "100"
    },
    {
      name  = "HASURA_GRAPHQL_JWT_SECRET",
      value = "{\"type\":\"${var.hasura_jwt_secret_algo}\", \"key\": \"${var.hasura_jwt_secret_key}\"}"
    }
  ]

  ecs_container_definitions = [
    {
      image       = "hasura/graphql-engine:${var.hasura_version_tag}"
      name        = var.hasura_unique_identifier,
      networkMode = "awsvpc",

      portMappings = [
        {
          containerPort = 8080,
          hostPort      = 8080
        }
      ]

      logConfiguration = {
        logDriver = "awslogs",
        options = {
          awslogs-group         = "${aws_cloudwatch_log_group.hasura.name}",
          awslogs-region        = "${var.region}",
          awslogs-stream-prefix = "ecs"
        }
      }

      environment = flatten([local.ecs_environment, var.environment])
    }
  ]
}

resource "aws_ecs_task_definition" "hasura" {
  family                   = var.hasura_unique_identifier
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.hasura_role.arn

  container_definitions = jsonencode(local.ecs_container_definitions)
}

# -----------------------------------------------------------------------------
# Create the ECS service
# -----------------------------------------------------------------------------

resource "aws_ecs_service" "hasura" {
  depends_on = [
    aws_ecs_task_definition.hasura,
    aws_cloudwatch_log_group.hasura,
    aws_alb_listener.hasura
  ]
  name            = "${var.hasura_unique_identifier}-service"
  cluster         = aws_ecs_cluster.hasura.id
  task_definition = aws_ecs_task_definition.hasura.arn
  desired_count   = var.multi_az == true ? "2" : "1"
  launch_type     = "FARGATE"

  network_configuration {
    assign_public_ip = true
    security_groups  = [aws_security_group.hasura_ecs.id]
    subnets          = aws_subnet.hasura_public.*.id
  }

  load_balancer {
    target_group_arn = aws_alb_target_group.hasura.id
    container_name   = var.hasura_unique_identifier
    container_port   = "8080"
  }
}

# -----------------------------------------------------------------------------
# Create the ALB log bucket
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "hasura" {
  bucket        = "hasura-${var.region}-${var.hasura_unique_identifier}-${var.domain}"
  acl           = "private"
  force_destroy = "true"
}

# -----------------------------------------------------------------------------
# Add IAM policy to allow the ALB to log to it
# -----------------------------------------------------------------------------

data "aws_elb_service_account" "main" {
}

data "aws_iam_policy_document" "hasura" {
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.hasura.arn}/alb/*"]

    principals {
      type        = "AWS"
      identifiers = [data.aws_elb_service_account.main.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "hasura" {
  bucket = aws_s3_bucket.hasura.id
  policy = data.aws_iam_policy_document.hasura.json
}

# -----------------------------------------------------------------------------
# Create the ALB
# -----------------------------------------------------------------------------

resource "aws_alb" "hasura" {
  name            = "${var.hasura_unique_identifier}-alb"
  subnets         = aws_subnet.hasura_public.*.id
  security_groups = [aws_security_group.hasura_alb.id]

  access_logs {
    bucket  = aws_s3_bucket.hasura.id
    prefix  = "alb"
    enabled = true
  }
}

# -----------------------------------------------------------------------------
# Create the ALB target group for ECS
# -----------------------------------------------------------------------------

resource "aws_alb_target_group" "hasura" {
  name        = "${var.hasura_unique_identifier}-alb"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.hasura.id
  target_type = "ip"

  health_check {
    path    = "/healthz"
    matcher = "200"
  }
}

# -----------------------------------------------------------------------------
# Create the ALB listener
# -----------------------------------------------------------------------------

resource "aws_alb_listener" "hasura" {
  load_balancer_arn = aws_alb.hasura.id
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate.hasura.arn

  default_action {
    target_group_arn = aws_alb_target_group.hasura.id
    type             = "forward"
  }
}

# -----------------------------------------------------------------------------
# Create Route 53 record to point to the ALB
# -----------------------------------------------------------------------------

resource "aws_route53_record" "hasura" {
  zone_id = data.aws_route53_zone.hasura.zone_id
  name    = "${var.hasura_subdomain}.${var.domain}"
  type    = "A"

  alias {
    name                   = aws_alb.hasura.dns_name
    zone_id                = aws_alb.hasura.zone_id
    evaluate_target_health = true
  }
}
