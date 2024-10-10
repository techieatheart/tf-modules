###########
# IAM Roles 
###########

data "aws_iam_policy_document" "dms_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      identifiers = ["dms.amazonaws.com"]
      type        = "Service"
    }
  }
}

# DMS <-> Redshift, S3
resource "aws_iam_role" "dms-access-for-endpoint" {
  assume_role_policy = data.aws_iam_policy_document.dms_assume_role.json
  name               = "dms-access-for-endpoint"
}
# DMS <-> Redshift, S3
resource "aws_iam_role_policy_attachment" "dms-access-for-endpoint-AmazonDMSRedshiftS3Role" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonDMSRedshiftS3Role"
  role       = aws_iam_role.dms-access-for-endpoint.name
}

# DMS <-> Cloudwatch
resource "aws_iam_role" "dms-cloudwatch-logs-role" {
  assume_role_policy = data.aws_iam_policy_document.dms_assume_role.json
  name               = "dms-cloudwatch-logs-role"
}
# DMS <-> Cloudwatch
resource "aws_iam_role_policy_attachment" "dms-cloudwatch-logs-role-AmazonDMSCloudWatchLogsRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonDMSCloudWatchLogsRole"
  role       = aws_iam_role.dms-cloudwatch-logs-role.name
}

# DMS <-> VPC
resource "aws_iam_role" "dms-vpc-role" {
  assume_role_policy = data.aws_iam_policy_document.dms_assume_role.json
  name               = "dms-vpc-role"
}
# DMS <-> VPC
resource "aws_iam_role_policy_attachment" "dms-vpc-role-AmazonDMSVPCManagementRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonDMSVPCManagementRole"
  role       = aws_iam_role.dms-vpc-role.name
}

######################
# Replication instance
######################

resource "aws_dms_replication_instance" "this" {
  allocated_storage            = var.instance_allocated_storage
  allow_major_version_upgrade  = var.instance_allow_major_version_upgrade
  apply_immediately            = var.instance_apply_immediately
  auto_minor_version_upgrade   = var.instance_auto_minor_version_upgrade
  availability_zone            = var.instance_availability_zone
  engine_version               = var.instance_engine_version
  kms_key_arn                  = var.instance_kms_key_arn
  multi_az                     = var.instance_multi_az
  network_type                 = var.instance_network_type
  preferred_maintenance_window = var.instance_preferred_maintenance_window
  publicly_accessible          = var.instance_publicly_accessible
  replication_instance_class   = var.instance_class
  replication_instance_id      = var.instance_id
  replication_subnet_group_id  = var.instance_subnet_group_id
  vpc_security_group_ids       = var.instance_vpc_security_group_ids

  tags = {
    Name = "test"
  }

  depends_on = [
    aws_iam_role_policy_attachment.dms-access-for-endpoint-AmazonDMSRedshiftS3Role,
    aws_iam_role_policy_attachment.dms-cloudwatch-logs-role-AmazonDMSCloudWatchLogsRole,
    aws_iam_role_policy_attachment.dms-vpc-role-AmazonDMSVPCManagementRole
  ]
}


