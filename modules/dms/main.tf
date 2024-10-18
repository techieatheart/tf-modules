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

##########################
# Replication Subnet group
##########################

locals {
  replication_subnet_group = var.create_repl_subnet_group ? { "replication_subnet_group" = lower(var.repl_subnet_group_name) } : {}
}

resource "aws_dms_replication_subnet_group" "this" {
  for_each = local.replication_subnet_group

  replication_subnet_group_id          = each.value
  replication_subnet_group_description = var.repl_subnet_group_description
  subnet_ids                           = var.repl_subnet_group_subnet_ids

  tags = merge(var.tags, var.repl_subnet_group_tags)

  depends_on = [time_sleep.wait_for_dependency_resources]
}


###########
# Endpoints
###########

# Fetch the password from SSM Parameter Store
data "aws_ssm_parameter" "db_password" {
  name = "/path/to/your/parameter"  # Update this with the correct path to your SSM parameter
  with_decryption = true  # Set to true if the parameter is encrypted
}

resource "aws_dms_endpoint" "this" {
  for_each = { for k, v in var.endpoints : k => v if var.create }

  certificate_arn             = try(aws_dms_certificate.this[each.value.certificate_key].certificate_arn, null)
  database_name               = lookup(each.value, "database_name", null)
  endpoint_id                 = each.value.endpoint_id
  endpoint_type               = each.value.endpoint_type
  engine_name                 = each.value.engine_name
  extra_connection_attributes = try(each.value.extra_connection_attributes, null)
  kms_key_arn                 = lookup(each.value, "kms_key_arn", null)
  password                    = data.aws_ssm_parameter.db_password.value  # Check with each
  port                        = try(each.value.port, null)
  
  secrets_manager_access_role_arn = lookup(each.value, "secrets_manager_arn", null) != null ? lookup(each.value, "secrets_manager_access_role_arn", local.access_iam_role) : null
  secrets_manager_arn             = lookup(each.value, "secrets_manager_arn", null)
  server_name                     = lookup(each.value, "server_name", null)
  service_access_role             = lookup(each.value, "service_access_role", local.access_iam_role)
  ssl_mode                        = try(each.value.ssl_mode, null)
  username                        = try(each.value.username, null)

 
 dynamic "postgres_settings" {
    for_each = length(lookup(each.value, "postgres_settings", [])) > 0 ? [each.value.postgres_settings] : []
    content {
      after_connect_script         = try(postgres_settings.value.after_connect_script, null)
      babelfish_database_name      = try(postgres_settings.value.babelfish_database_name, null)
      capture_ddls                 = try(postgres_settings.value.capture_ddls, null)
      database_mode                = try(postgres_settings.value.database_mode, null)
      ddl_artifacts_schema         = try(postgres_settings.value.ddl_artifacts_schema, null)
      execute_timeout              = try(postgres_settings.value.execute_timeout, null)
      fail_tasks_on_lob_truncation = try(postgres_settings.value.fail_tasks_on_lob_truncation, null)
      heartbeat_enable             = try(postgres_settings.value.heartbeat_enable, null)
      heartbeat_frequency          = try(postgres_settings.value.heartbeat_frequency, null)
      heartbeat_schema             = try(postgres_settings.value.heartbeat_schema, null)
      map_boolean_as_boolean       = try(postgres_settings.value.map_boolean_as_boolean, null)
      map_jsonb_as_clob            = try(postgres_settings.value.map_jsonb_as_clob, null)
      map_long_varchar_as          = try(postgres_settings.value.map_long_varchar_as, null)
      max_file_size                = try(postgres_settings.value.max_file_size, null)
      plugin_name                  = try(postgres_settings.value.plugin_name, null)
      slot_name                    = try(postgres_settings.value.slot_name, null)
    }
  }

  dynamic "elasticsearch_settings" {
    for_each = length(lookup(each.value, "elasticsearch_settings", [])) > 0 ? [each.value.elasticsearch_settings] : []

    content {
      endpoint_uri               = elasticsearch_settings.value.endpoint_uri
      error_retry_duration       = try(elasticsearch_settings.value.error_retry_duration, null)
      full_load_error_percentage = try(elasticsearch_settings.value.full_load_error_percentage, null)
      service_access_role_arn    = lookup(elasticsearch_settings.value, "service_access_role_arn", aws_iam_role.access[0].arn)
      use_new_mapping_type       = try(elasticsearch_settings.value.use_new_mapping_type, null)
    }
  }

  dynamic "kafka_settings" {
    for_each = length(lookup(each.value, "kafka_settings", [])) > 0 ? [each.value.kafka_settings] : []

    content {
      broker                         = kafka_settings.value.broker
      include_control_details        = try(kafka_settings.value.include_control_details, null)
      include_null_and_empty         = try(kafka_settings.value.include_null_and_empty, null)
      include_partition_value        = try(kafka_settings.value.include_partition_value, null)
      include_table_alter_operations = try(kafka_settings.value.include_table_alter_operations, null)
      include_transaction_details    = try(kafka_settings.value.include_transaction_details, null)
      message_format                 = try(kafka_settings.value.message_format, null)
      message_max_bytes              = try(kafka_settings.value.message_max_bytes, null)
      no_hex_prefix                  = try(kafka_settings.value.no_hex_prefix, null)
      partition_include_schema_table = try(kafka_settings.value.partition_include_schema_table, null)
      sasl_password                  = lookup(kafka_settings.value, "sasl_password", null)
      sasl_username                  = lookup(kafka_settings.value, "sasl_username", null)
      security_protocol              = try(kafka_settings.value.security_protocol, null)
      ssl_ca_certificate_arn         = lookup(kafka_settings.value, "ssl_ca_certificate_arn", null)
      ssl_client_certificate_arn     = lookup(kafka_settings.value, "ssl_client_certificate_arn", null)
      ssl_client_key_arn             = lookup(kafka_settings.value, "ssl_client_key_arn", null)
      ssl_client_key_password        = lookup(kafka_settings.value, "ssl_client_key_password", null)
      topic                          = try(kafka_settings.value.topic, null)
    }
  }

  dynamic "kinesis_settings" {
    for_each = length(lookup(each.value, "kinesis_settings", [])) > 0 ? [each.value.kinesis_settings] : []

    content {
      include_control_details        = try(kinesis_settings.value.include_control_details, null)
      include_null_and_empty         = try(kinesis_settings.value.include_null_and_empty, null)
      include_partition_value        = try(kinesis_settings.value.include_partition_value, null)
      include_table_alter_operations = try(kinesis_settings.value.include_table_alter_operations, null)
      include_transaction_details    = try(kinesis_settings.value.include_transaction_details, null)
      message_format                 = try(kinesis_settings.value.message_format, null)
      partition_include_schema_table = try(kinesis_settings.value.partition_include_schema_table, null)
      service_access_role_arn        = lookup(kinesis_settings.value, "service_access_role_arn", local.access_iam_role)
      stream_arn                     = lookup(kinesis_settings.value, "stream_arn", null)
    }
  }

  dynamic "mongodb_settings" {
    for_each = length(lookup(each.value, "mongodb_settings", [])) > 0 ? [each.value.mongodb_settings] : []

    content {
      auth_mechanism      = try(mongodb_settings.value.auth_mechanism, null)
      auth_source         = try(mongodb_settings.value.auth_source, null)
      auth_type           = try(mongodb_settings.value.auth_type, null)
      docs_to_investigate = try(mongodb_settings.value.docs_to_investigate, null)
      extract_doc_id      = try(mongodb_settings.value.extract_doc_id, null)
      nesting_level       = try(mongodb_settings.value.nesting_level, null)
    }
  }

  dynamic "redis_settings" {
    for_each = length(lookup(each.value, "redis_settings", [])) > 0 ? [each.value.redis_settings] : []

    content {
      auth_password          = try(redis_settings.value.auth_password, null)
      auth_type              = redis_settings.value.auth_type
      auth_user_name         = try(redis_settings.value.auth_user_name, null)
      port                   = try(redis_settings.value.port, 6379)
      server_name            = redis_settings.value.server_name
      ssl_ca_certificate_arn = lookup(redis_settings.value, "ssl_ca_certificate_arn", null)
      ssl_security_protocol  = try(redis_settings.value.ssl_security_protocol, null)
    }
  }

  dynamic "redshift_settings" {
    for_each = length(lookup(each.value, "redshift_settings", [])) > 0 ? [each.value.redshift_settings] : []

    content {
      bucket_folder                     = try(redshift_settings.value.bucket_folder, null)
      bucket_name                       = lookup(redshift_settings.value, "bucket_name", null)
      encryption_mode                   = try(redshift_settings.value.encryption_mode, null)
      server_side_encryption_kms_key_id = lookup(redshift_settings.value, "server_side_encryption_kms_key_id", null)
      service_access_role_arn           = lookup(redshift_settings.value, "service_access_role_arn", "arn:${local.partition}:iam::${local.account_id}:role/dms-access-for-endpoint")
    }
  }
}

##############
# S3 Endpoint
##############

resource "aws_dms_s3_endpoint" "this" {
  for_each = { for k, v in var.s3_endpoints : k => v if var.create }

  # https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.S3.html
  # https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Target.S3.html
  certificate_arn = try(aws_dms_certificate.this[each.value.certificate_key].certificate_arn, null)
  endpoint_id     = each.value.endpoint_id
  endpoint_type   = each.value.endpoint_type
  kms_key_arn     = lookup(each.value, "kms_key_arn", null)
  ssl_mode        = try(each.value.ssl_mode, null)

  add_column_name                             = try(each.value.add_column_name, null)
  add_trailing_padding_character              = try(each.value.add_trailing_padding_character, null)
  bucket_folder                               = try(each.value.bucket_folder, null)
  bucket_name                                 = each.value.bucket_name
  canned_acl_for_objects                      = try(each.value.canned_acl_for_objects, null)
  cdc_inserts_and_updates                     = try(each.value.cdc_inserts_and_updates, null)
  cdc_inserts_only                            = try(each.value.cdc_inserts_only, null)
  cdc_max_batch_interval                      = try(each.value.cdc_max_batch_interval, null)
  cdc_min_file_size                           = try(each.value.cdc_min_file_size, null)
  cdc_path                                    = try(each.value.cdc_path, null)
  compression_type                            = try(each.value.compression_type, null)
  csv_delimiter                               = try(each.value.csv_delimiter, null)
  csv_no_sup_value                            = try(each.value.csv_no_sup_value, null)
  csv_null_value                              = try(each.value.csv_null_value, null)
  csv_row_delimiter                           = try(each.value.csv_row_delimiter, null)
  data_format                                 = try(each.value.data_format, null)
  data_page_size                              = try(each.value.data_page_size, null)
  date_partition_delimiter                    = try(each.value.date_partition_delimiter, null)
  date_partition_enabled                      = try(each.value.date_partition_enabled, null)
  date_partition_sequence                     = try(each.value.date_partition_sequence, null)
  date_partition_timezone                     = try(each.value.date_partition_timezone, null)
  detach_target_on_lob_lookup_failure_parquet = try(each.value.detach_target_on_lob_lookup_failure_parquet, null)
  dict_page_size_limit                        = try(each.value.dict_page_size_limit, null)
  enable_statistics                           = try(each.value.enable_statistics, null)
  encoding_type                               = try(each.value.encoding_type, null)
  encryption_mode                             = try(each.value.encryption_mode, null)
  expected_bucket_owner                       = try(each.value.expected_bucket_owner, null)
  external_table_definition                   = try(each.value.external_table_definition, null)
  glue_catalog_generation                     = try(each.value.glue_catalog_generation, null)
  ignore_header_rows                          = try(each.value.ignore_header_rows, null)
  include_op_for_full_load                    = try(each.value.include_op_for_full_load, null)
  max_file_size                               = try(each.value.max_file_size, null)
  parquet_timestamp_in_millisecond            = try(each.value.parquet_timestamp_in_millisecond, null)
  parquet_version                             = try(each.value.parquet_version, null)
  preserve_transactions                       = try(each.value.preserve_transactions, null)
  rfc_4180                                    = try(each.value.rfc_4180, null)
  row_group_length                            = try(each.value.row_group_length, null)
  server_side_encryption_kms_key_id           = lookup(each.value, "server_side_encryption_kms_key_id", null)
  service_access_role_arn                     = lookup(each.value, "service_access_role_arn", local.access_iam_role)
  timestamp_column_name                       = try(each.value.timestamp_column_name, null)
  use_csv_no_sup_value                        = try(each.value.use_csv_no_sup_value, null)
  use_task_start_time_for_full_load_timestamp = try(each.value.use_task_start_time_for_full_load_timestamp, null)

  tags = merge(var.tags, try(each.value.tags, {}))
}

##############################
# Replication Task - Instance
##############################

resource "aws_dms_replication_task" "this" {
  for_each = { for k, v in var.replication_tasks : k => v if !contains(keys(v), "serverless_config") }

  cdc_start_position        = try(each.value.cdc_start_position, null)
  cdc_start_time            = try(each.value.cdc_start_time, null)
  migration_type            = each.value.migration_type
  replication_instance_arn  = aws_dms_replication_instance.this[0].replication_instance_arn
  replication_task_id       = each.value.replication_task_id
  replication_task_settings = try(each.value.replication_task_settings, null)
  source_endpoint_arn       = try(each.value.source_endpoint_arn, aws_dms_endpoint.this[each.value.source_endpoint_key].endpoint_arn, aws_dms_s3_endpoint.this[each.value.source_endpoint_key].endpoint_arn)
  start_replication_task    = try(each.value.start_replication_task, null)
  table_mappings            = try(each.value.table_mappings, null)
  target_endpoint_arn       = try(each.value.target_endpoint_arn, aws_dms_endpoint.this[each.value.target_endpoint_key].endpoint_arn, aws_dms_s3_endpoint.this[each.value.target_endpoint_key].endpoint_arn)

  tags = merge(var.tags, try(each.value.tags, {}))
}

################################
# Replication Task - Serverless
################################
resource "aws_dms_replication_config" "this" {
  for_each = { for k, v in var.replication_tasks : k => v if contains(keys(v), "serverless_config") }

  replication_config_identifier = each.value.replication_task_id
  resource_identifier           = each.value.replication_task_id

  replication_type    = each.value.migration_type
  source_endpoint_arn = try(each.value.source_endpoint_arn, aws_dms_endpoint.this[each.value.source_endpoint_key].endpoint_arn, aws_dms_s3_endpoint.this[each.value.source_endpoint_key].endpoint_arn)
  target_endpoint_arn = try(each.value.target_endpoint_arn, aws_dms_endpoint.this[each.value.target_endpoint_key].endpoint_arn, aws_dms_s3_endpoint.this[each.value.target_endpoint_key].endpoint_arn)
  table_mappings      = try(each.value.table_mappings, null)

  replication_settings  = try(each.value.replication_task_settings, null)
  supplemental_settings = try(each.value.supplemental_task_settings, null)

  start_replication = try(each.value.start_replication_task, null)

  compute_config {
    availability_zone            = try(each.value.serverless_config.availability_zone, null)
    dns_name_servers             = try(each.value.serverless_config.dns_name_servers, null)
    kms_key_id                   = try(each.value.serverless_config.kms_key_id, null)
    max_capacity_units           = each.value.serverless_config.max_capacity_units
    min_capacity_units           = try(each.value.serverless_config.min_capacity_units, null)
    multi_az                     = try(each.value.serverless_config.multi_az, null)
    preferred_maintenance_window = try(each.value.serverless_config.preferred_maintenance_window, null)
    replication_subnet_group_id  = aws_dms_replication_subnet_group.this.id
    vpc_security_group_ids       = try(each.value.serverless_config.vpc_security_group_ids, null)
  }

  tags = merge(var.tags, try(each.value.tags, {}))
}


######################
# Event Subscription
######################

resource "aws_dms_event_subscription" "this" {
  for_each = { for k, v in var.event_subscriptions : k => v}

  enabled          = try(each.value.enabled, null)
  event_categories = try(each.value.event_categories, null)
  name             = each.value.name
  sns_topic_arn    = each.value.sns_topic_arn

  source_ids = compact(concat(
    [
      for instance in aws_dms_replication_instance.this[*] :
      instance.replication_instance_id if lookup(each.value, "instance_event_subscription_keys", null) == var.instance_id
    ],
    [
      for task in aws_dms_replication_task.this[*] :
      task.replication_task_id if contains(lookup(each.value, "task_event_subscription_keys", []), each.key)
    ]
  ))

  source_type = try(each.value.source_type, null)

  tags = merge(var.tags, try(each.value.tags, {}))

  timeouts {
    create = try(var.event_subscription_timeouts.create, null)
    update = try(var.event_subscription_timeouts.update, null)
    delete = try(var.event_subscription_timeouts.delete, null)
  }
}

##############
# Certificate
##############

resource "aws_dms_certificate" "this" {
  for_each = { for k, v in var.certificates : k => v}

  certificate_id     = each.value.certificate_id
  certificate_pem    = lookup(each.value, "certificate_pem", null)
  certificate_wallet = lookup(each.value, "certificate_wallet", null)

  tags = merge(var.tags, try(each.value.tags, {}))
}