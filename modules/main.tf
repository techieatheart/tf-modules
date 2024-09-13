# Customer gateway
resource "aws_customer_gateway" "customer_gw" {
  bgp_asn         = var.customer_gateway_bgp_asn
  certificate_arn = var.customer_gateway_certificate_arn
  device_name     = var.customer_gateway_device_name
  ip_address      = var.customer_gateway_ip_address
  type            = "ipsec.1"
  #tags            = module.this.tags
}

# Virtual Private Gateway
resource "aws_vpn_gateway" "vpn_gw" {
  vpc_id            = aws_vpc.main.id
  availability_zone = var.vpn_gateway_availibility_zone
  amazon_side_asn   = var.vpn_gateway_amazon_side_asn

  tags = {
    Name = "main"
  }
}

# VPG Route Propagation
resource "aws_vpn_gateway_route_propagation" "example" {
  vpn_gateway_id = aws_vpn_gateway.vpn_gw.id
  route_table_id = aws_route_table.example.id
}

# VPN connection
resource "aws_vpn_connection" "example" {
  customer_gateway_id = aws_customer_gateway.customer_gw.id
  type                = "ipsec.1"
  transit_gateway_id  = aws_ec2_transit_gateway.example.id
  vpn_gateway_id      = aws_vpn_gateway.vpn_gw
  static_routes_only  = var.vpn_connection_static_routes_only

  enable_acceleration                     = var.vpn_connection.enable_acceleration
  outside_ip_address_type                 = "PrivateIpv4"
  transport_transit_gateway_attachment_id = data.aws_ec2_transit_gateway_dx_gateway_attachment.example.id
  tunnel_inside_ip_version                = var.vpn_connection.tunnel1_inside_ip_version

  local_ipv4_network_cidr  = var.vpn_connection_local_ipv4_network_cidr
  remote_ipv4_network_cidr = var.vpn_connection_remote_ipv4_network_cidr

  tunnel1_dpd_timeout_action = var.vpn_connection_tunnel1_dpd_timeout_action
  tunnel1_ike_versions       = var.vpn_connection_tunnel1_ike_versions
  tunnel1_inside_cidr        = var.vpn_connection_tunnel1_inside_cidr
  tunnel1_preshared_key      = var.vpn_connection_tunnel1_preshared_key
  tunnel1_startup_action     = var.vpn_connection_tunnel1_startup_action

  tunnel1_phase1_dh_group_numbers      = var.vpn_connection_tunnel1_phase1_dh_group_numbers
  tunnel1_phase2_dh_group_numbers      = var.vpn_connection_tunnel1_phase2_dh_group_numbers
  tunnel1_phase1_encryption_algorithms = var.vpn_connection_tunnel1_phase1_encryption_algorithms
  tunnel1_phase2_encryption_algorithms = var.vpn_connection_tunnel1_phase2_encryption_algorithms
  tunnel1_phase1_integrity_algorithms  = var.vpn_connection_tunnel1_phase1_integrity_algorithms
  tunnel1_phase2_integrity_algorithms  = var.vpn_connection_tunnel1_phase2_integrity_algorithms

  tunnel1_log_options {
    cloudwatch_log_options {
      log_enabled       = var.vpn_connection_tunnel1_cloudwatch_log_enabled
      log_group_arn     = var.vpn_connection_tunnel1_cloudwatch_log_enabled ? module.logs.log_group_arn : null
      log_output_format = var.vpn_connection_tunnel1_cloudwatch_log_enabled ? var.vpn_connection_tunnel1_cloudwatch_log_output_format : null
    }
  }

  tunnel2_dpd_timeout_action = var.vpn_connection_tunnel2_dpd_timeout_action
  tunnel2_ike_versions       = var.vpn_connection_tunnel2_ike_versions
  tunnel2_inside_cidr        = var.vpn_connection_tunnel2_inside_cidr
  tunnel2_preshared_key      = var.vpn_connection_tunnel2_preshared_key
  tunnel2_startup_action     = var.vpn_connection_tunnel2_startup_action

  tunnel2_phase1_dh_group_numbers      = var.vpn_connection_tunnel2_phase1_dh_group_numbers
  tunnel2_phase2_dh_group_numbers      = var.vpn_connection_tunnel2_phase2_dh_group_numbers
  tunnel2_phase1_encryption_algorithms = var.vpn_connection_tunnel2_phase1_encryption_algorithms
  tunnel2_phase2_encryption_algorithms = var.vpn_connection_tunnel2_phase2_encryption_algorithms
  tunnel2_phase1_integrity_algorithms  = var.vpn_connection_tunnel2_phase1_integrity_algorithms
  tunnel2_phase2_integrity_algorithms  = var.vpn_connection_tunnel2_phase2_integrity_algorithms

  tunnel2_log_options {
    cloudwatch_log_options {
      log_enabled       = var.vpn_connection_tunnel2_cloudwatch_log_enabled
      log_group_arn     = var.vpn_connection_tunnel2_cloudwatch_log_enabled ? module.logs.log_group_arn : null
      log_output_format = var.vpn_connection_tunnel2_cloudwatch_log_enabled ? var.vpn_connection_tunnel2_cloudwatch_log_output_format : null
    }
  }

  tags = {
    Name = "terraform_ipsec_vpn_example"
  }
}
