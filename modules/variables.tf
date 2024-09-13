variable "customer_gateway_bgp_asn" {
  type        = number
  description = "The Customer Gateway's Border Gateway Protocol (BGP) Autonomous System Number (ASN)"
  default     = 65000
  nullable    = false
}

variable "customer_gateway_ip_address" {
  type        = string
  description = "The IP address of the Customer Gateway's Internet-routable external interface. Set to `null` to not create the Customer Gateway"
  default     = null
}

variable "customer_gateway_certificate_arn" {
  type        = string
  description = "The ARN for the customer gateway certificate."
  default     = null
}

variable "customer_gateway_device_name" {
  type        = string
  description = "A name for the customer gateway device"
  default     = null
}