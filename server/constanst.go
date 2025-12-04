package server

// SOCKS5H_VERSION - SOCKS5H Version
const SOCKS5H_VERSION = 0x05

// RSV - Reserved
const RSV = 0x00

// Method Constants
const (
	// NO_AUTHENTICATION_REQUIRED_method - X'00' NO AUTHENTICATION REQUIRED
	NO_AUTHENTICATION_REQUIRED_method = 0x00

	// GSSAPI_method - X'01' GSSAPI
	GSSAPI_method = 0x01

	// USERNAME_PASSWORD_method - X'02' USERNAME/PASSWORD
	USERNAME_PASSWORD_method = 0x02

	// NO_AUTHENTICATION_REQUIRED_method - X'FF' NO ACCEPTABLE METHODS
	NO_ACCEPTABLE_METHODS_method = 0xFF

	// X'03' to X'7F' IANA ASSIGNED
	// X'80' to X'FE' RESERVED FOR PRIVATE METHODS
)

// Command Constants
const (
	// CONNECT_cmd - CONNECT X'01'
	CONNECT_cmd = 0x01

	// BIND_cmd - BIND X'02'
	BIND_cmd = 0x02

	// UDP_ASSOCIATE_cmd - UDP ASSOCIATE X'03'
	UDP_ASSOCIATE_cmd = 0x03
)

// ATYP - Address type
const (
	// IP_V4_addr - IP V4 address: X'01'
	IP_V4_addr = 0x01

	// DOMAINNAME_addr - DOMAINNAME: X'03'
	DOMAINNAME_addr = 0x03

	// IP_V6_addr - IP V6 address: X'04'
	IP_V6_addr = 0x04
)

// Connection Replies
const (
	// X'00' succeeded
	SUCCEEDED_connReply = 0x00

	// X'01' general SOCKS server failure
	GENERAL_SOCKS_SERVER_FAILURE_connReply = 0x01

	// X'02' connection not allowed by ruleset
	CONNECTION_NOT_ALLOWED_BY_RULESET_connReply = 0x02

	// X'03' Network unreachable
	NETWORK_UNREACHABLE_connReply = 0x03

	// X'04' Host unreachable
	HOST_UNREACHABLE_connReply = 0x04

	// X'05' Connection refused
	CONNECTION_REFUSED_connReply = 0x05

	// X'06' TTL expired
	TTL_EXPIRED_connReply = 0x06

	// X'07' Command not supported
	COMMAND_NOT_SUPPORTED_connReply = 0x07

	// X'08' Address type not supported
	ADDRESS_TYPE_NOT_SUPPORTED_connReply = 0x08

// X'09' to X'FF' unassigned
)

// Dial-up Constants
const (
	TCP_V4 = "tcp4"
)
