package handlers

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
