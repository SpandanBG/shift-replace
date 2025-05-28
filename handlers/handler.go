package handlers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
)

// Handle_SOCKS5H_Connection - handles a new incoming TCP connection.
// Follows the guidelines of - https://datatracker.ietf.org/doc/html/rfc1927
func Handle_SOCKS5H_Connection(conn net.Conn, ctx context.Context) error {
	defer conn.Close()

	version := make([]byte, 1)
	if _, err := conn.Read(version); err != nil {
		return err
	}

	if len(version) > 0 && version[0] == SOCKS5H_VERSION {
		return handleSOCKS5(conn)
	}

	return errors.New("non socks5h connection received")
}

// handleSOCKS5 - handles any SOCK 5 connection
//
// The client connects to the server, and sends a version
// identifier/method selection message:
//
//	+----+----------+----------+
//	|VER | NMETHODS | METHODS  |
//	+----+----------+----------+
//	| 1  |    1     | 1 to 255 |
//	+----+----------+----------+
//
// The VER field is set to X'05' for this version of the protocol.  The
// NMETHODS field contains the number of method identifier octets that
// appear in the METHODS field.
func handleSOCKS5(conn net.Conn) error {
	nmethods := make([]byte, 1)
	if _, err := conn.Read(nmethods); err != nil {
		return err
	}

	var methods []byte
	if len(nmethods) > 0 && nmethods[0] > 0 {
		methods = make([]byte, nmethods[0])

		if _, err := conn.Read(methods); err != nil {
			return err
		}
	}

	if err := replyMethodSelection(conn, methods); err != nil {
		return err
	}

	if err := readSockRequest(conn); err != nil {
		return err
	}

	return nil
}

// replyMethodSelection - performs method negotiaions and sub-negotiations.
//
// The server selects from one of the methods given in METHODS, and
// sends a METHOD selection message:
//
//	+----+--------+
//	|VER | METHOD |
//	+----+--------+
//	| 1  |   1    |
//	+----+--------+
//
// If the selected METHOD is X'FF', none of the methods listed by the
// client are acceptable, and the client MUST close the connection.
// The values currently defined for METHOD are:
//
//	o  X'00' NO AUTHENTICATION REQUIRED
//	o  X'01' GSSAPI
//	o  X'02' USERNAME/PASSWORD
//	o  X'03' to X'7F' IANA ASSIGNED
//	o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
//	o  X'FF' NO ACCEPTABLE METHODS
//
// The client and server then enter a method-specific sub-negotiation.
func replyMethodSelection(conn net.Conn, methods []byte) error {
	// set reply to no acceptable methods avaiable by default
	reply := []byte{SOCKS5H_VERSION, NO_ACCEPTABLE_METHODS_method}

	// Select no auth required method if applicable
	if slices.Contains(methods, NO_AUTHENTICATION_REQUIRED_method) {
		reply[1] = NO_AUTHENTICATION_REQUIRED_method
	}

	// TODO: handle GSSAPI and USERNAME/PASSWORD auth methods

	if _, err := conn.Write(reply); err != nil {
		return err
	}

	// TODO: handle method sub-negotiations if required
	return nil
}

// readSockRequest - reads the socks5 request from the client
//
// The SOCKS request is formed as follows:
//
//			+----+-----+-------+------+----------+----------+
//			|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//			+----+-----+-------+------+----------+----------+
//			| 1  |  1  | X'00' |  1   | Variable |    2     |
//			+----+-----+-------+------+----------+----------+
//	 Where:
//				o  VER    protocol version: X'05'
//				o  CMD
//					 o  CONNECT X'01'
//					 o  BIND X'02'
//					 o  UDP ASSOCIATE X'03'
//				o  RSV    RESERVED
//				o  ATYP   address type of following address
//					 o  IP V4 address: X'01'
//					 o  DOMAINNAME: X'03'
//					 o  IP V6 address: X'04'
//				o  DST.ADDR       desired destination address
//				o  DST.PORT desired destination port in network octet
//					 order
//
// The SOCKS server will typically evaluate the request based on source
// and destination addresses, and return one or more reply messages, as
// appropriate for the request type.
func readSockRequest(conn net.Conn) error {
	// ---------------- READ Reqeust Header
	header := make([]byte, 4)
	if readLen, err := conn.Read(header); err != nil {
		return err
	} else if readLen != 4 {
		return errors.New("ver to aytp in socks5h request isn't of length 4")
	}

	ver, cmd, rsv, atyp := header[0], header[1], header[2], header[3]

	if ver != SOCKS5H_VERSION || rsv != RSV {
		return errors.New("invalid version or rsv")
	}

	if cmd < CONNECT_cmd || cmd > UDP_ASSOCIATE_cmd {
		return errors.New("request cmd type is invalid")
	}

	// ---------------- READ Address and Port
	var addr, port []byte
	var err error

	switch atyp {
	case IP_V4_addr:
		addr, port, err = readIPV4Addr(conn)
	case DOMAINNAME_addr:
		addr, port, err = readDomainNameAddr(conn)
	case IP_V6_addr:
		addr, port, err = readIPV6Addr(conn)
	default:
		err = errors.New("invalid atyp provided")
	}

	if err != nil {
		return err
	}

	fmt.Println(addr, port)
	return nil
}

// readIPV4Addr - reads the IPv4 address sent in the address request
func readIPV4Addr(conn net.Conn) (ipv4 []byte, port []byte, err error) {
	ipv4 = make([]byte, 4)
	port = make([]byte, 2)

	if readLen, err := conn.Read(ipv4); err != nil {
		return nil, nil, err
	} else if readLen != 4 {
		return nil, nil, errors.New("unable to ipv4")
	}

	if readLen, err := conn.Read(port); err != nil {
		return nil, nil, err
	} else if readLen != 2 {
		return nil, nil, errors.New("unable to ipv4 port")
	}

	return
}

// readDomainNameAddr - reads the domain name sent in the address request
func readDomainNameAddr(conn net.Conn) (domainName []byte, port []byte, err error) {
	length := make([]byte, 1)

	if readLen, err := conn.Read(length); err != nil {
		return nil, nil, err
	} else if readLen != 1 {
		return nil, nil, errors.New("unable to read domain name length")
	}

	domainName = make([]byte, length[0])
	port = make([]byte, 2)

	if readLen, err := conn.Read(domainName); err != nil {
		return nil, nil, err
	} else if readLen != int(length[0]) {
		return nil, nil, errors.New("unable to domain name")
	}

	if readLen, err := conn.Read(port); err != nil {
		return nil, nil, err
	} else if readLen != 2 {
		return nil, nil, errors.New("unable to domain name port")
	}

	return
}

// readIPV6Addr - reads the IPv6 address in the address request
func readIPV6Addr(conn net.Conn) (ipv6 []byte, port []byte, err error) {
	ipv6 = make([]byte, 16)
	port = make([]byte, 2)

	if readLen, err := conn.Read(ipv6); err != nil {
		return nil, nil, err
	} else if readLen != 16 {
		return nil, nil, errors.New("unable to ipv6")
	}

	if readLen, err := conn.Read(port); err != nil {
		return nil, nil, err
	} else if readLen != 2 {
		return nil, nil, errors.New("unable to ipv6 port")
	}

	return
}
