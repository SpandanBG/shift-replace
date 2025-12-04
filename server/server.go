package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"slices"
)

const (
	net_type = "tcp"
	port     = ":1080"
)

// Setup_SOCKS5H_Server - sets up the `socks5h://` server for proxy connections
func Setup_SOCKS5H_Server() {
	listener, err := net.Listen(net_type, port)
	if err != nil {
		panic(err)
	}

	fmt.Println("socks5h:// started on port", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}

		go func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("Recovered from panic: %v\nStack Trace:\n%s\n", r, debug.Stack())
				}
			}()

			if err := handle_socks5_connection(conn, context.Background()); err != nil {
				fmt.Println(err)
			}
		}()
	}
}

// handle_socks5_connection - handles a new incoming TCP connection.
// Follows the guidelines of - https://datatracker.ietf.org/doc/html/rfc1927
func handle_socks5_connection(conn net.Conn, ctx context.Context) error {
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
// The VER field is set to X'05' for this version of the protocol. The
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

	req, err := readSockRequest(conn)
	if err != nil {
		return err
	}

	remote, res, err := prepareProxy(req)
	if err != nil {
		return err
	}

	if remote == nil {
		return errors.New("could not create remote connection")
	}

	if err := replyConnInfo(conn, res); err != nil {
		return err
	}

	if rErr, wErr := tunnel(conn, remote); rErr != nil || wErr != nil {
		return fmt.Errorf("readError: %v\nwriteError: %v", rErr, wErr)
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
	// set reply to no acceptable methods (X'FF) avaiable by default
	reply := []byte{SOCKS5H_VERSION, NO_ACCEPTABLE_METHODS_method}

	// Select no auth required method (X'00) if applicable
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
func readSockRequest(conn net.Conn) (Socks5_Req, error) {
	// ---------------- READ Reqeust Header
	header := make([]byte, 4)
	if readLen, err := conn.Read(header); err != nil {
		return Socks5_Req{}, err
	} else if readLen != 4 {
		return Socks5_Req{}, errors.New("ver to aytp in socks5h request isn't of length 4")
	}

	ver, cmd, rsv, atyp := header[0], header[1], header[2], header[3]

	if ver != SOCKS5H_VERSION || rsv != RSV {
		return Socks5_Req{}, errors.New("invalid version or rsv")
	}

	if cmd < CONNECT_cmd || cmd > UDP_ASSOCIATE_cmd {
		return Socks5_Req{}, errors.New("request cmd type is invalid")
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
		return Socks5_Req{}, err
	}

	return Socks5_Req{
		Version: ver,
		Cmd:     cmd,
		AType:   atyp,
		DstAddr: addr,
		DstPort: port,
	}, nil
}

func prepareProxy(req Socks5_Req) (net.Conn, Socks5_Res, error) {
	if req.Cmd == CONNECT_cmd {
		return connectDst(req)
	}

	// TODO handle for BIND and UDP associate

	return nil, Socks5_Res{}, nil
}

// connectDst - In the reply to a CONNECT (refer `replyConnInfo`), BND.PORT
// contains the port number that the server assigned to connect to the target
// host, while BND.ADDR contains the associated IP address.  The supplied
// BND.ADDR is often different from the IP address that the client uses to
// reach the SOCKS server, since such servers are often multi-homed.  It is
// expected that the SOCKS server will use DST.ADDR and DST.PORT, and the
// client-side source address and port in evaluating the CONNECT request.
func connectDst(req Socks5_Req) (remote net.Conn, res Socks5_Res, err error) {

	switch req.AType {
	case DOMAINNAME_addr:
		remote, err = net.Dial(TCP_V4, req.FullAddr())
		if err == nil {
			res.Reply = SUCCEEDED_connReply
		}
	default:
		res.Reply = ADDRESS_TYPE_NOT_SUPPORTED_connReply
	}

	localAddr := remote.LocalAddr().(*net.TCPAddr)
	if remote != nil {
		if v4 := localAddr.IP.To4(); v4 != nil {
			res.AType = IP_V4_addr
		} else if v6 := localAddr.IP.To16(); v6 != nil {
			res.AType = IP_V6_addr
		} else {
			res.AType = DOMAINNAME_addr
		}

		res.BindAddr = localAddr.IP.String()
		res.BindPort = localAddr.Port
	}

	return
}

// replyConnInfo - The server evaluates the request, and returns a reply formed
// as follows:
//
//			+----+-----+-------+------+----------+----------+
//			|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//			+----+-----+-------+------+----------+----------+
//			| 1  |  1  | X'00' |  1   | Variable |    2     |
//			+----+-----+-------+------+----------+----------+
//
//	 Where:
//				o  VER    protocol version: X'05'
//				o  REP    Reply field:
//					 o  X'00' succeeded
//					 o  X'01' general SOCKS server failure
//					 o  X'02' connection not allowed by ruleset
//					 o  X'03' Network unreachable
//					 o  X'04' Host unreachable
//					 o  X'05' Connection refused
//					 o  X'06' TTL expired
//					 o  X'07' Command not supported
//					 o  X'08' Address type not supported
//					 o  X'09' to X'FF' unassigned
//				o  RSV    RESERVED
//				o  ATYP   address type of following address
//					 o  IP V4 address: X'01'
//					 o  DOMAINNAME: X'03'
//					 o  IP V6 address: X'04'
//				o  BND.ADDR       server bound address
//				o  BND.PORT       server bound port in network octet order
//
// Fields marked RESERVED (RSV) must be set to X'00'.
//
// If the chosen method includes encapsulation for purposes of
// authentication, integrity and/or confidentiality, the replies are
// encapsulated in the method-dependent encapsulation.
func replyConnInfo(conn net.Conn, res Socks5_Res) error {
	reply := []byte{SOCKS5H_VERSION, res.Reply, RSV, res.AType}
	reply = append(reply, res.AddrBytes()...)
	reply = append(reply, res.PortBytes()...)

	wLen, err := conn.Write(reply)

	if err != nil {
		return err
	}

	if wLen != len(reply) {
		return errors.New("couldn't reply complete connect reply")
	}

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
func readDomainNameAddr(conn net.Conn) (
	domainName []byte,
	port []byte,
	err error,
) {
	// to hold the length of the domain name
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

func tunnel(client, remote net.Conn) (readErr, writeErr error) {
	go func() {
		_, writeErr = io.Copy(remote, client)
	}()
	_, readErr = io.Copy(client, remote)

	return
}
