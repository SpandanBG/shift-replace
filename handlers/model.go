package handlers

import (
	"encoding/binary"
	"fmt"
)

type Socks5_Req struct {
	Version byte
	Cmd     byte
	AType   byte
	DstAddr []byte
	DstPort []byte

	addr string
	port int
}

func (s Socks5_Req) AddrStr() string {
	if len(s.addr) > 0 {
		return s.addr
	}

	s.addr = string(s.DstAddr)
	return s.addr
}

func (s Socks5_Req) PortNum() int {
	if s.port > 0 {
		return s.port
	}

	s.port = int(binary.BigEndian.Uint16(s.DstPort))
	return s.port
}

func (s Socks5_Req) FullAddr() string {
	return fmt.Sprintf("%s:%d", s.AddrStr(), s.PortNum())
}

type Socks5_Res struct {
	Reply    byte
	AType    byte
	BindAddr string
	BindPort int

	addr []byte
	port []byte
}

func (s Socks5_Res) AddrBytes() []byte {
	if len(s.addr) > 0 {
		return s.addr
	}

	s.addr = []byte(s.BindAddr)
	return s.addr
}

func (s Socks5_Res) PortBytes() []byte {
	if len(s.port) > 0 {
		return s.port
	}

	s.port = make([]byte, 2)
	binary.BigEndian.PutUint16(s.port, uint16(s.BindPort))
	return s.port
}
