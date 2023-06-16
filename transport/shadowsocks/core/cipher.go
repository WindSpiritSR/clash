package core

import (
	"crypto/md5"
	"errors"
	"net"
	"sort"
	"strings"

	"github.com/Dreamacro/clash/transport/shadowsocks/shadowaead"
	"github.com/Dreamacro/clash/transport/shadowsocks/shadowaead2022"
	"github.com/Dreamacro/clash/transport/shadowsocks/shadowstream"
	"github.com/Dreamacro/clash/transport/socks5"
)

type Cipher interface {
	StreamConnCipher
	PacketConnCipher
}

type Conn interface {
	net.Conn
	WriteHeader(addr []byte) error
	ReadHeader() (addr []byte, err error)
}

type StreamConnCipher interface {
	StreamConn(net.Conn) Conn
}

type PacketConnCipher interface {
	PacketConn(net.PacketConn) net.PacketConn
}

// ErrCipherNotSupported occurs when a cipher is not supported (likely because of security concerns).
var ErrCipherNotSupported = errors.New("cipher not supported")

const (
	aeadBlake3Aes128Gcm        = "AEAD_BLAKE3_AES_128_GCM"
	aeadBlake3Aes256Gcm        = "AEAD_BLAKE3_AES_256_GCM"
	aeadBlake3Chacha20Poly1305 = "AEAD_BLAKE3_CHACHA20_POLY1305"
)

// List of AEAD 2022 ciphers: key size in bytes and constructor
var aead2022List = map[string]struct {
	KeySize int
	New     func([]byte) (shadowaead.Cipher, error)
}{
	aeadBlake3Aes128Gcm:        {16, shadowaead2022.AESGCM},
	aeadBlake3Aes256Gcm:        {32, shadowaead2022.AESGCM},
	aeadBlake3Chacha20Poly1305: {32, shadowaead2022.XChacha20Poly1305},
}

const (
	aeadAes128Gcm         = "AEAD_AES_128_GCM"
	aeadAes192Gcm         = "AEAD_AES_192_GCM"
	aeadAes256Gcm         = "AEAD_AES_256_GCM"
	aeadChacha20Poly1305  = "AEAD_CHACHA20_POLY1305"
	aeadXChacha20Poly1305 = "AEAD_XCHACHA20_POLY1305"
)

// List of AEAD ciphers: key size in bytes and constructor
var aeadList = map[string]struct {
	KeySize int
	New     func([]byte) (shadowaead.Cipher, error)
}{
	aeadAes128Gcm:         {16, shadowaead.AESGCM},
	aeadAes192Gcm:         {24, shadowaead.AESGCM},
	aeadAes256Gcm:         {32, shadowaead.AESGCM},
	aeadChacha20Poly1305:  {32, shadowaead.Chacha20Poly1305},
	aeadXChacha20Poly1305: {32, shadowaead.XChacha20Poly1305},
}

// List of stream ciphers: key size in bytes and constructor
var streamList = map[string]struct {
	KeySize int
	New     func(key []byte) (shadowstream.Cipher, error)
}{
	"RC4-MD5":       {16, shadowstream.RC4MD5},
	"AES-128-CTR":   {16, shadowstream.AESCTR},
	"AES-192-CTR":   {24, shadowstream.AESCTR},
	"AES-256-CTR":   {32, shadowstream.AESCTR},
	"AES-128-CFB":   {16, shadowstream.AESCFB},
	"AES-192-CFB":   {24, shadowstream.AESCFB},
	"AES-256-CFB":   {32, shadowstream.AESCFB},
	"CHACHA20-IETF": {32, shadowstream.Chacha20IETF},
	"XCHACHA20":     {32, shadowstream.Xchacha20},
}

// ListCipher returns a list of available cipher names sorted alphabetically.
func ListCipher() []string {
	var l []string
	for k := range aeadList {
		l = append(l, k)
	}
	for k := range streamList {
		l = append(l, k)
	}
	sort.Strings(l)
	return l
}

// PickCipher returns a Cipher of the given name. Derive key from password if given key is empty.
func PickCipher(name string, key []byte, password string) (Cipher, error) {
	name = strings.ToUpper(name)

	switch name {
	case "DUMMY":
		return &dummy{}, nil
	case "CHACHA20-IETF-POLY1305":
		name = aeadChacha20Poly1305
	case "XCHACHA20-IETF-POLY1305":
		name = aeadXChacha20Poly1305
	case "AES-128-GCM":
		name = aeadAes128Gcm
	case "AES-192-GCM":
		name = aeadAes192Gcm
	case "AES-256-GCM":
		name = aeadAes256Gcm
	case "2022-BLAKE3-CHACHA20-POLY1305":
		name = aeadBlake3Chacha20Poly1305
	case "2022-BLAKE3-AES-128-GCM":
		name = aeadBlake3Aes128Gcm
	case "2022-BLAKE3-AES-256-GCM":
		name = aeadBlake3Aes256Gcm
	}

	if choice, ok := aeadList[name]; ok {
		if len(key) == 0 {
			key = Kdf(password, choice.KeySize)
		}
		if len(key) != choice.KeySize {
			return nil, shadowaead.KeySizeError(choice.KeySize)
		}
		aead, err := choice.New(key)
		return &AeadCipher{Cipher: aead, Key: key}, err
	}

	if choice, ok := streamList[name]; ok {
		if len(key) == 0 {
			key = Kdf(password, choice.KeySize)
		}
		if len(key) != choice.KeySize {
			return nil, shadowstream.KeySizeError(choice.KeySize)
		}
		ciph, err := choice.New(key)
		return &StreamCipher{Cipher: ciph, Key: key}, err
	}

	return nil, ErrCipherNotSupported
}

type AeadCipher struct {
	shadowaead.Cipher

	Key []byte
}

func (aead *AeadCipher) StreamConn(c net.Conn) Conn { return shadowaead.NewConn(c, aead) }
func (aead *AeadCipher) PacketConn(c net.PacketConn) net.PacketConn {
	return shadowaead.NewPacketConn(c, aead)
}

type StreamCipher struct {
	shadowstream.Cipher

	Key []byte
}

func (ciph *StreamCipher) StreamConn(c net.Conn) Conn { return shadowstream.NewConn(c, ciph) }
func (ciph *StreamCipher) PacketConn(c net.PacketConn) net.PacketConn {
	return shadowstream.NewPacketConn(c, ciph)
}

// dummy cipher does not encrypt

type dummy struct{}

func (dummy) StreamConn(c net.Conn) Conn                 { return &dummyConn{c} }
func (dummy) PacketConn(c net.PacketConn) net.PacketConn { return c }

type dummyConn struct{ net.Conn }

func (d *dummyConn) ReadHeader() ([]byte, error) { return socks5.ReadAddrBuf(d.Conn) }
func (d *dummyConn) WriteHeader(addr []byte) error {
	_, err := d.Conn.Write(addr)
	return err
}

// key-derivation function from original Shadowsocks
func Kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}
