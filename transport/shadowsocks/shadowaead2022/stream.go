package shadowaead2022

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	mathRand "math/rand"
	"net"
	"time"

	"github.com/Dreamacro/clash/transport/shadowsocks/shadowaead"
	"github.com/Dreamacro/clash/transport/socks5"
)

const (
	// payloadSizeMask is the maximum size of payload in bytes.
	payloadSizeMask = 0xFFFF    // 65535
	bufSize         = 65 * 1024 // >= 2+aead.Overhead()+payloadSizeMask+aead.Overhead()
)

const (
	headerClientStream = 0
	headerServerStream = 1
	minPaddingLength   = 0
	maxPaddingLength   = 900
)

var (
	ErrZeroChunk              = errors.New("zero chunk")
	ErrWriteHeaderTooLarge    = errors.New("write buffer too large")
	ErrShortBuffer            = errors.New("short buffer")
	ErrInvalidHeader          = errors.New("header invalid")
	ErrShouldReadHeaderFirst  = errors.New("should ReadHeader first")
	ErrShouldWriteHeaderFirst = errors.New("should WriteHeader first")
)

type Writer struct {
	io.Writer
	cipher.AEAD
	nonce     [32]byte
	salt      []byte
	buf       []byte
	writeResp bool
}

// NewWriter wraps an io.Writer with authenticated encryption.
func NewWriter(w io.Writer, aead cipher.AEAD, salt []byte) *Writer {
	return &Writer{Writer: w, AEAD: aead, salt: salt, buf: make([]byte, bufSize)}
}

func (w *Writer) appendTo(in []byte, out []byte) (n int, err error) {
	tag := w.Overhead()

	if len(in) > payloadSizeMask {
		return 0, ErrWriteHeaderTooLarge
	} else if len(out) < len(in)+tag {
		return 0, ErrShortBuffer
	}

	nonce := w.nonce[:w.NonceSize()]
	w.Seal(out[:0], nonce, in, nil)
	increment(nonce)
	return len(in) + tag, nil
}

// Write encrypts p and writes to the embedded io.Writer.
func (w *Writer) Write(p []byte) (n int, err error) {
	buf := w.buf
	nonce := w.nonce[:w.NonceSize()]
	tag := w.Overhead()
	off := 2 + tag

	for nr := 0; n < len(p) && err == nil; n += nr {
		nr = payloadSizeMask
		if n+nr > len(p) {
			nr = len(p) - n
		}
		buf = buf[:off+nr+tag]
		buf[0], buf[1] = byte(nr>>8), byte(nr) // big-endian payload size
		w.Seal(buf[:0], nonce, buf[:2], nil)
		increment(nonce)
		w.Seal(buf[:off], nonce, p[n:n+nr], nil)
		increment(nonce)
		_, err = w.Writer.Write(buf)
	}
	return
}

// ReadFrom reads from the given io.Reader until EOF or error, encrypts and
// writes to the embedded io.Writer. Returns number of bytes read from r and
// any error encountered.
func (w *Writer) ReadFrom(r io.Reader) (n int64, err error) {
	buf := w.buf
	nonce := w.nonce[:w.NonceSize()]
	tag := w.Overhead()
	off := 2 + tag
	for {
		nr, er := r.Read(buf[off : off+payloadSizeMask])
		n += int64(nr)
		buf[0], buf[1] = byte(nr>>8), byte(nr)
		w.Seal(buf[:0], nonce, buf[:2], nil)
		increment(nonce)
		w.Seal(buf[:off], nonce, buf[off:off+nr], nil)
		increment(nonce)
		if _, ew := w.Writer.Write(buf[:off+nr+tag]); ew != nil {
			err = ew
			return
		}
		if er != nil {
			if er != io.EOF { // ignore EOF as per io.ReaderFrom contract
				err = er
			}
			return
		}
	}
}

type Reader struct {
	io.Reader
	cipher.AEAD
	nonce [32]byte // should be sufficient for most nonce sizes
	buf   []byte   // to be put back into bufPool
	off   int      // offset to unconsumed part of buf
}

// NewReader wraps an io.Reader with authenticated decryption.
func NewReader(r io.Reader, aead cipher.AEAD) *Reader {
	return &Reader{Reader: r, AEAD: aead, buf: make([]byte, bufSize), off: bufSize}
}

// readExact decrypt a raw record into p. len(p) >= max payload size + AEAD overhead.
func (r *Reader) readExact(p []byte, n int) error {
	nonce := r.nonce[:r.NonceSize()]
	tag := r.Overhead()

	if n > len(p)-tag {
		return ErrShortBuffer
	}

	p = p[:n+tag]
	if _, err := io.ReadFull(r.Reader, p); err != nil {
		return err
	}
	_, err := r.Open(p[:0], nonce, p, nil)
	increment(nonce)
	if err != nil {
		return err
	}
	return nil
}

// Read and decrypt a record into p. len(p) >= max payload size + AEAD overhead.
func (r *Reader) readChunk(p []byte) (int, error) {
	nonce := r.nonce[:r.NonceSize()]
	tag := r.Overhead()

	// decrypt payload size
	p = p[:2+tag]
	if _, err := io.ReadFull(r.Reader, p); err != nil {
		return 0, err
	}
	_, err := r.Open(p[:0], nonce, p, nil)
	increment(nonce)
	if err != nil {
		return 0, err
	}

	// decrypt payload
	size := (int(p[0])<<8 + int(p[1])) & payloadSizeMask
	if size == 0 {
		return 0, ErrZeroChunk
	}

	p = p[:size+tag]
	if _, err := io.ReadFull(r.Reader, p); err != nil {
		return 0, err
	}
	_, err = r.Open(p[:0], nonce, p, nil)
	increment(nonce)
	if err != nil {
		return 0, err
	}
	return size, nil
}

// Read reads from the embedded io.Reader, decrypts and writes to p.
func (r *Reader) Read(p []byte) (int, error) {
	if r.off == len(r.buf) {
		if len(p) >= payloadSizeMask+r.Overhead() {
			return r.readChunk(p)
		}
		r.buf = r.buf[:bufSize]
		n, err := r.readChunk(r.buf)
		if err != nil {
			return 0, err
		}
		r.buf = r.buf[:n]
		r.off = 0
	}

	n := copy(p, r.buf[r.off:])
	r.off += n
	return n, nil
}

// WriteTo reads from the embedded io.Reader, decrypts and writes to w until
// there's no more data to write or when an error occurs. Return number of
// bytes written to w and any error encountered.
func (r *Reader) WriteTo(w io.Writer) (n int64, err error) {
	for {
		for r.off < len(r.buf) {
			nw, ew := w.Write(r.buf[r.off:])
			r.off += nw
			n += int64(nw)
			if ew != nil {
				err = ew
				return
			}
		}

		nr, er := r.readChunk(r.buf)
		if er != nil {
			if er != io.EOF {
				err = er
			}
			return
		}
		r.buf = r.buf[:nr]
		r.off = 0
	}
}

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

type Conn struct {
	net.Conn
	shadowaead.Cipher
	r *Reader
	w *Writer
}

// NewConn wraps a stream-oriented net.Conn with cipher.
func NewConn(c net.Conn, ciph shadowaead.Cipher) *Conn { return &Conn{Conn: c, Cipher: ciph} }

func (c *Conn) ReadHeader() ([]byte, error) {
	if c.r != nil {
		return nil, ErrShouldReadHeaderFirst
	}

	salt, err := c.initReader()
	if err != nil {
		return nil, err
	}

	// we don't need to read the header in one buffer
	buf := make([]byte, 128)
	if err := c.r.readExact(buf, 11); err != nil {
		return nil, err
	}

	if buf[0] != headerServerStream {
		return nil, ErrInvalidHeader
	} else if time.Since(time.Unix(int64(binary.BigEndian.Uint64(buf[1:])), 0)).Abs() > time.Second*30 {
		return nil, ErrInvalidHeader
	}

	nextLen := binary.BigEndian.Uint16(buf[9:])

	addr, err := socks5.ReadAddrBuf(c.r)
	if err != nil {
		return nil, err
	}
	var paddingLen uint16
	if err := binary.Read(c.r, binary.BigEndian, &paddingLen); err != nil {
		return nil, err
	}
	if _, err := io.CopyBuffer(io.Discard, io.LimitReader(c.r, int64(paddingLen)), buf); err != nil {
		return nil, err
	}

	initialLen := int(nextLen) - len(addr) - int(paddingLen)
	if initialLen < 0 || (len(c.r.buf)-c.r.off) != initialLen {
		return nil, ErrInvalidHeader
	}

	headerBuf := bytes.Buffer{}
	headerBuf.Grow(9 + c.SaltSize() + 2 + c.w.Overhead())

	// +------+---------------+----------------+--------+
	// | type |   timestamp   |  request salt  | length |
	// +------+---------------+----------------+--------+
	// |  1B  | 8B unix epoch |     16/32B     |  u16be |
	// +------+---------------+----------------+--------+
	headerBuf.WriteByte(headerServerStream)
	binary.Write(&headerBuf, binary.BigEndian, uint64(time.Now().Unix()))
	headerBuf.Write(salt)
	binary.Write(&headerBuf, binary.BigEndian, uint16(0))

	return addr, nil
}

func (c *Conn) WriteHeader(addr []byte) error {
	if c.w != nil {
		return ErrShouldWriteHeaderFirst
	}

	if err := c.initWriter(); err != nil {
		return err
	}

	tagLen := c.w.Overhead()
	paddingLen := mathRand.Intn(maxPaddingLength) + 1
	firstHeaderLen := 11
	secondHeaderLen := len(addr) + 2 + paddingLen
	salt := c.w.salt

	buf := bytes.Buffer{}
	headerBuf := bytes.Buffer{}
	headerBuf.Grow(len(salt) + firstHeaderLen + tagLen + secondHeaderLen + tagLen)
	headerBuf.Write(salt)

	// +------+---------------+--------+
	// | type |   timestamp   | length |
	// +------+---------------+--------+
	// |  1B  | 8B unix epoch |  u16be |
	// +------+---------------+--------+
	buf.WriteByte(headerClientStream)
	binary.Write(&buf, binary.BigEndian, uint64(time.Now().Unix()))
	binary.Write(&buf, binary.BigEndian, uint16(secondHeaderLen))

	if _, err := c.w.appendTo(buf.Bytes(), headerBuf.Bytes()[:len(salt)]); err != nil {
		return err
	}

	// +------+----------+-------+----------------+----------+-----------------+
	// | ATYP |  address |  port | padding length |  padding | initial payload |
	// +------+----------+-------+----------------+----------+-----------------+
	// |  1B  | variable | u16be |     u16be      | variable |    variable     |
	// +------+----------+-------+----------------+----------+-----------------+
	buf.Reset()
	binary.Write(&buf, binary.BigEndian, uint16(secondHeaderLen))
	buf.Write(addr)
	binary.Write(&buf, binary.BigEndian, uint16(paddingLen))
	buf.ReadFrom(io.LimitReader(rand.Reader, int64(paddingLen)))

	if _, err := c.w.appendTo(buf.Bytes(), headerBuf.Bytes()[:len(salt)+firstHeaderLen+tagLen]); err != nil {
		return err
	}

	_, err := c.w.Write(headerBuf.Bytes())
	c.w.writeResp = true
	return err
}

func (c *Conn) initReader() ([]byte, error) {
	salt := make([]byte, c.SaltSize())
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return nil, err
	}

	aead, err := c.Decrypter(salt)
	if err != nil {
		return nil, err
	}

	c.r = NewReader(c.Conn, aead)
	return salt, nil
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.r == nil {
		if _, err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	if c.r == nil {
		if _, err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.WriteTo(w)
}

func (c *Conn) initWriter() error {
	salt := make([]byte, c.SaltSize())
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	aead, err := c.Encrypter(salt)
	if err != nil {
		return err
	}
	c.w = NewWriter(c.Conn, aead, salt)
	return nil
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.w != nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}

func (c *Conn) ReadFrom(r io.Reader) (int64, error) {
	if c.w != nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.ReadFrom(r)
}
