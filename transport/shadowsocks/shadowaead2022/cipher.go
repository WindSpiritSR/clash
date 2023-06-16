package shadowaead2022

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/Dreamacro/clash/transport/shadowsocks/shadowaead"

	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"
)

func blake3Kdf(secret, salt, outkey []byte) {
	srckey := make([]byte, len(secret)+len(salt))
	copy(srckey, secret)
	copy(srckey[len(secret):], salt)
	blake3.DeriveKey(outkey, "shadowsocks 2022 session subkey", srckey)
}

type metaCipher struct {
	psk      []byte
	makeAEAD func(key []byte) (cipher.AEAD, error)
}

func (a *metaCipher) KeySize() int { return len(a.psk) }
func (a *metaCipher) SaltSize() int {
	if ks := a.KeySize(); ks > 16 {
		return ks
	}
	return 16
}

func (a *metaCipher) Encrypter(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, a.KeySize())
	blake3Kdf(a.psk, salt, subkey)
	return a.makeAEAD(subkey)
}

func (a *metaCipher) Decrypter(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, a.KeySize())
	blake3Kdf(a.psk, salt, subkey)
	return a.makeAEAD(subkey)
}

func aesGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// AESGCM creates a new Cipher with a pre-shared key. len(psk) must be
// one of 16, 24, or 32 to select AES-128/196/256-GCM.
func AESGCM(psk []byte) (shadowaead.Cipher, error) {
	switch l := len(psk); l {
	case 16, 32: // AES 128/256
	default:
		return nil, aes.KeySizeError(l)
	}
	return &metaCipher{psk: psk, makeAEAD: aesGCM}, nil
}

// XChacha20Poly1305 creates a new Cipher with a pre-shared key. len(psk)
// must be 32.
func XChacha20Poly1305(psk []byte) (shadowaead.Cipher, error) {
	if len(psk) != chacha20poly1305.KeySize {
		return nil, shadowaead.KeySizeError(chacha20poly1305.KeySize)
	}
	return &metaCipher{psk: psk, makeAEAD: chacha20poly1305.NewX}, nil
}
