package cryptopals

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"io"
)

// HexToBase64 solves challenge 1
// maybe I cheated
func HexToBase64(h string) string {
	ret, _ := hex.DecodeString(h)
	return base64.StdEncoding.EncodeToString(ret)
}

// FixedXOR solves challenge 2
func FixedXOR(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("a and b have different sizes")
	}

	ret := make([]byte, len(a))
	for i := range ret {
		ret[i] = a[i] ^ b[i]
	}

	return ret
}

// BreakSingleByteXORCipher solves challenge 3
func BreakSingleByteXORCipher(cipher []byte) []byte {
	key, _ := keyForSingleByteXorCipher(cipher)
	return byteXOR(key, cipher)
}

func keyForSingleByteXorCipher(cipher []byte) (key byte, score uint) {
	plain := make([]byte, len(cipher))

	for k := 0x00; k <= 0xff; k++ {
		for i := range cipher {
			plain[i] = cipher[i] ^ byte(k)
		}

		if s := frequencyScore(plain); s > score {
			key = byte(k)
			score = s
		}
	}

	return
}

func byteXOR(k byte, src []byte) []byte {
	dest := make([]byte, len(src))

	for i := range src {
		dest[i] = src[i] ^ k
	}

	return dest
}

func frequencyScore(in []byte) (s uint) {
	for _, c := range in {
		switch c {
		case ' ':
			s += 3
		case 'E', 'T', 'A', 'O', 'I', 'N', 'S', 'H', 'R', 'D', 'L', 'U':
			s += 3
		case 'e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 'l', 'u':
			s += 3
		default:
			switch {
			case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
				s += 2
			case (c >= '0' && c <= '9'):
				s++
			}
		}
	}

	return
}

func NewHexEncodingScanner(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	split := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		advance, token, err = bufio.ScanLines(data, atEOF)
		if err == nil && token != nil {
			token, err = hex.DecodeString(string(token))
		}
		return
	}

	s.Split(split)

	return s
}

// DetectSingleByteXOR solves challenge 4
func DetectSingleByteXOR(r io.Reader) []byte {
	var score uint
	var plain []byte

	s := NewHexEncodingScanner(r)

	for s.Scan() {
		cipher := s.Bytes()
		k, s := keyForSingleByteXorCipher(cipher)

		if s > score {
			score = s
			plain = byteXOR(k, cipher)
		}
	}

	return plain
}

// RepeatingKeyXOR solves challenge 5
func RepeatingKeyXOR(key, plain []byte) []byte {
	k := make([]byte, len(plain))
	repeatKey([]byte(key), k[:])
	return FixedXOR(plain, k)
}

func repeatKey(key, rep []byte) {
	p := 0
	for len(rep[p:]) > 0 {
		p += copy(rep[p:], []byte(key))
	}
}
