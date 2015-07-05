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
func BreakSingleByteXORCipher(in []byte) ([]byte, uint) {
	var candidate singleByteXORCandidate
	key := make([]byte, len(in))
	for c := 0x00; c <= 0xff; c++ {
		for i := range key {
			key[i] = byte(c)
		}

		p := FixedXOR(in, key)

		if s := score(p); s > candidate.score {
			candidate = singleByteXORCandidate{p, s}
		}
	}

	return candidate.key, candidate.score
}

type singleByteXORCandidate struct {
	key   []byte
	score uint
}

func score(in []byte) (s uint) {
	for _, c := range in {
		switch c {
		case 'E', 'T', 'A', 'O', 'I', 'N', ' ', 'S', 'H', 'R', 'D', 'L', 'U':
		case 'e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 'l', 'u':
			s += 7
		default:
			switch {
			case (c >= '0' && c <= '9'):
				s += 3
			case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
				s += 5
			case c >= ' ' && c <= '~':
				s++
			}
		}
	}

	return
}

func NewBase64Decoder(r io.Reader) *bufio.Scanner {
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
	var bestScore uint
	var ret []byte

	s := NewBase64Decoder(r)

	for s.Scan() {
		k, s := BreakSingleByteXORCipher(s.Bytes())

		if s > bestScore {
			bestScore = s
			ret = k
		}
	}

	return ret
}
