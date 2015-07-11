package cryptopals

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"io"

	"github.com/twstrike/AwESome/aes"
	"github.com/twstrike/AwESome/block"
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
	key, _ := BreakSingleByteXORKey(cipher)
	return byteXOR(key, cipher)
}

func BreakSingleByteXORKey(cipher []byte) (key byte, score uint) {
	for k := 0x00; k <= 0xff; k++ {
		plain := byteXOR(byte(k), cipher)

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
		k, s := BreakSingleByteXORKey(cipher)

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

func HammingDistance(a, b []byte) int {
	if len(a) != len(b) {
		panic("a and b have different sizes")
	}

	n := 0
	for i := range a {
		for j := uint(0); j < 8; j++ {
			if byte(a[i]>>j&1) != byte(b[i]>>j&1) {
				n++
			}
		}
	}

	return n
}

func repeatingKeySize(cipher []byte, s int) []int {
	norm := 1000
	candidates := make([][]int, s)
	for i := range candidates {
		candidates[i] = []int{0, norm}
	}

	for k := 2; k <= 40; k++ {
		sa := cipher[:k]
		sb := cipher[k : 2*k]
		sc := cipher[2*k : 3*k]
		sd := cipher[3*k : 4*k]
		d1 := HammingDistance(sa, sb)
		d2 := HammingDistance(sb, sc)
		d3 := HammingDistance(sc, sd)
		d := 100 * (d1 + d2 + d3) / 3
		n := d / k

		i := s
		for ; i > 0 && candidates[i-1][1] > n; i-- {
		}

		if i == s {
			continue
		}

		copy(candidates[i+1:], candidates[i:])
		candidates[i] = []int{k, n}
	}

	keysize := make([]int, s)
	for i, c := range candidates {
		keysize[i] = c[0]
	}

	return keysize
}

func transposeBlocks(src []byte, n int) [][]byte {
	ret := make([][]byte, n)
	for i := range ret {
		ret[i] = make([]byte, 0, len(src)/n)
	}

	for i, b := range src {
		ret[i%n] = append(ret[i%n], b)
	}

	return ret
}

//BreakRepeatingKeyXOR solves challenge 6
func BreakRepeatingKeyXOR(cipher []byte) []byte {
	var ret []byte
	candidates := repeatingKeySize(cipher, 5)
	bestScore := uint(0)

	for _, length := range candidates {
		key := make([]byte, 0, length)
		score := uint(0)

		for _, block := range transposeBlocks(cipher, length) {
			k, s := BreakSingleByteXORKey(block)
			key = append(key, k)
			score += s
		}

		if score > bestScore {
			bestScore, ret = score, key
		}
	}

	return ret
}

func DecryptAEC_128_ECB(key, cipher []byte) []byte {
	ecb := block.ECB{}
	return ecb.Decrypt(key, cipher, aes.BlockCipher)
}
