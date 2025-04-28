package ckks_cipher

import (
	"strings"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

type BitSet struct {
    bits []uint8
    size  int
}

func NewBitSet(size int) *BitSet {
    return &BitSet{
        bits: make([]uint8, size),
        size:  size,
    }
}

func (b *BitSet) Set(x int) {
	if x<0 {panic("x value must > 0")}
	for i:=0;i<b.size;i++{
		b.bits[i] = uint8(x & 0x1)
		x >>= 1
	}
}

func (b *BitSet) ToULong() uint64 {
	var Out uint64
	for i, bit := range b.bits {
		Out = Out + uint64(bit << i)
	}
	return Out
}

func (b *BitSet) ToString() string {
    var sb strings.Builder
    for _, byte := range b.bits {
        if byte == 1 {
            sb.WriteString("1")
        } else {
            sb.WriteString("0")
        }
    }
    return sb.String()
}

func (b *BitSet) Copy() *BitSet {
    out := NewBitSet(b.size)
    for i, bit := range b.bits {
        if bit == 1 {
            out.bits[i] = 1
        } else {
            out.bits[i] = 0
        }
    }
    return out
}

func Xor(v0, v1 *BitSet) *BitSet {
	
    if v0.size!= v1.size {
        panic("bit sets have different sizes")
    }
	Out := NewBitSet(v0.size)
    for i := 0; i < v0.size; i++ {
        Out.bits[i] = v0.bits[i] ^ v1.bits[i]
    }
	return Out
}

func (b *BitSet) GetSize() int {
    return b.size
}

func vectorLeftRotationInplace(vector []*rlwe.Ciphertext, rotNum int) {
    for i := 0; i < rotNum; i++ {
        first := vector[0]
        copy(vector, vector[1:])
        vector[len(vector)-1] = first
    }
}

func vectorRightRotationInplace(vector []*rlwe.Ciphertext, rotNum int) {
    for i := 0; i < rotNum; i++ {
        last := vector[len(vector)-1]
        copy(vector[1:], vector)
        vector[0] = last
    }
}

func ctr(iv *BitSet, ctr uint64) *BitSet {
	out := iv.Copy()
	for i := iv.size - 64; i < iv.size; i++ {
		out.bits[i] = iv.bits[i] ^ byte( (ctr>>uint(i-8))&1 )
	}
	return out
}
// MinInt returns the minimum value of the input of int values.
func MinInt(a, b int) (r int) {
	if a <= b {
		return a
	}
	return b
}