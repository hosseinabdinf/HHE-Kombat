package pasta

import (
	"encoding/binary"
	"fmt"
	"testing"

	"HHELand/sym/pasta"
	"HHELand/utils"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func testString(opName string, p pasta.Parameter) string {
	return fmt.Sprintf("%s/KeySize=%d/PlainSize=%d/CipherSize=%d/Modulus=%d/Rounds=%d",
		opName, p.GetKeySize(), p.GetBlockSize(), p.GetBlockSize(), p.GetModulus(), p.GetRounds())
}

func TestPasta3(t *testing.T) {
	for _, tc := range pasta3TestVector {
		fmt.Println(testString("PASTA-3", tc.SymParams))
		testHEPasta(t, tc)
	}
	// testHEPasta(t, pasta3TestVector[0])
}

func TestPasta4(t *testing.T) {
	for _, tc := range pasta4TestVector {
		fmt.Println(testString("PASTA-4", tc.SymParams))
		testHEPasta(t, tc)
	}
	// testHEPasta(t, pasta4TestVector[0])
}

func testHEPasta(t *testing.T, tc TestContext) {
	hePasta := NewHEPasta()
	lg := hePasta.logger
	lg.PrintDataLen(tc.Key)

	hePasta.InitParams(tc.Params, tc.SymParams)

	hePasta.HEKeyGen()
	lg.PrintMemUsage("HEKeyGen")

	_ = hePasta.InitFvPasta()
	lg.PrintMemUsage("InitFvPasta")

	hePasta.CreateGaloisKeys(len(tc.ExpCipherText))
	lg.PrintMemUsage("CreateGaloisKeys")

	// encrypts symmetric master key using BFV on the client side
	hePasta.EncryptSymKey(tc.Key)
	lg.PrintMemUsage("EncryptSymKey")

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, uint64(123456789))

	// the server side
	fvCiphers := hePasta.Trancipher(nonce, tc.ExpCipherText)
	lg.PrintMemUsage("Trancipher")

	hePasta.Decrypt(fvCiphers[0])
	lg.PrintMemUsage("Decrypt")
}

func TestNbPasta3(t *testing.T) {
	utils.PrintHeader("PASTA-3 Transciphering")
	tc := pasta3TestVector[0]
	fmt.Println(testString("PASTA-3", tc.SymParams))

	hePasta := NewHEPasta()

	hePasta.InitParams(tc.Params, tc.SymParams)

	hePasta.HEKeyGen()

	_ = hePasta.InitFvPasta()

	hePasta.CreateGaloisKeys(len(tc.ExpCipherText))

	// encrypts symmetric master key using BFV on the client side
	hePasta.EncryptSymKey(tc.Key)

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, uint64(123456789))

	println("Data length: ", len(tc.ExpCipherText))
	// the server side
	var fvCiphers []*rlwe.Ciphertext

	utils.Benchmark("HHE.Decomp()", func() {
		fvCiphers = hePasta.Trancipher(nonce, tc.ExpCipherText)
	})

	hePasta.Decrypt(fvCiphers[0])
}

func TestNbPasta4(t *testing.T) {
	utils.PrintHeader("PASTA-4 Transciphering")
	tc := pasta4TestVector[2]
	fmt.Println(testString("PASTA-4", tc.SymParams))

	hePasta := NewHEPasta()

	hePasta.InitParams(tc.Params, tc.SymParams)

	hePasta.HEKeyGen()

	_ = hePasta.InitFvPasta()

	hePasta.CreateGaloisKeys(len(tc.ExpCipherText))

	// encrypts symmetric master key using BFV on the client side
	hePasta.EncryptSymKey(tc.Key)

	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, uint64(123456789))

	println("Data length: ", len(tc.ExpCipherText))
	// the server side
	var fvCiphers []*rlwe.Ciphertext

	utils.Benchmark("HHE.Decomp()", func() {
		fvCiphers = hePasta.Trancipher(nonce, tc.ExpCipherText)
	})

	hePasta.Decrypt(fvCiphers[0])
}
