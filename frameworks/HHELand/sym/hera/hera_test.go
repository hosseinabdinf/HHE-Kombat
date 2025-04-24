package hera

import (
	"HHELand"
	"HHELand/utils"
	"fmt"
	"testing"
)

func testString(opName string, p Parameter) string {
	return fmt.Sprintf("%s/BlockSize=%d/Modulus=%d/Rounds=%d",
		opName, p.GetBlockSize(), p.GetModulus(), p.GetRounds())
}

func TestHera(t *testing.T) {
	logger := utils.NewLogger(utils.DEBUG)
	for _, tc := range TestVector {
		fmt.Println(testString("HERA", tc.Params))
		heraCipher := NewHera(tc.Key, tc.Params)
		encryptor := heraCipher.NewEncryptor()
		var ciphertext HHELand.Ciphertext

		t.Run("HeraEncryptionTest", func(t *testing.T) {
			ciphertext = encryptor.Encrypt(tc.Plaintext)
			logger.PrintMemUsage("HeraEncryptionTest")
		})

		t.Run("HeraDecryptionTest", func(t *testing.T) {
			encryptor.Decrypt(ciphertext)
		})

		logger.PrintDataLen(tc.Key)
		logger.PrintDataLen(ciphertext)
	}
}

// TestNbHera new benchmarking test for rubato
func TestNbHera(t *testing.T) {
	t.Run("HHEKombat:Hera", func(t *testing.T) {
		utils.PrintHeader("Hera SKE Benchmark")
		// test vectors Hera4 = {0,1,2,4}, Hera5={4,5,6,7}
		tCase := TestVector[6]

		fmt.Println(testString("HERA", tCase.Params))
		heraCipher := NewHera(tCase.Key, tCase.Params)
		encryptor := heraCipher.NewEncryptor()
		println("data len:", len(tCase.Plaintext))

		utils.BenchmarkIter("SKE.Enc()", 100, func() {
			_ = encryptor.Encrypt(tCase.Plaintext)
		})
	})
}
