package rubato

import (
	"fmt"
	"testing"

	"HHELand"
	"HHELand/utils"
)

func testString(opName string, p Parameter) string {
	return fmt.Sprintf("%s/BlockSize=%d/Modulus=%d/Rounds=%d/Sigma=%f",
		opName, p.GetBlockSize(), p.GetModulus(), p.GetRounds(), p.GetSigma())
}

func TestRubato(t *testing.T) {
	logger := utils.NewLogger(utils.DEBUG)
	for _, tc := range TestsVector {
		fmt.Println(testString("Rubato", tc.Params))
		rubatoCipher := NewRubato(tc.Key, tc.Params)
		encryptor := rubatoCipher.NewEncryptor()
		var ciphertext HHELand.Ciphertext

		t.Run("RubatoEncryptionTest", func(t *testing.T) {
			ciphertext = encryptor.Encrypt(tc.Plaintext)
			logger.PrintMemUsage("RubatoEncryptionTest")
		})

		t.Run("RubatoDecryptionTest", func(t *testing.T) {
			encryptor.Decrypt(ciphertext)
		})

		logger.PrintDataLen(tc.Key)
		logger.PrintDataLen(ciphertext)
	}
}

// TestNbRubato new benchmarking test for rubato
func TestNbRubato(t *testing.T) {
	t.Run("HHEKombat:Rubato", func(t *testing.T) {
		utils.PrintHeader("Rubato SKE Benchmark")
		tCase := TestsVector[0] // for rubato 5
		//tCase := TestsVector[1] // for rubato 3
		//tCase := TestsVector[2] // for rubato 2

		fmt.Println(testString("Rubato", tCase.Params))

		rubatoCipher := NewRubato(tCase.Key, tCase.Params)
		encryptor := rubatoCipher.NewEncryptor()

		utils.BenchmarkIter("SKE.Enc()", 100, func() {
			_ = encryptor.Encrypt(tCase.Plaintext)
		})
	})
}
