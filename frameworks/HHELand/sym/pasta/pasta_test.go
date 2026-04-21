package pasta

import (
	"HHELand"
	"HHELand/utils"
	"fmt"
	"reflect"
	"testing"
)

func testString(opName string, p Parameter) string {
	return fmt.Sprintf("%s/KeySize=%d/PlainSize=%d/CipherSize=%d/Modulus=%d/Rounds=%d",
		opName, p.GetKeySize(), p.GetBlockSize(), p.GetBlockSize(), p.GetModulus(), p.GetRounds())
}

func TestPasta3(t *testing.T) {
	logger := utils.NewLogger(utils.DEBUG)
	for _, tc := range pasta3TestVector {
		fmt.Println(testString("PASTA", tc.Params))
		pastaCipher := NewPasta(tc.Key, tc.Params)
		encryptor := pastaCipher.NewEncryptor()
		var ciphertext HHELand.Ciphertext

		t.Run("PastaEncryptionTest", func(t *testing.T) {
			ciphertext = encryptor.Encrypt(tc.Plaintext)
			logger.PrintMemUsage("Pasta3EncryptionTest")
		})

		t.Run("PastaDecryptionTest", func(t *testing.T) {
			encryptor.Decrypt(ciphertext)
		})

		t.Run(testString("Pasta", tc.Params), func(t *testing.T) {
			newCiphertext := encryptor.Encrypt(tc.Plaintext)
			newPlaintext := encryptor.Decrypt(newCiphertext)

			if reflect.DeepEqual(tc.Plaintext, newPlaintext) {
				logger.PrintMessage("Got the same plaintext, it is working fine.")
			} else {
				logger.PrintMessage("The plaintext after DEC is different, decryption failure!")
			}
			if reflect.DeepEqual(tc.ExpCipherText, newCiphertext) {
				logger.PrintMessage("Got the same ciphertext, it is working fine.")
			} else {
				logger.PrintMessage("The ciphertext after ENC is different, encryption failure!")
			}
		})
	}
}

func TestPasta4(t *testing.T) {
	logger := utils.NewLogger(utils.DEBUG)
	for _, tc := range pasta4TestVector {
		fmt.Println(testString("PASTA", tc.Params))
		pastaCipher := NewPasta(tc.Key, tc.Params)
		encryptor := pastaCipher.NewEncryptor()
		var ciphertext HHELand.Ciphertext

		t.Run("PastaEncryptionTest", func(t *testing.T) {
			ciphertext = encryptor.Encrypt(tc.Plaintext)
			logger.PrintMemUsage("Pasta4EncryptionTest")
		})

		t.Run("PastaDecryptionTest", func(t *testing.T) {
			encryptor.Decrypt(ciphertext)
		})

		t.Run(testString("Pasta", tc.Params), func(t *testing.T) {
			newCiphertext := encryptor.Encrypt(tc.Plaintext)
			newPlaintext := encryptor.Decrypt(newCiphertext)

			if reflect.DeepEqual(tc.Plaintext, newPlaintext) {
				logger.PrintMessage("Got the same plaintext, it is working fine.")
			} else {
				logger.PrintMessage("The plaintext after DEC is different, decryption failure!")
			}
			if reflect.DeepEqual(tc.ExpCipherText, newCiphertext) {
				logger.PrintMessage("Got the same ciphertext, it is working fine.")
			} else {
				logger.PrintMessage("The ciphertext after ENC is different, encryption failure!")
			}
		})
	}
}

// TestNbPasta3 new benchmarking test for Pasta3
func TestNbPasta3(t *testing.T) {
	t.Run("HHEKombat:Pasta3", func(t *testing.T) {
		utils.PrintHeader("Pasta3 SKE Benchmark")
		// test vectors Pasta3 = {0,1,2}
		tCase := pasta3TestVector[1]

		fmt.Println(testString("Pasta3", tCase.Params))
		pastaCipher := NewPasta(tCase.Key, tCase.Params)
		encryptor := pastaCipher.NewEncryptor()
		println("data len:", len(tCase.Plaintext))

		utils.BenchmarkIter("SKE.Enc()", 100, func() {
			_ = encryptor.Encrypt(tCase.Plaintext)
		})
	})
}

// TestNbPasta4 new benchmarking test for Pasta4
func TestNbPasta4(t *testing.T) {
	t.Run("HHEKombat:Pasta4", func(t *testing.T) {
		utils.PrintHeader("Pasta4 SKE Benchmark")
		// test vectors Pasta4 = {0,1,2}
		tCase := pasta4TestVector[0]

		fmt.Println(testString("Pasta4", tCase.Params))
		pastaCipher := NewPasta(tCase.Key, tCase.Params)
		encryptor := pastaCipher.NewEncryptor()
		println("data len:", len(tCase.Plaintext))

		utils.BenchmarkIter("SKE.Enc()", 100, func() {
			_ = encryptor.Encrypt(tCase.Plaintext)
		})
	})
}
