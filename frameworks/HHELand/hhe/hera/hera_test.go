package hera

import (
	"fmt"
	"math"
	"testing"

	RtF "HHELand/rtf_integration"
	"HHELand/sym/hera"
	"HHELand/utils"
)

func testString(opName string, p hera.Parameter) string {
	return fmt.Sprintf("%s/BlockSize=%d/Modulus=%d/Rounds=%d",
		opName, p.GetBlockSize(), p.GetModulus(), p.GetRounds())
}

func TestHera(t *testing.T) {
	for _, tc := range hera.TestVector {
		// skip the test for 80-bit security
		if tc.Params.Rounds == 4 {
			// fmt.Println("Skipped: ", testString("HERA", tc.Params))
			continue
		}
		fmt.Println(testString("HERA", tc.Params))
		testHEHera(t, tc)
	}
}

func testHEHera(t *testing.T, tc hera.TestContext) {
	heHera := NewHEHera()
	lg := heHera.logger
	lg.PrintDataLen(tc.Key)

	var data [][]float64
	var nonces [][]byte
	var keyStream [][]uint64

	heHera.InitParams(tc.FVParamIndex, tc.Params)

	heHera.HEKeyGen()
	lg.PrintMemUsage("HEKeyGen")

	heHera.HalfBootKeyGen(tc.Radix)
	lg.PrintMemUsage("HalfBootKeyGen")

	heHera.InitHalfBootstrapper()
	lg.PrintMemUsage("InitHalfBootstrapper")

	heHera.InitEvaluator()
	lg.PrintMemUsage("InitEvaluator")

	heHera.InitCoefficients()
	lg.PrintMemUsage("InitCoefficients")

	if heHera.fullCoefficients {
		data = heHera.RandomDataGen(heHera.params.N())
		lg.PrintMemUsage("RandomDataGen")

		nonces = heHera.NonceGen(heHera.params.N())

		keyStream = make([][]uint64, heHera.params.N())
		symHera := hera.NewHera(tc.Key, tc.Params)
		for i := 0; i < heHera.params.N(); i++ {
			keyStream[i] = symHera.KeyStream(nonces[i])
		}
		lg.PrintMemUsage("SymKeyStreamGen")

		heHera.DataToCoefficients(data, heHera.params.N())
		lg.PrintMemUsage("DataToCoefficients")

		heHera.EncodeEncrypt(keyStream, heHera.params.N())
		lg.PrintMemUsage("EncodeEncrypt")
	} else {
		data = heHera.RandomDataGen(heHera.params.Slots())
		lg.PrintMemUsage("RandomDataGen")

		nonces = heHera.NonceGen(heHera.params.Slots())

		keyStream = make([][]uint64, heHera.params.Slots())
		symHera := hera.NewHera(tc.Key, tc.Params)
		for i := 0; i < heHera.params.Slots(); i++ {
			keyStream[i] = symHera.KeyStream(nonces[i])
		}
		lg.PrintMemUsage("SymKeyStreamGen")

		heHera.DataToCoefficients(data, heHera.params.Slots())
		lg.PrintMemUsage("DataToCoefficients")

		heHera.EncodeEncrypt(keyStream, heHera.params.Slots())
		lg.PrintMemUsage("EncodeEncrypt")
	}

	heHera.ScaleUp()
	lg.PrintMemUsage("ScaleUp")

	_ = heHera.InitFvHera()
	lg.PrintMemUsage("InitFvHera")

	// encrypts symmetric master key using BFV on the client side
	heHera.EncryptSymKey(tc.Key)
	lg.PrintMemUsage("EncryptSymKey")

	// get BFV key stream using encrypted symmetric key, nonce, and counter on the server side
	fvKeyStreams := heHera.GetFvKeyStreams(nonces)
	lg.PrintMemUsage("GetFvKeyStreams")

	heHera.ScaleCiphertext(fvKeyStreams)
	lg.PrintMemUsage("ScaleCiphertext")

	var ctBoot *RtF.Ciphertext
	ctBoot = heHera.HalfBoot()
	lg.PrintMemUsage("HalfBoot")

	valuesWant := make([]complex128, heHera.params.Slots())
	for i := 0; i < heHera.params.Slots(); i++ {
		valuesWant[i] = complex(data[0][i], 0)
	}

	fmt.Println("Precision of HalfBoot(ciphertext)")
	printDebug(heHera.params, ctBoot, valuesWant,
		heHera.ckksDecryptor, heHera.ckksEncoder)
}

// TestNbHera for the new benchmarking
func TestNbHera(t *testing.T) {
	utils.PrintHeader("Hera Transciphering")

	// skip the test for 80-bit security
	// for 128-bit security, you can use {4 -> Mod:28, 5-> Mod:28, 6-> Mod:25, 7-> Mod:25}
	tc := hera.TestVector[6]
	fmt.Println(testString("HERA", tc.Params))

	heHera := NewHEHera()

	var data [][]float64
	var nonces [][]byte
	var keyStream [][]uint64

	heHera.InitParams(tc.FVParamIndex, tc.Params)
	heHera.HEKeyGen()

	heHera.HalfBootKeyGen(tc.Radix)

	heHera.InitHalfBootstrapper()

	heHera.InitEvaluator()

	heHera.InitCoefficients()

	if heHera.fullCoefficients {
		fmt.Println("Full Coefficients")
		data = heHera.RandomDataGen(heHera.params.N())

		nonces = heHera.NonceGen(heHera.params.N())

		keyStream = make([][]uint64, heHera.params.N())
		symHera := hera.NewHera(tc.Key, tc.Params)
		for i := 0; i < heHera.params.N(); i++ {
			keyStream[i] = symHera.KeyStream(nonces[i])
		}

		heHera.DataToCoefficients(data, heHera.params.N())

		heHera.EncodeEncrypt(keyStream, heHera.params.N())
	} else {
		fmt.Println("Full half-Coefficients")
		data = heHera.RandomDataGen(heHera.params.Slots())

		nonces = heHera.NonceGen(heHera.params.Slots())

		keyStream = make([][]uint64, heHera.params.Slots())
		symHera := hera.NewHera(tc.Key, tc.Params)
		for i := 0; i < heHera.params.Slots(); i++ {
			keyStream[i] = symHera.KeyStream(nonces[i])
		}

		heHera.DataToCoefficients(data, heHera.params.Slots())

		heHera.EncodeEncrypt(keyStream, heHera.params.Slots())
	}

	heHera.ScaleUp()

	_ = heHera.InitFvHera()

	// encrypts symmetric master key using BFV on the client side
	heHera.EncryptSymKey(tc.Key)

	// get BFV key stream using encrypted symmetric key, nonce, and counter on the server side
	println("Hera Data length: ", 1<<heHera.params.LogSlots(), ", Log P:", heHera.params.LogP())
	utils.Benchmark("HHE.Decomp()", func() {
		fvKeyStreams := heHera.GetFvKeyStreams(nonces)

		heHera.ScaleCiphertext(fvKeyStreams)

		_ = heHera.HalfBoot()
	})
}

func printDebug(params *RtF.Parameters, ciphertext *RtF.Ciphertext, valuesWant []complex128, decryptor RtF.CKKSDecryptor, encoder RtF.CKKSEncoder) {
	valuesTest := encoder.DecodeComplex(decryptor.DecryptNew(ciphertext), params.LogSlots())
	logSlots := params.LogSlots()
	sigma := params.Sigma()
	fmt.Printf("Level: %d (logQ = %d)\n", ciphertext.Level(), params.LogQLvl(ciphertext.Level()))
	fmt.Printf("Scale: 2^%f\n", math.Log2(ciphertext.Scale()))
	fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	fmt.Printf("ValuesWant: %6.10f %6.10f %6.10f %6.10f...\n", valuesWant[0], valuesWant[1], valuesWant[2], valuesWant[3])
	precisionState := RtF.GetPrecisionStats(params, encoder, nil, valuesWant, valuesTest, logSlots, sigma)
	fmt.Println(precisionState.String())
}
