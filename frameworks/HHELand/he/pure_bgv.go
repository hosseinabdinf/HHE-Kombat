package he

import (
	"HHELand/utils"
	"fmt"
	"math/rand"
	"slices"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func PureBgv(paramsLiteral bgv.ParametersLiteral) {
	var err error
	var params bgv.Parameters
	// 128-bit secure parameters enabling depth-7 circuits.
	// LogN:14, LogQP: 431.
	params, err = bgv.NewParametersFromLiteral(paramsLiteral)
	utils.HandleError(err)

	printBgvParams(params)
	// Key Generator
	kgen := rlwe.NewKeyGenerator(params)

	// Secret Key
	sk := kgen.GenSecretKeyNew()

	// Encoder
	ecd := bgv.NewEncoder(params)

	rlk := rlwe.NewRelinearizationKey(params)
	evk := rlwe.NewMemEvaluationKeySet(rlk)
	evl := bgv.NewEvaluator(params, evk, false)
	// Encryptor
	enc := rlwe.NewEncryptor(params, sk)

	// Decryptor
	dec := rlwe.NewDecryptor(params, sk)

	// Vector of plaintext values
	xValuse := make([]uint64, params.MaxSlots())
	aValues := make([]uint64, params.MaxSlots())
	bValuse := make([]uint64, params.MaxSlots())

	// Source for sampling random plaintext values (not cryptographically secure)
	/* #nosec G404 */
	r := rand.New(rand.NewSource(0))

	// Populates the vector of plaintext values
	T := params.PlaintextModulus()
	for i := range xValuse {
		xValuse[i] = r.Uint64() % T
		aValues[i] = r.Uint64() % T
		bValuse[i] = r.Uint64() % T
	}

	// Allocates a plaintext at the max level.
	// Default rlwe.MetaData:
	// - IsBatched = true (slots encoding)
	// - Scale = params.DefaultScale()
	xPt := bgv.NewPlaintext(params, params.MaxLevel())
	aPt := bgv.NewPlaintext(params, params.MaxLevel())
	bPt := bgv.NewPlaintext(params, params.MaxLevel())

	// Encodes the vector of plaintext values
	err = ecd.Encode(xValuse, xPt)
	utils.HandleError(err)

	err = ecd.Encode(aValues, aPt)
	utils.HandleError(err)

	err = ecd.Encode(bValuse, bPt)
	utils.HandleError(err)

	// Encrypts the vector of plaintext values
	var xCt, aCt, bCt, axCt, resCt *rlwe.Ciphertext

	fmt.Println("Params: ", params.LogP())
	utils.PrintHeader("Linear Regression BGV")
	println(
		"Data Size: ", xPt.BinarySize()*8,
		"bits, Size/Slots = ", (xPt.BinarySize()*8)/xPt.Slots(), "bits")
	utils.BenchmarkIter("HE.Enc()", 100, func() {
		_, err = enc.EncryptNew(xPt)
	})

	xCt, err = enc.EncryptNew(xPt)
	utils.HandleError(err)
	aCt, err = enc.EncryptNew(aPt)
	utils.HandleError(err)
	bCt, err = enc.EncryptNew(bPt)
	utils.HandleError(err)

	// res = ax + b
	utils.BenchmarkIter("HE.Eval() = ax+b", 100, func() {
		_, err := evl.MulNew(aCt, xCt)
		utils.HandleError(err)
		_, err = evl.AddNew(xCt, bCt)
		utils.HandleError(err)
	})

	axCt, err = evl.MulNew(aCt, xCt)
	utils.HandleError(err)
	resCt, err = evl.AddNew(axCt, bCt)
	utils.HandleError(err)

	// Allocates a vector for the reference values
	want := make([]uint64, params.MaxSlots())
	copy(want, linReg(xValuse, aValues, bValuse, T))

	PrintBgvPrecisionStats(params, resCt, want, ecd, dec)
}

// PrintBgvPrecisionStats decrypts, decodes and prints the precision stats of a ciphertext.
func PrintBgvPrecisionStats(params bgv.Parameters, ct *rlwe.Ciphertext, want []uint64, ecd *bgv.Encoder, dec *rlwe.Decryptor) {

	var err error

	// Decrypts the vector of plaintext values
	pt := dec.DecryptNew(ct)

	// Decodes the plaintext
	have := make([]uint64, params.MaxSlots())
	if err = ecd.Decode(pt, have); err != nil {
		panic(err)
	}

	// Pretty prints some values
	fmt.Printf("Have: ")
	for i := 0; i < 4; i++ {
		fmt.Printf("%d ", have[i])
	}
	fmt.Printf("...\n")

	fmt.Printf("Want: ")
	for i := 0; i < 4; i++ {
		fmt.Printf("%d ", want[i])
	}
	fmt.Printf("...\n")

	if !slices.Equal(want, have) {
		panic("wrong result: bad decryption or encrypted/plaintext circuits do not match")
	}
}

func printBgvParams(params bgv.Parameters) {
	println(
		"Params (logN=", params.LogN(),
		", logP=", params.LogP(),
		", logQ=", params.LogQ(),
		", Max Slots=", params.MaxSlots(),
		", Max Level=", params.MaxLevel(),
		", Default Scale=", params.DefaultScale().Float64())
}

// linReg res = ax + b
func linReg(x, a, b []uint64, t uint64) (res []uint64) {
	res = make([]uint64, len(x))
	for i := 0; i < len(x); i++ {
		res[i] = (a[i]*x[i] + b[i]) % t
	}
	return res
}
