package he

import (
	"fmt"
	"math"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/utils/bignum"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"

	"HHELand/utils"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/polynomial"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// PureCKKS for a simple encryption and multiplication
func PureCKKS(paramsLiteral ckks.ParametersLiteral) {
	var err error
	// ================================================================
	// user side
	// initialize the ckks scheme requirements with default parameters
	params, err := ckks.NewParametersFromLiteral(paramsLiteral)
	utils.HandleError(err)

	printParams(params)

	keygen := rlwe.NewKeyGenerator(params)

	sk := keygen.GenSecretKeyNew()

	ecd := ckks.NewEncoder(params)

	enc := ckks.NewEncryptor(params, sk)

	dec := ckks.NewDecryptor(params, sk)

	rlk := keygen.GenRelinearizationKeyNew(sk)

	evk := rlwe.NewMemEvaluationKeySet(rlk)

	evl := ckks.NewEvaluator(params, evk)

	//make random plaintext data
	xPt := ckks.NewPlaintext(params, params.MaxLevel())
	aPt := ckks.NewPlaintext(params, params.MaxLevel())
	bPt := ckks.NewPlaintext(params, params.MaxLevel())

	xData := generateRandomData(20.0, params)
	err = ecd.Encode(xData, xPt)
	utils.HandleError(err)

	aData := generateRandomData(1.0, params)
	err = ecd.Encode(aData, aPt)
	utils.HandleError(err)

	bData := generateRandomData(5.0, params)
	err = ecd.Encode(bData, bPt)
	utils.HandleError(err)

	utils.PrintHeader("Pure CKKS Encryption")

	println(
		"Data Size: ", xPt.BinarySize()*8,
		"bits, Size/Slots = ", (xPt.BinarySize()*8)/xPt.Slots(), "bits")

	utils.BenchmarkIter("HE.Enc()", 100, func() {
		_, err = enc.EncryptNew(aPt)
	})

	// HE Encryption
	xCt, err := enc.EncryptNew(xPt)
	utils.HandleError(err)
	aCt, err := enc.EncryptNew(aPt)
	utils.HandleError(err)
	bCt, err := enc.EncryptNew(bPt)
	utils.HandleError(err)

	utils.BenchmarkIter("HE.Eval() = ax+b", 100, func() {
		axCt, err := evl.MulNew(aCt, xCt)
		utils.HandleError(err)
		_, err = evl.AddNew(axCt, bCt)
		utils.HandleError(err)
	})

	axCt, err := evl.MulNew(aCt, bCt)
	utils.HandleError(err)
	res, err := evl.AddNew(axCt, bCt)
	noise, _, _ := rlwe.Norm(res, dec)
	println("--> STD(noise):", noise)
}

func printParams(params ckks.Parameters) {
	println(
		"Params (logN=", params.LogN(),
		", logP=", params.LogP(),
		", logQ=", params.LogQ(),
		", Max Slots=", params.MaxSlots(),
		", Max Level=", params.MaxLevel(),
		", Default Scale=", params.DefaultScale().Float64())
}

func generateRandomData(k float64, params ckks.Parameters) (data []float64) {
	data = make([]float64, params.MaxSlots())
	for i := range data {
		data[i] = sampling.RandFloat64(-k, k)
	}
	return data
}

func ChebyshevCKKS(paramsLiteral ckks.ParametersLiteral) {
	var err error
	var params ckks.Parameters

	params, err = ckks.NewParametersFromLiteral(paramsLiteral)
	utils.HandleError(err)

	printParams(params)

	// Key Generator
	kgen := rlwe.NewKeyGenerator(params)

	// Secret Key
	sk := kgen.GenSecretKeyNew()

	// Encoder
	ecd := ckks.NewEncoder(params)

	// Encryptor
	enc := rlwe.NewEncryptor(params, sk)

	// Decryptor
	dec := rlwe.NewDecryptor(params, sk)

	// Relinearization Key
	rlk := kgen.GenRelinearizationKeyNew(sk)

	// Evaluation Key Set with the Relinearization Key
	evk := rlwe.NewMemEvaluationKeySet(rlk)

	// Evaluator
	eval := ckks.NewEvaluator(params, evk)

	// Samples values in [-K, K]
	K := 25.0

	// Allocates a plaintext at the max level.
	pt := ckks.NewPlaintext(params, params.MaxLevel())

	// Populates the vector of plaintext values
	values := generateRandomData(K, params)

	// Encodes the vector of plaintext values
	err = ecd.Encode(values, pt)
	utils.HandleError(err)

	// Encrypts the vector of plaintext values
	var ct *rlwe.Ciphertext
	ct, err = enc.EncryptNew(pt)
	utils.HandleError(err)

	utils.PrintHeader("Chebyshev CKKS")
	println(
		"Data Size: ", pt.BinarySize()*8,
		"bits, Size/Slots = ", (pt.BinarySize()*8)/pt.Slots(), "bits")

	utils.BenchmarkIter("HE.Enc()", 100, func() {
		_, err = enc.EncryptNew(pt)
	})

	sigmoid := func(x float64) (y float64) {
		return 1 / (math.Exp(-x) + 1)
	}

	// Chebyshev approximation of the sigmoid in the domain [-K, K] of degree 63.
	poly := polynomial.NewPolynomial(GetChebyshevPoly(K, 63, sigmoid))

	// Instantiates the polynomial evaluator
	polyEval := polynomial.NewEvaluator(params, eval)

	// Retrieves the change of basis y = scalar * x + constant
	scalar, constant := poly.ChangeOfBasis()

	// Perform the change of basis Standard -> Chebyshev
	utils.BenchmarkIter("Chebyshev HHE.Eval()", 1, func() {
		err = eval.Mul(ct, scalar, ct)
		utils.HandleError(err)

		err = eval.Add(ct, constant, ct)
		utils.HandleError(err)

		err = eval.Rescale(ct, ct)
		utils.HandleError(err)

		// Evaluates the polynomial
		ct, err = polyEval.Evaluate(ct, poly, params.DefaultScale())
		utils.HandleError(err)
	})

	// Allocates a vector for the reference values and
	// evaluates the same circuit on the plaintext values
	want := make([]float64, ct.Slots())
	for i := range want {
		want[i], _ = poly.Evaluate(values[i])[0].Float64()
		//want[i] = sigmoid(values[i])
	}

	// Decrypts and print the stats about the precision.
	PrintPrecisionStats(params, ct, want, ecd, dec)
}

// GetChebyshevPoly returns the Chebyshev polynomial approximation of f the
// in the interval [-K, K] for the given degree.
func GetChebyshevPoly(K float64, degree int, f64 func(x float64) (y float64)) bignum.Polynomial {

	FBig := func(x *big.Float) (y *big.Float) {
		xF64, _ := x.Float64()
		return new(big.Float).SetPrec(x.Prec()).SetFloat64(f64(xF64))
	}

	var prec uint = 128

	interval := bignum.Interval{
		A:     *bignum.NewFloat(-K, prec),
		B:     *bignum.NewFloat(K, prec),
		Nodes: degree,
	}

	// Returns the polynomial.
	return bignum.ChebyshevApproximation(FBig, interval)
}

// PrintPrecisionStats decrypts, decodes and prints the precision stats of a ciphertext.
func PrintPrecisionStats(params ckks.Parameters, ct *rlwe.Ciphertext, want []float64, ecd *ckks.Encoder, dec *rlwe.Decryptor) {

	var err error

	// Decrypts the vector of plaintext values
	pt := dec.DecryptNew(ct)

	// Decodes the plaintext
	have := make([]float64, ct.Slots())
	if err = ecd.Decode(pt, have); err != nil {
		panic(err)
	}

	// Pretty prints some values
	fmt.Printf("Have: ")
	for i := 0; i < 4; i++ {
		fmt.Printf("%20.15f ", have[i])
	}
	fmt.Printf("...\n")

	fmt.Printf("Want: ")
	for i := 0; i < 4; i++ {
		fmt.Printf("%20.15f ", want[i])
	}
	fmt.Printf("...\n")

	// Pretty prints the precision stats
	fmt.Println(ckks.GetPrecisionStats(params, ecd, dec, have, want, 0, false).String())
}
