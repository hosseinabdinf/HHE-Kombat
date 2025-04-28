package ckks_cipher

import (
	"fmt"
	"math"
	"math/bits"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

const DEBUG = false

type RtBCipher struct {
	*bootstrapping.Evaluator
	params         ckks.Parameters
	encoder        *ckks.Encoder
	encryptor      *rlwe.Encryptor
	decryptor      *rlwe.Decryptor
	totalLevel     int
	remainingLevel int
	symmetricKey   []uint8
	keyEncrypted   []*rlwe.Ciphertext
	inputEncrypted []*rlwe.Ciphertext
	encodeCipher   []*rlwe.Ciphertext
}

// NewRtBCipher create a new Real to boolean transcipher helper
func NewRtBCipher(key []uint8, param_ ckks.Parameters, btpParams_ bootstrapping.Parameters, btpKey_ *bootstrapping.EvaluationKeys,
	encoder_ *ckks.Encoder, encryptor_ *rlwe.Encryptor, decryptor_ *rlwe.Decryptor,
) (rtb *RtBCipher, err error) {
	eval, err := bootstrapping.NewEvaluator(btpParams_, btpKey_)
	if err != nil {
		panic("btp in RtBCipher initial failed!")
	}
	rtb = &RtBCipher{
		Evaluator:      eval,
		params:         param_,
		encoder:        encoder_,
		symmetricKey:   key,
		encryptor:      encryptor_,
		decryptor:      decryptor_,
		totalLevel:     param_.MaxLevel(),
		remainingLevel: param_.MaxLevel() - btpParams_.Depth() + btpParams_.SlotsToCoeffsParameters.LevelQ,
		keyEncrypted:   make([]*rlwe.Ciphertext, 0),
		inputEncrypted: make([]*rlwe.Ciphertext, 0),
		encodeCipher:   make([]*rlwe.Ciphertext, 0),
	}
	return rtb, nil
}

func BootstrapCipher(eval *bootstrapping.Evaluator, ct *rlwe.Ciphertext) (ctOut *rlwe.Ciphertext) {
	// for ct.Level() > 1 {
	// 	rtb.DropLevel(ct, 1)
	// }
	// ct.SetScale(math.Exp2(math.Round(math.Log2(ct.Scale())))) // rounds to the nearest power of two
	ctOut, err := eval.Bootstrap(ct)
	if err != nil {
		panic(err)
	}

	return
}

// func BootReEnc( eval *bootstrapping.Evaluator, decryptor rlwe.Decryptor, ct *rlwe.Ciphertext ) *rlwe.Ciphertext {
// 	valuesTest := eval.Decode( decryptor.DecryptNew(ct), eval.LogMaxSlots())
// 	// fmt.Println("BootReEnc debug")
// 	// PrintVectorTrunc(valuesTest, 7, 3)
// 	plainNew := ckks.NewPlaintext( eval.params, eval.remainingLevel )
// 	(*eval.encoder).Encode( valuesTest, plainNew )
// 	rtnCipher := ckks.NewCiphertext( eval.params, 1, plainNew.Level() )
// 	(*eval.encryptor).Encrypt( plainNew, rtnCipher )
// 	return rtnCipher
// }

// PowerOf2 computes op^(2^logPow2), consuming logPow2 levels, and returns the result on opOut. Providing an evaluation
// key is necessary when logPow2 > 1.
func PowerOf2(eval *bootstrapping.Evaluator, op *rlwe.Ciphertext, logPow2 int, opOut *rlwe.Ciphertext) {
	if logPow2 == 0 {
		if op != opOut {
			opOut.Copy(op)
		}
	} else {

		eval.MulRelin(op, op, opOut)

		if err := eval.Rescale(opOut, opOut); err != nil {
			panic(err)
		}

		for i := 1; i < logPow2; i++ {

			eval.MulRelin(opOut, opOut, opOut)

			if err := eval.Rescale(opOut, opOut); err != nil {
				panic(err)
			}
		}
	}
}

// PowerNew computes op^degree, consuming log(degree) levels, and returns the result on a new element. Providing an evaluation
// key is necessary when degree > 2.
func PowerNew(eval *bootstrapping.Evaluator, op *rlwe.Ciphertext, degree int) (opOut *rlwe.Ciphertext) {
	opOut = ckks.NewCiphertext(*eval.GetParameters(), 1, op.Level())
	Power(eval, op, degree, opOut)
	return
}

// Power computes op^degree, consuming log(degree) levels, and returns the result on opOut. Providing an evaluation
// key is necessary when degree > 2.
func Power(eval *bootstrapping.Evaluator, op *rlwe.Ciphertext, degree int, opOut *rlwe.Ciphertext) {
	if degree < 1 {
		panic("eval.Power -> degree cannot be smaller than 1")
	}

	tmpct0 := op.CopyNew()

	var logDegree, po2Degree int

	logDegree = bits.Len64(uint64(degree)) - 1
	po2Degree = 1 << logDegree

	PowerOf2(eval, tmpct0, logDegree, opOut)

	degree -= po2Degree

	for degree > 0 {

		logDegree = bits.Len64(uint64(degree)) - 1
		po2Degree = 1 << logDegree

		tmp := ckks.NewCiphertext(*eval.GetParameters(), 1, tmpct0.Level())

		PowerOf2(eval, tmpct0, logDegree, tmp)

		eval.MulRelin(opOut, tmp, opOut)

		if err := eval.Rescale(opOut, opOut); err != nil {
			panic(err)
		}

		degree -= po2Degree
	}
}

// //boolean function constructed from Heaan using CKKS scheme
func XOR(eval *bootstrapping.Evaluator, ct0, ct1 *rlwe.Ciphertext, ctOut *rlwe.Ciphertext) {
	// (x-y)^2
	eval.Sub(ct0, ct1, ctOut)
	eval.MulRelin(ctOut, ctOut, ctOut)
	eval.Rescale(ctOut, ctOut)
}

// //boolean function constructed from Heaan using CKKS scheme
func XORNew(eval *bootstrapping.Evaluator, ct0, ct1 *rlwe.Ciphertext) (ctOut *rlwe.Ciphertext) {
	// (x-y)^2
	ctOut, err := eval.SubNew(ct0, ct1)
	if err != nil {
		panic(err)
	}
	eval.MulRelin(ctOut, ctOut, ctOut)
	eval.Rescale(ctOut, ctOut)
	return
}

func NOT(eval *bootstrapping.Evaluator, ct0 *rlwe.Ciphertext, ctOut *rlwe.Ciphertext) {
	// (1-x)
	if ct0.Degree() != ctOut.Degree() {
		panic("cannot Negate: invalid receiver Ciphertext does not match input Ciphertext degree")
	}

	for i := range ct0.Value {
		eval.GetParameters().RingQ().AtLevel(i).Neg(ct0.Value[i], ctOut.Value[i])
	}

	eval.SetScale(ctOut, ct0.Scale)
	eval.Add(ctOut, 1.0, ctOut)
}

func NOTNew(eval *bootstrapping.Evaluator, ct0 *rlwe.Ciphertext) (ctOut *rlwe.Ciphertext) {
	// (1-x)
	if ct0.Degree() != ctOut.Degree() {
		panic("cannot Negate: invalid receiver Ciphertext does not match input Ciphertext degree")
	}
	ctOut = ct0.CopyNew()
	NOT(eval, ct0, ctOut)
	return
}

func AND(eval *bootstrapping.Evaluator, ct0, ct1 *rlwe.Ciphertext, ctOut *rlwe.Ciphertext) {
	// xy
	eval.MulRelin(ct0, ct1, ctOut)
	eval.Rescale(ctOut, ctOut)
}

func ANDNew(eval *bootstrapping.Evaluator, ct0, ct1 *rlwe.Ciphertext) (ctOut *rlwe.Ciphertext) {
	// xy
	ctOut, err := eval.MulRelinNew(ct0, ct1)
	if err != nil {
		panic(err)
	}
	eval.Rescale(ctOut, ctOut)
	return
}

func OR(eval *bootstrapping.Evaluator, ct0, ct1 *rlwe.Ciphertext, Out *rlwe.Ciphertext) {
	// x + y - x\cdot y
	eval.MulRelin(ct0, ct1, Out)
	eval.Evaluator.Rescale(Out, Out)
	eval.Sub(ct1, Out, Out)
	eval.Add(Out, ct0, Out)
}

func ORNew(eval *bootstrapping.Evaluator, ct0, ct1 *rlwe.Ciphertext) (ctOut *rlwe.Ciphertext) {
	// x + y - x\cdot y
	ctOut, err := eval.MulRelinNew(ct0, ct1)
	if err != nil {
		panic(err)
	}
	eval.Rescale(ctOut, ctOut)
	eval.Sub(ct1, ctOut, ctOut)
	eval.Add(ctOut, ct0, ctOut)
	return
}

func CleanReal(eval *bootstrapping.Evaluator, ct *rlwe.Ciphertext) {
	squ := PowerNew(eval, ct, 2)
	cube, err := eval.MulRelinNew(squ, ct)
	if err != nil {
		panic(err)
	}
	eval.Rescale(cube, cube)
	// computation of 3x^2-2x^3 which is a rough-but-good-enough approximation of
	// the sign fucntion
	eval.Add(squ, squ, ct)
	eval.Add(squ, ct, ct)
	eval.Sub(ct, cube, ct)
	eval.Sub(ct, cube, ct)
}

func BinaryTreeAdd(eval *bootstrapping.Evaluator, cts []*rlwe.Ciphertext) (ctOut *rlwe.Ciphertext) {
	for j := 1; j < len(cts); j *= 2 {
		for i := 0; i < len(cts); i += 2 * j {
			if i+j < len(cts) {
				eval.Add(cts[i], cts[i+j], cts[i])
			}
		}
	}
	ctOut = cts[0]
	return
}

func ConstructNumberFromBits(eval *bootstrapping.Evaluator, cts []*rlwe.Ciphertext, error int) (ctOut *rlwe.Ciphertext) {
	fmt.Println("Construct bits...")
	ctOut, err := eval.AddNew(cts[0], cts[1])
	if err != nil {
		panic(err)
	}
	eval.Add(ctOut, cts[1], ctOut)

	errorBound := 0.5 * float64(error)
	n := len(cts)
	ctxPool := make([]*rlwe.Ciphertext, 0)
	for i := 2; i < n; i++ {
		if float64(i) < errorBound {
			tmp := math.Pow(2.0, float64(i)/2)
			b, err := eval.MulNew(cts[i], tmp)
			if err != nil {
				panic(err)
			}
			eval.Rescale(b, b)
			Power(eval, b, 2, b)
			if i%2 == 1 {
				eval.Add(b, b, b)
			}
			ctxPool = append(ctxPool, b)
		} else {
			tmp := math.Pow(2.0, float64(i)/4)
			b, err := eval.MulNew(cts[i], tmp)
			if err != nil {
				panic(err)
			}
			eval.Rescale(b, b)
			Power(eval, b, 4, b)
			copyNum := int(math.Pow(2.0, float64(i%4)))
			for j := 0; j < copyNum; j++ {
				ctxPool = append(ctxPool, b)
			}
		}
	}
	sum := BinaryTreeAdd(eval, ctxPool)
	eval.Add(ctOut, sum, ctOut)

	return
}

func (rtb *RtBCipher) DebugPrint(ct *rlwe.Ciphertext, descriptor string) {
	if DEBUG {
		fmt.Printf("Chain Index: %d, Scale: %.2f\n", ct.Level(), ct.LogScale())
		valuesTest := make([]float64, ct.Slots())
		if err := rtb.Decode(rtb.decryptor.DecryptNew(ct), valuesTest); err != nil {
			panic(err)
		}
		fmt.Println(descriptor)
		PrintVectorTrunc(valuesTest, 7, 4)
	}
}

// PrintVectorTrunc prints a truncated version of the vector.
func PrintVectorTrunc(vec interface{}, printSize, prec int) {
	if DEBUG {
		switch v := vec.(type) {
		case []complex128:
			printComplexVectorTrunc(v, printSize, prec)
		case []float64:
			printFloatVectorTrunc(v, printSize, prec)
		default:
			fmt.Println("Unsupported type")
		}
		fmt.Println()
	}
}

// extractComponents extracts the real and imaginary parts of a complex number.
func extractComponents(value complex128) (float64, float64) {
	return real(value), imag(value)
}

// getDelimiter returns the appropriate delimiter for the print output.
func getDelimiter(i, maxIndex int) string {
	if i != maxIndex {
		return ", "
	}
	return " ]\n"
}

// printComplexVectorTrunc prints a truncated version of a complex vector.
func printComplexVectorTrunc(v []complex128, printSize, prec int) {
	lenV := len(v)
	if lenV <= 2*printSize {
		fmt.Printf("[")
		for i, value := range v {
			cReal, cImag := extractComponents(value)
			fmt.Printf(" (%.*f,+ %.*fi)%s", prec, cReal, prec, cImag, getDelimiter(i, lenV-1))
		}
	} else {
		fmt.Printf("[")
		for i := 0; i < printSize; i++ {
			cReal, cImag := extractComponents(v[i])
			fmt.Printf(" (%.*f+%.*fi)%s", prec, cReal, prec, cImag, getDelimiter(i, printSize-1))
		}
		fmt.Printf(" ... ")
		for i := lenV - printSize; i < lenV; i++ {
			cReal, cImag := extractComponents(v[i])
			fmt.Printf(" (%.*f+%.*fi)%s", prec, cReal, prec, cImag, getDelimiter(i, lenV-1))
		}
	}
}

// printFloatVectorTrunc prints a truncated version of a float vector.
func printFloatVectorTrunc(v []float64, printSize, prec int) {
	lenV := len(v)
	if lenV <= 2*printSize {
		fmt.Printf("[")
		for i, value := range v {
			fmt.Printf(" %.*f%s", prec, value, getDelimiter(i, lenV-1))
		}
	} else {
		fmt.Printf("[")
		for i := 0; i < printSize; i++ {
			fmt.Printf(" %.*f%s", prec, v[i], getDelimiter(i, printSize-1))
		}
		fmt.Printf(" ...")
		for i := lenV - printSize; i < lenV; i++ {
			fmt.Printf(" %.*f%s", prec, v[i], getDelimiter(i, lenV-1))
		}
	}
}
