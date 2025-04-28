package cnn_infer

import (
	"os"
	"strconv"
	"strings"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func minimax_ReLU_cipher(compNo int, deg []int, alpha int, trees []*Tree, scaledVal float64, context *testParams, cipherIn *rlwe.Ciphertext) ( ctOut *rlwe.Ciphertext ) {
	decompCoeff := make([][]float64, compNo)
	scaleVal := make([]float64, compNo)

	var tempCipher, xCipher *rlwe.Ciphertext

	scaleVal[0] = 1.0
	for i := 1; i < compNo; i++ {
		scaleVal[i] = 2.0
	}
	scaleVal[compNo-1] = scaledVal

	addr := "../../cnn_infer/result/"
	filePath := addr + "d" + strconv.Itoa(alpha) + ".txt"
	data, err := os.ReadFile(filePath)
	if err != nil {
		panic("Read Approximation ReLU Coefficient failed!\n")
	}

	coeffStrings := strings.Fields(string(data))
	coeffIdx := 0
	for i := range decompCoeff {
		decompCoeff[i] = make([]float64, 0)
		for j := 0; j < coeffNumber(deg[i], trees[i]); j++ {
			coeff, convErr := strconv.ParseFloat(coeffStrings[coeffIdx], 64)
			if convErr != nil {
				panic("Read coefficient from file failed!\n")
			}
			decompCoeff[i] = append(decompCoeff[i], coeff)
			coeffIdx++
		}
	}

	// scale coefficients properly so that unnecessary level consumptions do not occur
	for i := 0; i < compNo-1; i++ {
		for j := range decompCoeff[i] {
			decompCoeff[i][j] /= scaleVal[i+1]
		}
	}
	for j := range decompCoeff[compNo-1] {
		decompCoeff[compNo-1][j] *= 0.5
	}

	n := context.params.MaxSlots()

	mHalf := make([]float64, n)
	for i := range mHalf {
		mHalf[i] = 0.5
	}
	// generation of half ciphertext
	// long n = cipher_in.poly_modulus_degree()/2;
	xCipher = cipherIn

	for i := 0; i < compNo-1; i++ {
		// fmt.Println("in poly evaluate\n",i)
		xCipher = evalPolynomialIntegrateCipher( xCipher, deg[i], decompCoeff[i], trees[i], context)
		// printDebug(xCipher, context, 7, 7)
	}
	xCipher, err = context.evaluator.BootstrapReal(xCipher)
	if err != nil {
		panic(err)
	}
	printDebug(xCipher, context, 7, 7)

	xCipher = evalPolynomialIntegrateCipher( xCipher, deg[compNo-1], decompCoeff[compNo-1], trees[compNo-1], context)

	// x(1+sgn(x))/2 from sgn(x)/2
	tempCipher, err = context.evaluator.AddNew(xCipher, mHalf )
	if err != nil {
		panic(err)
	}
	ctOut, err = context.evaluator.MulRelinNew(cipherIn, tempCipher)
	if err != nil {
		panic(err)
	}
	context.evaluator.Rescale(ctOut, ctOut)
	
	return
}