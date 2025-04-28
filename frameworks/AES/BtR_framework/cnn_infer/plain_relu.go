package cnn_infer

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

func add_(a, b []float64) ([]float64, error) {
	if len(a) != len(b) {
		return nil, errors.New("add - len(a) != len(b)")
	}
	out := make([]float64, len(a))
	for i := range a {
		out[i] = a[i] + b[i]
	}
	return out, nil
}

func multiply_(a, b []float64) ([]float64, error) {
	if len(a) != len(b) {
		return nil, errors.New("mul - len(a) != len(b)")
	}
	out := make([]float64, len(a))
	for i := range a {
		out[i] = a[i] * b[i]
	}
	return out, nil
}

func minimax_ReLU_plain(compNo int, deg []int, alpha int, trees []*Tree, scaledVal float64, scalingFactor int, plainIn []float64) ([]float64, error) {
	decompCoeff := make([][]float64, compNo)
	scaleVal := make([]float64, compNo)

	var temp, half, x []float64
	scaleVal[0] = 1.0
	for i := 1; i < compNo; i++ {
		scaleVal[i] = 2.0
	}
	scaleVal[compNo-1] = scaledVal
	
	addr := "../../cnn_infer/result/"
	filePath := addr + "d" + strconv.Itoa(alpha) + ".txt"
	data, err := os.ReadFile(filePath) 
	if err != nil {
		return nil, err
	}
	coeffStrings := strings.Fields(string(data))
	coeffIdx := 0
	for i := range decompCoeff {
		decompCoeff[i] = make([]float64, 0)
		for j := 0; j < coeffNumber(deg[i], trees[i]); j++ {
			coeff, convErr := strconv.ParseFloat(coeffStrings[coeffIdx], 64)
			if convErr != nil {
				return nil, convErr
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
	n := len(plainIn)
	mHalf := make([]float64, n)
	for i := range mHalf {
		mHalf[i] = 0.5
	}
	// generation of half ciphertext
	// long n = cipher_in.poly_modulus_degree()/2;
	x = make([]float64, len(plainIn))
	copy(x, plainIn)

	for i := 0; i < compNo; i++ {
		// fmt.Println("in poly evaluate\n",i)
		x, _ = evalPolynomialIntegrate( x, deg[i], decompCoeff[i], trees[i])
	}
	// 计算 ReLU
	half = mHalf
	temp, err = add_(x, half)
	if err != nil {
		return nil, err
	}
	res, err := multiply_(temp, plainIn)
	if err != nil {
		return nil, err
	}
	return res, nil
}