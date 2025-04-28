package main

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/cnn_infer"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func main() {
//     //2 Example run: import CIFAR-10 parameters for ResNet-20
	cnn_infer.ResNetCifar10Sparse(20, 0, 0)
	// ResNetCifar10Sparse
	// cnn_infer.ResNetCifar10LattigoSparse(20, 1, 1)
	// cnn_infer.ResNetCifar10RtfHeraInfer(20, 0, 0, "80f", 4, 0, 2, true)
	// cnn_infer.ResNetCifar10RtfRubatoInfer(20, 0, 0, "Param0", ckks.RUBATO128S)
	// func ResNetCifar10RtfHeraInfer(layerNum, startImageID, endImageID int, name string, numRound int, paramIndex int, radix int, fullCoeffs bool) {
}

func printDebug(params ckks.Parameters, ciphertext *rlwe.Ciphertext, valuesWant []complex128, decryptor *rlwe.Decryptor, encoder *ckks.Encoder) (valuesTest []float64) {

	valuesTest = make([]float64, params.MaxSlots())
	encoder.Decode(decryptor.DecryptNew(ciphertext), valuesTest)

	fmt.Println()
	fmt.Printf("Level: %d (logQ = %d)\n", ciphertext.Level(), params.LogQLvl(ciphertext.Level()))
	fmt.Printf("Scale: 2^%f\n", ciphertext.LogScale() )
	fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	fmt.Printf("ValuesWant: %6.10f %6.10f %6.10f %6.10f...\n", valuesWant[0], valuesWant[1], valuesWant[2], valuesWant[3])

	precStats := ckks.GetPrecisionStats(params, encoder, nil, valuesWant, valuesTest, 7, true)

	fmt.Println(precStats.String())
	fmt.Println()

	return
}
