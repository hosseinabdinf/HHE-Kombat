package cnn_infer

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func Index(slice []int, value int) int {
	for i, v := range slice {
		if v == value {
			return i 
		}
	}
	return -1 
}

func UnitSlice(slice1 []int, slice2 []int) []int {
	for _, rot := range slice2 {
		if Index(slice1, rot) == -1 {
			slice1 = append(slice1, rot)
		}
	}
	return slice1
}

func ResNetCifar10LattigoSparse(layerNum, startImageID, endImageID int) {

	// approximation boundary setting
	B := 40.0;	// approximation boundary
	
	// plain_dnn := false;
	// approx ReLU setting
	alpha := 13		// precision parameter alpha
	comp_no := 3;		// number of compositions
	deg := []int{15,15,27}		// degrees of component polynomials
	scaledVal := 1.7		// scaled_val: the last scaled value
	// double max_factor = 16;		// max_factor = 1 for comparison operation. max_factor > 1 for max or ReLU function
	tree := []*Tree{}		// structure of polynomial evaluation
	evType := oddbaby

	// generate tree
	for i:=0; i<comp_no; i++ {
		tr := Tree{}
		if evType == oddbaby { 
			tr = upgradeOddbaby( deg[i] )  
		} else if evType == baby {
			tr = upgradeBaby( deg[i] )
		} else { panic("evaluation type is not correct") }
		tree = append(tree, &tr)
		// tr.print();
	}

	var outShare *os.File
	var err error

	// Open the file based on layer number
	basePath := "../../cnn_infer/result/"
	filename := basePath + fmt.Sprintf("resnet%d_cifar10_label_%d_%d", layerNum, startImageID, endImageID)
	outShare, err = os.Create(filename)
	if err != nil {
		fmt.Println("Error opening file layer_num is not correct:", err)
		return
	}
	defer outShare.Close()

	endNum := 0		 
	if layerNum == 20 { 
		endNum = 2 // 0 ~ 2
	} else if layerNum == 32 {
		endNum = 4 // 0 ~ 4
	} else if layerNum == 44 {
		endNum = 6	// 0 ~ 6
	} else if layerNum == 56{
		endNum = 8	// 0 ~ 8
	} else if layerNum == 110{
		endNum = 17	// 0 ~ 17
	} else { panic("layer_num is not correct") }	 

	// ********* CKKS Parameter Generator****** Residual Parameters

	LogN := 16
	LogDefaultScale := 42

	q0 := []int{58}                                    // 3) ScaleDown & 4) ModUp
	qiSlotsToCoeffs := []int{42, 42, 42}               // 1) SlotsToCoeffs
	qiCircuitSlots := []int{LogDefaultScale, 42, 42, 42, 42, 42, 42, 42, 42}           // 0) Circuit in the slot domain
	qiEvalMod := []int{58, 58, 58, 58, 58, 58, 58, 58} // 6) EvalMod
	qiCoeffsToSlots := []int{55, 55, 55, 55}           // 5) CoeffsToSlots

	LogQ := append(q0, qiSlotsToCoeffs...)
	LogQ = append(LogQ, qiCircuitSlots...)
	LogQ = append(LogQ, qiEvalMod...)
	LogQ = append(LogQ, qiCoeffsToSlots...)

	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            LogN,                                              // Log2 of the ring degree
		LogQ:            LogQ, // Log2 of the ciphertext prime moduli
		LogP:            []int{59, 59, 60, 60, 60},                                 // Log2 of the key-switch auxiliary prime moduli
		LogDefaultScale: 42,                                                // Log2 of the scale
		Xs:              ring.Ternary{H: 192},
	})
	if err != nil {
		panic(err)
	}

	// CoeffsToSlots parameters (homomorphic encoding)
	CoeffsToSlotsParameters := dft.MatrixLiteral{
		Type:         dft.HomomorphicEncode,
		Format:       dft.RepackImagAsReal, // Returns the real and imaginary part into separate ciphertexts
		LogSlots:     params.LogMaxSlots(),
		LevelQ:       params.MaxLevelQ(),
		LevelP:       params.MaxLevelP(),
		LogBSGSRatio: 1,
		Levels:       []int{1, 1, 1, 1}, //qiCoeffsToSlots
	}

	// Parameters of the homomorphic modular reduction x mod 1
	Mod1ParametersLiteral := mod1.ParametersLiteral{
		LevelQ:          params.MaxLevel() - CoeffsToSlotsParameters.Depth(true),
		LogScale:        58,               // Matches qiEvalMod
		Mod1Type:        mod1.CosDiscrete, // Multi-interval Chebyshev interpolation
		Mod1Degree:      30,               // Depth 5
		DoubleAngle:     3,                // Depth 3
		K:               16,               // With EphemeralSecretWeight = 32 and 2^{15} slots, ensures < 2^{-138.7} failure probability
		LogMessageRatio: 10,               // q/|m| = 2^10
		Mod1InvDegree:   0,                // Depth 0
	}

	// SlotsToCoeffs parameters (homomorphic decoding)
	SlotsToCoeffsParameters := dft.MatrixLiteral{
		Type:         dft.HomomorphicDecode,
		LogSlots:     params.LogMaxSlots(),
		LogBSGSRatio: 1,
		LevelP:       params.MaxLevelP(),
		Levels:       []int{1, 1, 1}, // qiSlotsToCoeffs
	}

	SlotsToCoeffsParameters.LevelQ = len(SlotsToCoeffsParameters.Levels)

	// Custom bootstrapping.Parameters.
	// All fields are public and can be manually instantiated.
	btpParams := bootstrapping.Parameters{
		ResidualParameters:      params,
		BootstrappingParameters: params,
		SlotsToCoeffsParameters: SlotsToCoeffsParameters,
		Mod1ParametersLiteral:   Mod1ParametersLiteral,
		CoeffsToSlotsParameters: CoeffsToSlotsParameters,
		EphemeralSecretWeight:   32, // > 128bit secure for LogN=16 and LogQP = 115.
		CircuitOrder:            bootstrapping.DecodeThenModUp,
	}


	// We print some information about the residual parameters.
	fmt.Printf("Residual parameters: logN=%d, logSlots=%d, H=%d, sigma=%f, logQP=%f, levels=%d, scale=2^%d\n",
		btpParams.ResidualParameters.LogN(),
		btpParams.ResidualParameters.LogMaxSlots(),
		btpParams.ResidualParameters.XsHammingWeight(),
		btpParams.ResidualParameters.Xe(), params.LogQP(),
		btpParams.ResidualParameters.MaxLevel(),
		btpParams.ResidualParameters.LogDefaultScale())

	// And some information about the bootstrapping parameters.
	// We can notably check that the LogQP of the bootstrapping parameters is smaller than 1550, which ensures
	// 128-bit of security as explained above.
	fmt.Printf("Bootstrapping parameters: logN=%d, logSlots=%d, H(%d; %d), sigma=%f, logQP=%f, levels=%d, scale=2^%d\n",
		btpParams.BootstrappingParameters.LogN(),
		btpParams.BootstrappingParameters.LogMaxSlots(),
		btpParams.BootstrappingParameters.XsHammingWeight(),
		btpParams.EphemeralSecretWeight,
		btpParams.BootstrappingParameters.Xe(),
		btpParams.BootstrappingParameters.LogQP(),
		btpParams.BootstrappingParameters.QCount(),
		btpParams.BootstrappingParameters.LogDefaultScale())

	// Scheme context and keys

	fmt.Println()
	fmt.Println("Generating bootstrapping indices...")
	rotations := []int {
		0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,
		// ,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55
		56,
		// ,57,58,59,60,61
		62,63,64,66,84,124,128,132,256,512,959,960,990,991,1008,
		1023,1024,1036,1064,1092,1952,1982,1983,2016,2044,2047,2048,2072,2078,2100,3007,3024,3040,3052,3070,3071,3072,3080,3108,4031,
		4032,4062,4063,4095,4096,5023,5024,5054,5055,5087,5118,5119,5120,6047,6078,6079,6111,6112,6142,6143,6144,7071,7102,7103,7135,
		7166,7167,7168,8095,8126,8127,8159,8190,8191,8192,9149,9183,9184,9213,9215,9216,10173,10207,10208,10237,10239,10240,11197,11231,
		11232,11261,11263,11264,12221,12255,12256,12285,12287,12288,13214,13216,13246,13278,13279,13280,13310,13311,13312,14238,14240,
		14270,14302,14303,14304,14334,14335,15262,15264,15294,15326,15327,15328,15358,15359,15360,16286,16288,16318,16350,16351,16352,
		16382,16383,16384,17311,17375,18335,18399,18432,19359,19423,20383,20447,20480,21405,21406,21437,21469,21470,21471,21501,21504,
		22429,22430,22461,22493,22494,22495,22525,22528,23453,23454,23485,23517,23518,23519,23549,24477,24478,24509,24541,24542,24543,
		24573,24576,25501,25565,25568,25600,26525,26589,26592,26624,27549,27613,27616,27648,28573,28637,28640,28672,29600,29632,29664,
		29696,30624,30656,30688,30720,31648,31680,31712,31743,31744,31774,32636,32640,32644,32672,32702,32704,32706,32735,
		32736,32737,32759,32760,32761,32762,32763,32764,32765,32766,32767,
	}
	galEls := params.GaloisElements(rotations)
	context := genTestParams(params, btpParams, galEls) // generate testContext struc
	// //****************************

	logn := context.params.LogMaxSlots()
	fmt.Println("LogSlots: ", logn)

	Start := time.Now()
	for imageID := startImageID; imageID <=endImageID; imageID++ {

		fmt.Println("image id: ", imageID)
		var output *os.File
		var err error

		// Open the file based on layer number
		basePath := "../../cnn_infer/result/"
		filename := basePath + fmt.Sprintf("resnet%d_cifar10_image_%d.txt", layerNum, imageID)
		output, err = os.Create(filename)
		if err != nil {
			fmt.Println("Error opening file layer_num is not correct:", err)
			return
		}
		defer output.Close() 

		// dir := fmt.Sprintf("resnet%d_new", layerNum)

		cipherPool := make( []*rlwe.Ciphertext, 14 )
		var cnn *TensorCipher
		var temp *TensorCipher
		// deep learning parameters and import
		var co, st int
		fh, fw := 3, 3

		initP := 8
		n := context.params.MaxSlots()
		stage := 0
		epsilon := 0.00001
		var image, linearWeight, linearBias []float64
		var convWeight, bnBias, bnRunningMean, bnRunningVar, bnWeight [][]float64

		fmt.Println("Importing parameters")
		importParametersCifar10(&linearWeight, &linearBias, &convWeight, &bnBias, &bnRunningMean, &bnRunningVar, &bnWeight, layerNum, endNum)

		// Pack images compactly
		var in *os.File
		in, err = os.Open("../../cnn_infer/testFile/test_values.txt")
		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}
		defer in.Close()

		scanner := bufio.NewScanner(in)
		scanner.Split(bufio.ScanWords)
		// Move to the correct image ID
		for i := 0; i < 32*32*3*imageID && scanner.Scan(); i++ { }
		// Set image values to actual values
		image = make([]float64, n)
		for i := 0; i < 32*32*3 && scanner.Scan(); i++ {
			val, _ := strconv.ParseFloat(scanner.Text(), 64)
			image[i] = val
		}

		// Repeat image
		for i := n/initP; i < n; i++ {
			image[i] = image[ i % (n/initP) ]
		}

		// Divide image by B
		for i := 0; i < n; i++ {
			image[i] /= B // For boundary [-1,1]
		}

		// Open the file with image labels
		labelFile, err := os.Open("../../cnn_infer/testFile/test_label.txt")
		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}
		defer labelFile.Close()

		// Read the label for the current image ID
		scanner = bufio.NewScanner(labelFile)
		scanner.Split(bufio.ScanWords)
		var imageLabel int
		for i := 0; i <= imageID && scanner.Scan(); i++ {
			imageLabel, _ = strconv.Atoi(scanner.Text())
		}
		fmt.Println("image label:", imageLabel)

		// Generate CIFAR-10 image
		// Assuming logn, 1, 32, 32, 3, 3, B, image
		// are the correct parameters for NewTensor.
		cnn, _ = NewTensorCipherWithData(logn, 1, 32, 32, 3, 3, initP, image, context )

		fmt.Println("Done generating Tensor")
		// layer 0
		fmt.Println("layer 0")		
		for cnn.cipher.Level() > 5 {
			context.evaluator.DropLevel(cnn.cipher, 1)
		}
		// // debug memorySaveRotate ***************************
		// ctxtRot := cnn.cipher.CopyNew()
		// fmt.Println("before Rot, Step number : ", -1 )
		// printDebug(ctxtRot, context, 7, 7)
		// ctxtRot = memorySaveRotateCipher(ctxtRot, context, 32767 , n)
		// fmt.Println("After Rot")
		// printDebug(ctxtRot, context, 7, 7)
		// // debug memorySaveRotate ***************************
		// panic("Debug Rotate Donen \n\n\n\n")

		cnn, _ = MultiplexedParallelConvolutionCipher(cnn, 16, 1, fh, fw, convWeight[stage], bnRunningVar[stage], bnWeight[stage], epsilon, context, cipherPool, false)
		
		fmt.Println("after convolution")
		printDebug( cnn.cipher, context, 7 ,7 )
		
		cnn, _ = MultiplexedParallelBatchNormCipher(cnn, bnBias[stage], bnRunningMean[stage], bnRunningVar[stage], bnWeight[stage], epsilon, B, context, false)
		fmt.Println("after BN")
		printDebug( cnn.cipher, context, 7 ,7 )

		cnn.cipher, err = context.evaluator.BootstrapReal(cnn.cipher)
		if err != nil {
			panic(err)
		}
		printDebug( cnn.cipher, context, 7 ,7 )

		cnn, _ = ReLU_cipher(cnn, comp_no, deg, alpha, tree, scaledVal, context, context.evaluator)
		fmt.Println("after ReLU_cipher")
		printDebug( cnn.cipher, context, 7 ,7 )


		for j:=0; j<3; j++ {// layer 1_x, 2_x, 3_x
		
			if j==0 { 
				co = 16 
			} else if j==1{
				co = 32 
			} else if j==2 { 
				co = 64
			}
			for k:=0; k<=endNum; k++ 	{// 0 ~ 2/4/6/8/17
				stage = 2*((endNum+1)*j+k)+1 
				fmt.Println("layer: ", stage)

				temp = cnn

				if j>=1 && k==0 {
					st = 2
				} else{
					st = 1
				}
				
				cnn, _ = MultiplexedParallelConvolutionCipher(cnn, co, st, fh, fw, convWeight[stage], bnRunningVar[stage], bnWeight[stage], epsilon, context, cipherPool, false)
				fmt.Println("after convolution layer: ",  stage)
				printDebug( cnn.cipher, context, 7 ,7 )

				cnn, _ = MultiplexedParallelBatchNormCipher(cnn, bnBias[stage], bnRunningMean[stage], bnRunningVar[stage], bnWeight[stage], epsilon, B, context, false)
				fmt.Println("after BN layer: ",  stage)
				printDebug( cnn.cipher, context, 7 ,7 )

				cnn.cipher, err = context.evaluator.BootstrapReal(cnn.cipher)
				if err != nil {
					panic(err)
				}
				fmt.Println("after BTS layer: ",  stage)
				printDebug( cnn.cipher, context, 7 ,7 )

				cnn, _ = ReLU_cipher(cnn, comp_no, deg, alpha, tree, scaledVal, context, context.evaluator)
				fmt.Println("after ReLU_cipher")
				printDebug( cnn.cipher, context, 7 ,7 )

				stage = 2*((endNum+1)*j+k)+2	
				fmt.Println("layer: ", stage)
				st = 1;
				cnn, _ = MultiplexedParallelConvolutionCipher(cnn, co, st, fh, fw, convWeight[stage], bnRunningVar[stage], bnWeight[stage], epsilon, context, cipherPool, false)
				fmt.Println("after convolution layer: ",  stage)
				printDebug( cnn.cipher, context, 7 ,7 )

				cnn, _ = MultiplexedParallelBatchNormCipher(cnn, bnBias[stage], bnRunningMean[stage], bnRunningVar[stage], bnWeight[stage], epsilon, B, context, false)
				fmt.Println("after BN layer: ",  stage)
				printDebug( cnn.cipher, context, 7 ,7 )

				if j>=1 && k==0 {
					temp, _ = multiplexedParallelDownsamplingCipher( temp, context )
					fmt.Println("after Down sample layer: ",  stage)
					printDebug(temp.cipher, context, 7, 7)	
						
				}
				
				cnn, _ = cnnAddCipher(cnn, temp, context)
				fmt.Println("after cnnAddCipher layer: ",  stage)
				printDebug( cnn.cipher, context, 7, 7 )

				cnn.cipher, err = context.evaluator.BootstrapReal(cnn.cipher) 
				if err != nil {
					panic(err)
				}
				fmt.Println("after BTS layer: ",  stage)
				printDebug( cnn.cipher, context, 7 ,7 )
				cnn, _ = ReLU_cipher(cnn, comp_no, deg, alpha, tree, scaledVal, context, context.evaluator)
				fmt.Println("after ReLU_cipher")
				printDebug( cnn.cipher, context, 7 ,7 )
			}

		}

		fmt.Println("layer: ", layerNum-1)

		cnn, _ = averagePoolingCipherScale(cnn, B, context)
		fmt.Println("after averagePoolingCipherScale ")
		printDebug( cnn.cipher, context, 7 ,7 )

		cnn, _ = matrixMultiplicationCipher(cnn, linearWeight, linearBias, 10, 64, context)
		// PrintDebugVec(cnn.vec, 7, 7)
		fmt.Println("after matrixMultiplicationCipher ")
		printDebug( cnn.cipher, context, 7 ,7 )

		rtnVec := make([]float64, context.params.MaxSlots())
		context.encoder.Decode(context.decryptor.DecryptNew(cnn.cipher), rtnVec)
		
		fmt.Println("( ")
		for i:=0; i<10; i++{
			fmt.Println(rtnVec[i])
		}
		fmt.Println(" )")
		

		label := 0
		maxScore := -100.0
		for i:=0; i<10; i++ {
			if maxScore < rtnVec[i] {
				label = i
				maxScore = rtnVec[i]
			}
		}
		fmt.Println("image label: ", imageLabel)
		fmt.Println("inferred label: ", label)
		fmt.Println("max score: ", maxScore)

	}
	elapsed := time.Since(Start) // 计算从start到现在的持续时间
	fmt.Printf("The infer operation took %v\n", elapsed)

}

func printDebug(ciphertext *rlwe.Ciphertext, context *testParams, start, end int) {

	valuesTest := make([]float64, context.params.MaxSlots())
	context.encoder.Decode( context.decryptor.DecryptNew(ciphertext), valuesTest)

	fmt.Println()
	fmt.Printf("Level: %d (logQ = %d)\n", ciphertext.Level(), context.params.LogQLvl(ciphertext.Level()))
	fmt.Printf("Scale: 2^%f\n", ciphertext.LogScale() )
	fmt.Printf("Level: %d\n", ciphertext.Level())
	fmt.Print("ValuesTest: [")
	for _, v := range valuesTest[:start] {
		fmt.Printf("%f ", v )
	}
	fmt.Print("... ")
	for _, v := range valuesTest[len(valuesTest)-end:] {
		fmt.Printf("%f ", v )
	}
	fmt.Println("]")
	// fmt.Println(precStats.String())
	fmt.Println()
}
