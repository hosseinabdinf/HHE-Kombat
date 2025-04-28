package cnn_infer

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
)


func ResNetCifar10Sparse( layerNum, startImageID, endImageID int){
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
	// tree[0].Print()
	// dat := []float64{}

	// for i:=0;i<8*8;i++{
	// 	if i<8*4 {dat = append(dat, -0.99)} else {dat = append(dat, 0.67)}
	// }

	// res, _ := minimax_ReLU_plain(3, deg, alpha, tree, scaledVal, 42, dat)
	// fmt.Println("f",res)

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
	// boundary_K := 25
	// bootDeg := 59
	// scaleFactor := 2
	// inverseDeg := 1 
	// logN := 16
	// loge := 10 
	logn := 15		// full slots
	// logn_1 := 14	// sparse slots
	// logn_2 := 13
	// logn_3 := 12
	logp := 46
	// logq := 51
	// logSpecialPrime := 51
	// logIntegerPart := logq - logp - loge + 5
	// remainingLevel := 16 // Calculation required
	// bootLevel := 14 // 
	// totalLevel := remaining_level + boot_level

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



	// #pragma omp parallel for num_threads(1)
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
			// SEAL and bootstrapping setting



		// dir := fmt.Sprintf("resnet%d_new", layerNum)

		pool := make( [][]float64, 14 )
		for i := 0; i < 14; i++{
			pool[i] = make([]float64, 1<<logn)
		}

		var cnn, temp Tensor

		// deep learning parameters and import
		co, st, fh, fw := 0, 0, 3, 3
		
		initP := 8
		n := 1<<logn
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
		cnn, _ = NewTensorWithParams(logn, 1, 32, 32, 3, 3, initP, image)
		fmt.Println("Done generating Tensor")
		// layer 0
		fmt.Println("layer 0")
		fmt.Println("Before MPConv")
		PrintDebugVec(cnn.vec, 7, 7)
		cnn, _ = MultiplexedParallelConvolutionPlain(cnn, 16, 1, fh, fw, convWeight[stage], bnRunningVar[stage], bnWeight[stage], epsilon, pool, false)
		fmt.Println("After MPConv")
		PrintDebugVec(cnn.vec, 7, 7)
		cnn, _ = MultiplexedParallelBatchNormPlain(cnn, bnBias[stage], bnRunningMean[stage], bnRunningVar[stage], bnWeight[stage], epsilon, B, false)
		fmt.Println("After BN")
		PrintDebugVec(cnn.vec, 7, 7)
		cnn, _ = ReLU_plain(cnn, comp_no, deg, alpha, tree, scaledVal, logp, B)
		fmt.Println("After ReLu")
		PrintDebugVec(cnn.vec, 7, 7)
		// panic("done")
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
				cnn, _ = MultiplexedParallelConvolutionPlain(cnn, co, st, fh, fw, convWeight[stage], bnRunningVar[stage], bnWeight[stage], epsilon, pool, false)
				fmt.Println("After Conv")
				PrintDebugVec(cnn.vec, 7, 7)
				cnn, _ = MultiplexedParallelBatchNormPlain(cnn, bnBias[stage], bnRunningMean[stage], bnRunningVar[stage], bnWeight[stage], epsilon, B, false)
				fmt.Println("After BN")
				PrintDebugVec(cnn.vec, 7, 7)

				cnn, _ = ReLU_plain(cnn, comp_no, deg, alpha, tree, scaledVal, logp, B)
				// if(j==0) bootstrap_print(cnn, cnn, bootstrapper_1, output, decryptor, encoder, context, stage);
				// else if(j==1) bootstrap_print(cnn, cnn, bootstrapper_2, output, decryptor, encoder, context, stage);
				// else if(j==2) bootstrap_print(cnn, cnn, bootstrapper_3, output, decryptor, encoder, context, stage);
				fmt.Println("After ReLu")
				PrintDebugVec(cnn.vec, 7, 7)
				stage = 2*((endNum+1)*j+k)+2
				fmt.Println("layer: ", stage)
				st = 1;
				cnn, _ = MultiplexedParallelConvolutionPlain(cnn, co, st, fh, fw, convWeight[stage], bnRunningVar[stage], bnWeight[stage], epsilon, pool, false)
				fmt.Println("After MPConv")
				PrintDebugVec(cnn.vec, 7, 7)

				cnn, _ = MultiplexedParallelBatchNormPlain(cnn, bnBias[stage], bnRunningMean[stage], bnRunningVar[stage], bnWeight[stage], epsilon, B, false)
				fmt.Println("After BN")
				PrintDebugVec(cnn.vec, 7, 7)
				if j>=1 && k==0 {
					temp, _ = multiplexedParallelDownsamplingPlain( temp )
					fmt.Println("After DownSampl")
					PrintDebugVec(cnn.vec, 7, 7)
				}

				cnn, _ = cnnAddPlain(cnn, temp)
				fmt.Println("After ADD Plain")
				PrintDebugVec(cnn.vec, 7, 7)
				// if(j==0) bootstrap_print(cnn, cnn, bootstrapper_1, output, decryptor, encoder, context, stage);
				// else if(j==1) bootstrap_print(cnn, cnn, bootstrapper_2, output, decryptor, encoder, context, stage);
				// else if(j==2) bootstrap_print(cnn, cnn, bootstrapper_3, output, decryptor, encoder, context, stage);
				cnn, _ = ReLU_plain(cnn, comp_no, deg, alpha, tree, scaledVal, logp, B)
				fmt.Println("After ReLu")
				PrintDebugVec(cnn.vec, 7, 7)
			}
		}


		fmt.Println("layer: ", layerNum-1)

		cnn, _ = averagePoolingPlainScale(cnn, B)
		fmt.Println("After average Pool")
		PrintDebugVec(cnn.vec, 7, 7)
		cnn, _ = matrixMultiplicationPlain(cnn, linearWeight, linearBias, 10, 64)
		fmt.Println("After Full connect")
		PrintDebugVec(cnn.vec, 7, 7)

		rtnVec := cnn.vec
		fmt.Println("( ", cnn.vec[:9], " )")

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


}

