package cnn_infer

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func check(err error) {
    if err != nil {
        panic(err)
    }
}

func PrintDebugVec(  values interface{}, start, end int ) error {

	switch values := values.(type) {
	case []float64:
		if start > len(values) || end > len(values) {
			panic("Print element size is larger than vector size!")
		}
		starIDX := len( values ) - end
		fmt.Println( values[:start],"  ...  ", values[starIDX:])
	case []complex128:
		if start > len(values) || end > len(values) {
			panic("Print element size is larger than vector size!")
		}
		starIDX := len( values ) - end
		fmt.Println( values[:start],"  ...  ", values[starIDX:])
	}
	return nil
}

// Similar to C++'s ifsteam >> val;
func readDouble(scanner *bufio.Scanner) (float64, error) {
    if !scanner.Scan() {
        return 0, fmt.Errorf("failed to read value")
    }
    return strconv.ParseFloat(strings.TrimSpace(scanner.Text()), 64)
}

// Auxiliary function to read parameters from file into provided slice
func readParameterIntoSlice(fileName string, numValues int, target *[]float64) {
	file, err := os.Open(fileName)
	check(err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for i := 0; i < numValues; i++ {
		val, err := readDouble(scanner)
		check(err)
		*target = append(*target, val)
	}
}

func importParametersCifar10( linearWeight, linearBias *[]float64, convWeight, bnBias, bnRunningMean, bnRunningVar, bnWeight *[][]float64, layerNum, endNum int) { // Simplified version
    dirs := map[int]string{
        20: "resnet20_new",
        32: "resnet32_new",
        44: "resnet44_new",
        56: "resnet56_new",
        110: "resnet110_new",
    }

    if _, ok := dirs[layerNum]; !ok {
        panic("layer number is not valid")
    }
    dir := dirs[layerNum]

    numC, numB, numM, numV, numW := 0, 0, 0, 0, 0

    fh, fw, ci, co := 3, 3, 3, 16

    *convWeight = make([][]float64, layerNum-1)
    *bnBias = make([][]float64, layerNum-1)
    *bnRunningMean = make([][]float64, layerNum-1)
    *bnRunningVar = make([][]float64, layerNum-1)
    *bnWeight = make([][]float64, layerNum-1)

    fileName := fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/conv1_weight.txt", dir)
	readParameterIntoSlice(fileName, fh*fw*ci*co, &((*convWeight)[numC]) )
    numC++

	// 遍历 3 个 block
	for j := 1; j <= 3; j++ {
		for k := 0; k <= endNum; k++ {
			// co setting 根据当前的 j 来设置 co
			if j == 1 {
				co = 16
			} else if j == 2 {
				co = 32
			} else if j == 3 {
				co = 64
			}

			// ci setting 根据 j 和 k 设置 ci
			if j == 1 || (j == 2 && k == 0) {
				ci = 16
			} else if (j == 2 && k != 0) || (j == 3 && k == 0) {
				ci = 32
			} else {
				ci = 64
			}
			fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer%d_%d_conv1_weight.txt", dir, j, k)
			readParameterIntoSlice(fileName, fh*fw*ci*co, &((*convWeight)[numC]) )
			numC++

			if j==1{
				ci = 16
			} else if(j==2){
				ci = 32
			} else if(j==3){
				ci = 64
			}
			fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer%d_%d_conv2_weight.txt", dir, j, k)
			readParameterIntoSlice(fileName, fh*fw*ci*co, &((*convWeight)[numC]) )
			numC++
		}
	}	
    
	// batch normalization parameters ci设定
	ci = 16

	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/bn1_bias.txt", dir)
	readParameterIntoSlice(fileName, ci, &((*bnBias)[numB]) )
	numB++

	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/bn1_running_mean.txt", dir)
	readParameterIntoSlice(fileName, ci, &((*bnRunningMean)[numM]) )
	numM++

	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/bn1_running_var.txt", dir)
	readParameterIntoSlice(fileName, ci, &((*bnRunningVar)[numV]) )
	numV++

	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/bn1_weight.txt", dir)
	readParameterIntoSlice(fileName, ci, &((*bnWeight)[numW]) )
	numW++

	for j := 1; j <= 3; j++ {
		var ci int
		if j == 1 { 
			ci = 16 
		} else if j == 2 { 
			ci = 32 
		} else if j == 3 { 
			ci = 64 
		}
		
		for k := 0; k <= endNum; k++ {
			for i := 1; i <= 2; i++ { // bn1 and bn2
				fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer%d_%d_bn%d_bias.txt", dir, j, k, i)
				readParameterIntoSlice(fileName, ci, &((*bnBias)[numB]) )
				numB++
				
				fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer%d_%d_bn%d_running_mean.txt", dir, j, k, i)
				readParameterIntoSlice(fileName, ci, &((*bnRunningMean)[numM]) )
				numM++
				
				fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer%d_%d_bn%d_running_var.txt", dir, j, k, i)
				readParameterIntoSlice(fileName, ci, &((*bnRunningVar)[numV]) )
				numV++
				
				fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer%d_%d_bn%d_weight.txt", dir, j, k, i)
				readParameterIntoSlice(fileName, ci, &((*bnWeight)[numW]) )
				numW++
			}
		}
	}

	// Fully Connected layer params
	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/linear_weight.txt", dir)
	readParameterIntoSlice(fileName, 10*64, &(*linearWeight) )
	
	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/linear_bias.txt", dir)
	readParameterIntoSlice(fileName, 10, &(*linearBias) )

    fmt.Println("Data imported successfully")
}

func importParametersCifar100(linearWeight, linearBias *[]float64, convWeight, bnBias, bnRunningMean, bnRunningVar, bnWeight, shortcutWeight, shortcutBnBias, shortcutBnMean, shortcutBnVar, shortcutBnWeight *[][]float64, layerNum, endNum int) {
	if layerNum != 32 {
		panic("layer number is not valid")
	}
	dir := "resnet32_cifar100"

	// 根据需要大小重置 slice
	*convWeight = make([][]float64, layerNum-1)
	*bnBias = make([][]float64, layerNum-1)
	*bnRunningMean = make([][]float64, layerNum-1)
	*bnRunningVar = make([][]float64, layerNum-1)
	*bnWeight = make([][]float64, layerNum-1)
	*shortcutWeight = make([][]float64, 2)
	*shortcutBnBias = make([][]float64, 2)
	*shortcutBnMean = make([][]float64, 2)
	*shortcutBnVar = make([][]float64, 2)
	*shortcutBnWeight = make([][]float64, 2)

	numC, numB, numM, numV, numW := 0, 0, 0, 0, 0
	fh, fw, ci, co := 3, 3, 3, 16

	// 对于每一个文件类型，下面是一个简化的示例来加载参数
	fileName := fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/conv1_weight.txt", dir)
	readParameterIntoSlice(fileName, fh*fw*ci*co, &((*convWeight)[numC]) )
    numC++

	// 遍历 3 个 block
	for j := 1; j <= 3; j++ {
		for k := 0; k <= endNum; k++ {
			if j == 1 {
				co = 16
			} else if j == 2 {
				co = 32
			} else if j == 3 {
				co = 64
			}

			if j == 1 || (j == 2 && k == 0) {
				ci = 16
			} else if (j == 2 && k != 0) || (j == 3 && k == 0) {
				ci = 32
			} else {
				ci = 64
			}
			fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer%d_%d_conv1_weight.txt", dir, j, k)
			readParameterIntoSlice(fileName, fh*fw*ci*co, &((*convWeight)[numC]) )
			numC++

			if j==1{
				ci = 16
			} else if(j==2){
				ci = 32
			} else if(j==3){
				ci = 64
			}
			fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer%d_%d_conv2_weight.txt", dir, j, k)
			readParameterIntoSlice(fileName, fh*fw*ci*co, &((*convWeight)[numC]) )
			numC++
		}
	}

	// shortcut convolution parameters
	fh, fw = 1, 1
	ci, co = 16, 32
	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer2_0_shortcut_0_weight.txt", dir)
	readParameterIntoSlice(fileName, fh*fw*ci*co, &((*shortcutWeight)[0]) )
	ci, co = 32, 64
	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer3_0_shortcut_0_weight.txt", dir)
	readParameterIntoSlice(fileName, fh*fw*ci*co, &((*shortcutWeight)[1]) )
	
	// batch_normalization parameters
	ci = 16
	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/bn1_bias.txt", dir)
	readParameterIntoSlice(fileName, ci, &((*bnBias)[numB]) )
	numB++
	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/bn1_running_mean.txt", dir)
	readParameterIntoSlice(fileName, ci, &((*bnRunningMean)[numM]) )
	numM++
	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/bn1_running_var.txt", dir)
	readParameterIntoSlice(fileName, ci, &((*bnRunningVar)[numV]) )
	numV++
	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/bn1_weight.txt", dir)
	readParameterIntoSlice(fileName, ci, &((*bnWeight)[numW]) )
	numW++

	for j := 1; j <= 3; j++ {
		var ci int
		if j == 1 { 
			ci = 16 
		} else if j == 2 { 
			ci = 32 
		} else if j == 3 { 
			ci = 64 
		}
		
		for k := 0; k <= endNum; k++ {
			for i := 1; i <= 2; i++ { // bn1 and bn2
				fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer%d_%d_bn%d_bias.txt", dir, j, k, i)
				readParameterIntoSlice(fileName, ci, &((*bnBias)[numB]) )
				numB++
				
				fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer%d_%d_bn%d_running_mean.txt", dir, j, k, i)
				readParameterIntoSlice(fileName, ci, &((*bnRunningMean)[numM]) )
				numM++
				
				fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer%d_%d_bn%d_running_var.txt", dir, j, k, i)
				readParameterIntoSlice(fileName, ci, &((*bnRunningVar)[numV]) )
				numV++
				
				fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer%d_%d_bn%d_weight.txt", dir, j, k, i)
				readParameterIntoSlice(fileName, ci, &((*bnWeight)[numW]) )
				numW++
			}
		}
	}

	// shortcut batch normalization parameters
	ci = 32
	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer2_0_shortcut_1_bias.txt", dir)
	readParameterIntoSlice(fileName, ci, &((*shortcutBnBias)[0]) )
	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer2_0_shortcut_1_running_mean.txt", dir)
	readParameterIntoSlice(fileName, ci, &((*shortcutBnMean)[0]) )
	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer2_0_shortcut_1_running_var.txt", dir)
	readParameterIntoSlice(fileName, ci, &((*shortcutBnVar)[0]) )
	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer2_0_shortcut_1_weight.txt", dir)
	readParameterIntoSlice(fileName, ci, &((*shortcutBnWeight)[0]) )

	ci = 64;
	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer3_0_shortcut_1_bias.txt", dir)
	readParameterIntoSlice(fileName, ci, &((*shortcutBnBias)[1]) )
	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer3_0_shortcut_1_running_mean.txt", dir)
	readParameterIntoSlice(fileName, ci, &((*shortcutBnMean)[1]) )
	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer3_0_shortcut_1_running_var.txt", dir)
	readParameterIntoSlice(fileName, ci, &((*shortcutBnVar)[1]) )
	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/layer3_0_shortcut_1_weight.txt", dir)
	readParameterIntoSlice(fileName, ci, &((*shortcutBnWeight)[1]) )

	//FC
	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/linear_weight.txt", dir)
	readParameterIntoSlice(fileName, 100*64, &(*linearWeight) )
	fileName = fmt.Sprintf("../../cnn_infer/pretrained_parameters/%s/linear_bias.txt", dir)
	readParameterIntoSlice(fileName, 100, &(*linearBias) )
	fmt.Println("Data imported successfully")
}



