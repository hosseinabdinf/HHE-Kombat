package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"math"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils"
)


const EPSILON float64 = 1.0E-08


func ReadSNPFile(headers *[]string, dataColumns *[][]float64, y *[]float64, dataFileName string, N, M int) error {
	fileName := dataFileName + ".csv"
	fmt.Fprintf(os.Stderr, "file name = %s\n", fileName)

	file, err := os.Open(fileName)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.TrimLeadingSpace = true

	// Read the header line
	line, err := reader.Read()
	if err != nil {
		return fmt.Errorf("failed to read header line: %w", err)
	}

	cols := len(line)
	for i, value := range line {
		if value != "" && i > 4 && i < M+5 {
			*headers = append(*headers, value)
		}
	}

	count := 0
	for {
		if count >= N {
			break
		}
		line, err := reader.Read()
		if err != nil {
			break
		}

		if len(line) > 2 {
			yval, err := strconv.ParseFloat(line[1], 64)
			if err != nil {
				return fmt.Errorf("failed to parse float from line[1]: %w", err)
			}
			*y = append(*y, yval)

			var row []float64
			for i := 5; i < cols; i++ {
				val, err := strconv.ParseFloat(line[i], 64)
				if err != nil {
					return fmt.Errorf("failed to parse float from line[%d]: %w", i, err)
				}
				row = append(row, val)
			}
			*dataColumns = append(*dataColumns, row)
		}
		count++
	}

	fmt.Printf("Read in data: %s\n", dataFileName)
	return nil
}

// BS 
func BS(z float64) float64 {
	y := math.Exp(-z * z / 2)
	return math.Sqrt(1-y) * (31*y/200 - 341*y*y/8000) / math.Sqrt(math.Pi)
}

// normalCFD 
func normalCFD(value float64) float64 {
	return 0.5 * math.Erfc( math.Sqrt2/(-value) )
}

// sf 
func sf(value float64) float64 {
	return 1 - normalCFD(value)
}

func Equal(a, b float64) bool {
	return EPSILON > math.Abs(a-b)
}

func Less(a, b float64) bool {
	return (a - b) < (-EPSILON)
}

func Greater(a, b float64) bool {
	return (a - b) > EPSILON
}

// IncompleteGamma 
func IncompleteGamma(val, p float64) float64 {
	if !Greater(val, 0) || !Greater(p, 0) {
		return 0
	}
	LgammaP, _ := math.Lgamma(p)
	expValue := p*math.Log(val) - val - LgammaP
	if Less(expValue, math.Log(1.0E-37)) { // underflow
		return 0
	}
	factor := math.Exp(expValue)
	if !Greater(val, 1) || Less(val, p) {
		igamma := 1.0
		term := 1.0
		for i := 1; Greater(term, EPSILON); i++ {
			term *= (val / (p + float64(i)))
			igamma += term
		}
		return (igamma * factor / p)
	}

	pn := [6]float64{1, val, val + 1, val * (2 + val - p)}
	upperIncGamma := pn[2] / pn[3]
	for j := 1; ; j++ {
		a := (float64(j)+1)*2 + val - p
		b := (1 + float64(j) - p) * float64(j)
		pn[4] = a*pn[2] - b*pn[0]
		pn[5] = a*pn[3] - b*pn[1]
		if !Equal(pn[5], 0) {
			rn := pn[4] / pn[5]
			diff := math.Abs(upperIncGamma - rn)
			if !Greater(diff, EPSILON) && !Greater(diff, (EPSILON*rn)) {
				return (1 - factor*upperIncGamma)
			}
			upperIncGamma = rn
		}
		for i := 0; i < 4; i++ {
			pn[i] = pn[i+2]
		}
		if !Greater(1.0E+37, math.Abs(pn[4])) { // overflow
			for i := 0; i < 4; i++ {
				pn[i] = pn[i] / 1.0E+37
			}
		}
	}

}


func BinaryTreeAdd(vector []*rlwe.Ciphertext, evaluator *bootstrapping.Evaluator) *rlwe.Ciphertext {

	for j := 1; j < len(vector); j=j*2 {
		for i := 0; i<len(vector); i = i + 2*j {
			if (i+j)<len(vector) {
				evaluator.Add(vector[i], vector[i+j], vector[i])
			}				
		}
	}
	return vector[0]
}
 

func RunChi2(SNPDir, SNPFileName, pValue, Runtime, SampleSize, SNPs string) {
	N, err := strconv.Atoi(SampleSize)
	if err != nil {
		log.Fatalf("SampleSize转换错误: %v", err)
	}
	M, err := strconv.Atoi(SNPs)
	if err != nil {
		log.Fatalf("SNPs转换错误: %v", err)
	}
	scalingFactor := 0.1*math.Pow(float64(N), -2)

	var headersS []string
	var sData [][]float64
	var yData []float64

	startTime := time.Now()

	err = ReadSNPFile(&headersS, &sData, &yData, SNPDir+"/"+SNPFileName, N, M)
	if err != nil {
		log.Fatalf("ReadSNPFile error: %v", err)
	}
	for i:=0;i<10;i++{
		fmt.Println(headersS[i])
	}

	fmt.Println("Number of Individuals =", len(sData))
	fmt.Println("Number of SNPs =", len(sData[0]))
	fmt.Println("Number of yData =", len(yData))

	workingLevel := 3 // Specify the working level to reduce Mul complexity

	LogN := 16
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            LogN,                                              // Log2 of the ring degree
		LogQ:            []int{58, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42}, // Log2 of the ciphertext prime moduli
		LogP:            []int{61, 61, 61, 61, 61},                                 // Log2 of the key-switch auxiliary prime moduli
		LogDefaultScale: 42,                                                // Log2 of the scale
		Xs:              ring.Ternary{H: 192},
	})
	btpParametersLit := bootstrapping.ParametersLiteral{
		// We specify LogN to ensure that both the residual parameters and the bootstrapping parameters
		// have the same LogN. This is not required, but we want it for this example.
		LogN: utils.Pointy(LogN),

		// In this example we need manually specify the number of auxiliary primes (i.e. #Pi) used by the
		// evaluation keys of the bootstrapping circuit, so that the size of LogQP  meets the security target.
		LogP: []int{61, 61, 61, 61, 61},

		// In this example we manually specify the bootstrapping parameters' secret distribution.
		// This is not necessary, but we ensure here that they are the same as the residual parameters.
		Xs: params.Xs(),
	}
	btpParams, err := bootstrapping.NewParametersFromLiteral(params, btpParametersLit)
	if err != nil {
		panic(err)
	}

	// Scheme context and keys
	kgen := rlwe.NewKeyGenerator(params)

	sk, pk := kgen.GenKeyPairNew()

	encoder := ckks.NewEncoder(params)
	decryptor := rlwe.NewDecryptor(params, sk)
	encryptor := rlwe.NewEncryptor(params, pk)
	step := M // Collect half  ind1 || ind2 with each 16384 SNPs of total 32768 SNPs
	galEls := params.GaloisElements( []int{step} )
	evk, _, err := btpParams.GenEvaluationKeysWithOthers(sk, galEls)
	if err != nil {
		panic(err)
	}
	var eval *bootstrapping.Evaluator
	if eval, err = bootstrapping.NewEvaluator(btpParams, evk); err != nil {
		panic(err)
	}
	
	sCiphertexts := make([]*rlwe.Ciphertext, N/2)
	
	for i := 0; i < N/2; i++ {
		individual := make([]float64, 2*M)
		copy(individual[:M], sData[i])
		copy(individual[M:], sData[N/2 + i])
		S := ckks.NewCiphertext(params, 1, workingLevel)
		plaintext := ckks.NewPlaintext(params, workingLevel)
		encoder.Encode( individual, plaintext )
		encryptor.Encrypt(plaintext, S)
		for S.Level() > workingLevel {
			eval.DropLevel(S, 1)
		}
		sCiphertexts[i] = S
	}

	yCiphertexts := make([]*rlwe.Ciphertext, N/2)
	for i := 0; i < N/2; i++ {
		individual := make([]float64, 2*M)
		for j:=0;j<M;j++{
			individual[j] = yData[i]
			individual[j+M] = yData[N/2 + i]
		}
		plaintext := ckks.NewPlaintext(params, workingLevel)
		encoder.Encode( individual, plaintext )
		yCiphertexts[i], err = encryptor.EncryptNew(plaintext)
		if err != nil {
			panic(err)
		}
		for yCiphertexts[i].Level() > workingLevel {
			eval.DropLevel(yCiphertexts[i], 1)
		}
	}

	dVal := make([]float64, M)
	for i, _ := range dVal {
		tmp := float64(N)
		dVal[i] = 2 * tmp
	}
	// d := encoder.EncodeComplexNTTNew( dVal, params.LogSlots())

	dValScaled := make([]float64, M)
	for i, _ := range dValScaled {
		tmp := float64(N)
		dValScaled[i] = 2 * tmp * scalingFactor
	}
	dScaled := ckks.NewPlaintext(params, workingLevel)
	encoder.Encode(dValScaled, dScaled)

	start := time.Now()

	ySum := make([]*rlwe.Ciphertext, len(yCiphertexts) )
	for i := range yCiphertexts {
		ySum[i] = yCiphertexts[i].CopyNew()
	}
	yU := BinaryTreeAdd(ySum, eval)

	var chiD, chiN, orD, orN *rlwe.Ciphertext 
	ySMult := make([]*rlwe.Ciphertext, N/2)

	for i := 0; i < N/2; i++ {
		ySMult[i], err = eval.MulRelinNew(sCiphertexts[i], yCiphertexts[i])
		eval.Rescale(ySMult[i], ySMult[i])
	}
	// var wg sync.WaitGroup // 用于等待所有goroutine完成的同步工具
	// for i := 0; i < N/2; i++ {
	// 	wg.Add(1) // 增加等待计数
	// 	go func(i int) { // 使用goroutine并发执行
	// 		defer wg.Done() // 完成时减少等待计数
	// 		// 执行操作，假设这些方法是线程安全的
	// 		ySMult[i] = evaluator.ShallowCopy().MulRelinNew(sCiphertexts[i], yCiphertexts[i])
	// 		evaluator.ShallowCopy().RescaleMany(ySMult[i], 1, ySMult[i])
	// 	}(i) // 传递当前索引i
	// }
	// wg.Wait() // 等待所有goroutine完成


	n11 := BinaryTreeAdd(ySMult, eval)
	c1 := BinaryTreeAdd(sCiphertexts, eval)
	
	//Rotate step
	n11Rot, err := eval.RotateNew(n11, step)
	eval.Add(n11, n11Rot, n11)
	if err != nil {
		panic(err)
	}
	c1Rot, err := eval.RotateNew(c1, step)
	eval.Add(c1, c1Rot, c1)
	if err != nil {
		panic(err)
	}
	yURot, err := eval.RotateNew(yU, step)
	eval.Add(yU, yURot, yU)
	if err != nil {
		panic(err)
	}
	printDebug( "n11: ", params, n11, decryptor, encoder)
	printDebug( "c1: ", params, c1, decryptor, encoder)
	printDebug( "yU: ", params, yU, decryptor, encoder)

	// r1 = 2 * yU
	r1, err := eval.AddNew(yU, yU)
	r1Scaled, err := eval.MulNew(r1, float64(scalingFactor) )
	if err != nil {
		panic(err)
	}
	eval.Rescale(r1Scaled, r1Scaled)

	c1Scaled, err := eval.MulNew(c1, float64(scalingFactor) )
	eval.Rescale(c1Scaled, c1Scaled)
	if err != nil {
		panic(err)
	}
	// compute Chi2
	mult1, err := eval.MulRelinNew(n11, dScaled)
	eval.Rescale(mult1, mult1)
	if err != nil {
		panic(err)
	}
	mult2, err := eval.MulRelinNew(c1, r1Scaled)
	eval.Rescale(mult2, mult2)
	if err != nil {
		panic(err)
	}
	chiN1, err := eval.SubNew(mult1, mult2)
	if err != nil {
		panic(err)
	}
	chiN, err = eval.MulRelinNew(chiN1, chiN1)
	if err != nil {
		panic(err)
	}
	// denominator
	negC1Scaled, err := eval.MulNew(c1Scaled, -1)
	chiD1, err := eval.AddNew(negC1Scaled, dScaled)
	if err != nil {
		panic(err)
	}
	chiD1, err = eval.MulRelinNew(chiD1, c1)
	if err != nil {
		panic(err)
	}
	eval.Rescale(chiD1, chiD1)
	negR1Scaled, err := eval.MulNew(r1Scaled, -1)
	chiD2, err := eval.AddNew(negR1Scaled, dScaled)
	chiD2, err = eval.MulRelinNew(chiD2, r1)
	eval.Rescale(chiD2, chiD2)
	if err != nil {
		panic(err)
	}
	chiD, err = eval.MulRelinNew( chiD1, chiD2 )
	eval.Rescale(chiD, chiD)
	if err != nil {
		panic(err)
	}
	// Odds Ratio
	n11Scaled, err := eval.MulNew(n11, float64(scalingFactor) )
	eval.Rescale(n11Scaled, n11Scaled)
	
	// denominator
	or2, err := eval.SubNew(c1, n11)
	or3, err := eval.SubNew(r1Scaled, n11Scaled)
	orD, err = eval.MulRelinNew(or2, or3)
	eval.Rescale(orD, orD)
	if err != nil {
		panic(err)
	}
	// numerator
	or1, err := eval.SubNew(n11Scaled, r1Scaled)
	or1, err = eval.SubNew(or1, c1Scaled)
	or1, err = eval.AddNew(or1, dScaled)
	
	orN, err = eval.MulRelinNew(n11, or1)
	eval.Rescale(orN, orN)

	endToEndTime := float64(time.Since(start).Seconds())


	pN := decryptor.DecryptNew(chiN)
	pD := decryptor.DecryptNew(chiD)
	oddN := decryptor.DecryptNew(orN)
	oddD := decryptor.DecryptNew(orD)
	
	msg_pN := make([]float64, len(headersS))
	msg_pD := make([]float64, len(headersS))
	msg_oddN := make([]float64, len(headersS))
	msg_oddD := make([]float64, len(headersS))

	encoder.Decode(pN, msg_pN)
	encoder.Decode(pD, msg_pD)
	encoder.Decode(oddN, msg_oddN)
	encoder.Decode(oddD, msg_oddD)

	chival := make([]float64, len(headersS))
	pval := make([]float64, len(headersS))
	odds := make([]float64, len(headersS))

	for i := 0; i < len(headersS); i++ {
		chival[i] = msg_pN[i] * 2 * float64(N) / msg_pD[i]
		if chival[i] < 0 {
			chival[i] = 0
		}
		pval[i] = 1 - IncompleteGamma(chival[i]/2, 0.5)
		if pval[i] < 0 {
			pval[i] = 1e-15
		} else {
			if pval[i] == 0 {
				pval[i] = BS(math.Sqrt(chival[i]))
			}
		}
		odds[i] = msg_oddN[i] / msg_oddD[i]
	}	

	writeResults("pValue.txt", headersS, pval)
	writeResults("odds.txt", headersS, odds)
	writeResults("chi2.txt", headersS, chival)

	// keyGenTime := float64(time.Since(startKeyGen).Seconds())
	// encryptionTime := float64(time.Since(startEnc).Seconds())
	// computationTime := float64(time.Since(startComp).Seconds())
	// decryptionTime := float64(time.Since(startDec).Seconds())
	
	// fmt.Printf("\nKey Generation Time: \t\t%.3f s\n", keyGenTime)
	// fmt.Printf("Encoding and Encryption Time: \t%.3f s\n", encryptionTime)
	// fmt.Printf("Computation Time: \t\t%.3f s\n", computationTime)
	// fmt.Printf("Decryption & Decoding Time: \t%.3f s\n", decryptionTime)
	fmt.Printf("\nEnd-to-end Runtime: \t\t%.3f s\n", endToEndTime)

	// writeRuntime("runtime.txt", keyGenTime, encryptionTime, computationTime, decryptionTime, endToEndTime)

	duration := time.Since(startTime)
	fmt.Printf("End-to-end Runtime: %.2f s\n", duration.Seconds())
}

func writeResults(filename string, headersS []string, values []float64) {
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	for i := 0; i < len(headersS); i++ {
		fmt.Fprintf(file, "%s\t%f\n", headersS[i], values[i])
	}
}

func writeRuntime(filename string, keyGenTime, encryptionTime, computationTime, decryptionTime, endToEndTime float64) {
    file, err := os.Create(filename)
    if err != nil {
        panic(err)
    }
    defer file.Close()

    fmt.Fprintf(file, "Key Generation Time: \t\t%.3f s\n", keyGenTime)
    fmt.Fprintf(file, "Encoding and Encryption Time: \t%.3f s\n", encryptionTime)
    fmt.Fprintf(file, "Computation Time: \t\t%.3f s\n", computationTime)
    fmt.Fprintf(file, "Decryption & Decoding Time: \t%.3f s\n", decryptionTime)
    fmt.Fprintf(file, "End-to-end Runtime: \t\t%.3f s\n", endToEndTime)
}

func printDebug( str string, params ckks.Parameters, ciphertext *rlwe.Ciphertext, decryptor *rlwe.Decryptor, encoder *ckks.Encoder) {

	fmt.Println(str)
	valuesTest := make([]float64, params.MaxSlots())
	encoder.Decode(decryptor.DecryptNew(ciphertext), valuesTest)

	fmt.Printf("Level: %d (logQ = %d)\n", ciphertext.Level(), params.LogQLvl(ciphertext.Level()))
	fmt.Printf("Scale: 2^%f\n", ciphertext.LogScale())
	fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
}


func main() {
	runtime.GOMAXPROCS(1)
	// ./chi2 --SNPdir "../data" --SNPfilename "random_sample" --pvalue "pvalue.txt" --runtime "result.txt" --samplesize="200" --snps="16384"
	    // 定义命令行参数
	SNPDir := "data"
	SNPFileName := "random_sample"
	pValue := "pvalue.txt"
	Runtime := "result.txt"
	SampleSize := "200"
	SNPs := "16384"
	RunChi2(SNPDir, SNPFileName, pValue, Runtime, SampleSize, SNPs);

}
