package cnn_infer

import (
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

type testParams struct {
	params      ckks.Parameters
	sk  		*rlwe.SecretKey
	pk 			*rlwe.PublicKey
	encoder     *ckks.Encoder
	encryptor 	*rlwe.Encryptor
	decryptor   *rlwe.Decryptor
	evaluator   *bootstrapping.Evaluator
	totalLevel 	int
	remainingLevel int
	prng        sampling.PRNG
}

func genTestParams(params ckks.Parameters, defaultParam bootstrapping.Parameters, galEls []uint64) (testContext *testParams) {

	testContext = new(testParams)
	testContext.params = params
	kgen := rlwe.NewKeyGenerator(testContext.params)
	testContext.sk, testContext.pk = kgen.GenKeyPairNew()

	testContext.prng, _ = sampling.NewPRNG()

	testContext.encoder = ckks.NewEncoder(testContext.params)

	testContext.encryptor = rlwe.NewEncryptor(testContext.params, testContext.pk)
	testContext.decryptor = rlwe.NewDecryptor(testContext.params, testContext.sk)

	evk, _, err := defaultParam.GenEvaluationKeysWithOthers(testContext.sk, galEls)
	if err != nil {
		panic(err)
	}

	testContext.evaluator, err = bootstrapping.NewEvaluator(defaultParam, evk)
	if err != nil {
		panic(err)
	}

	testContext.totalLevel = testContext.params.MaxLevel()
	testContext.remainingLevel = defaultParam.ResidualParameters.MaxLevel()
	
	return
}

type TensorCipher struct {
	k, h, w, c, t, p, logn int
	cipher *rlwe.Ciphertext
}

func NewTensorCipher() *TensorCipher {

	return &TensorCipher{}
}

func NewTensorCipherWithCT(logn, k, h, w, c, t, p int, cipher *rlwe.Ciphertext ) (*TensorCipher, error) {

	return &TensorCipher{k: k, h: h, w: w, c: c, t: t, p: p, logn: logn, cipher: cipher}, nil
}

func NewTensorCipherWithData(logn, k, h, w, c, t, p int, data []float64, context *testParams) (*TensorCipher, error) {
	
    if k != 1 {panic("supported k is only 1 right now")}
    
	// 1 <= logn <= 16
    if logn < 1 || logn > 16 { panic("the value of logn is out of range") }
    if len( data ) > int(1<<logn) { panic("the size of data is larger than n") }

	n := 1 << logn

 	// vec size = n
	if len(data) != n { panic("the size of vec is not n") }
	vec := make([]float64, n)
	fmt.Println("Lenghth data: ", len(data))
	for i:=0; i<int( len(data) );i++ {
		vec[i] = data[i]
	}
	for i:=len(data); i<n; i++ {
		vec[i] = 0.0 // zero padding
	} 

	plaintext := ckks.NewPlaintext(context.params, context.remainingLevel)
	context.encoder.Encode(data, plaintext)
	// Encrypt
	rtn, err := context.encryptor.EncryptNew(plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Println("Tensor scale: ", rtn.LogScale() )

	return &TensorCipher{k: k, h: h, w: w, c: c, t: t, p: p, logn: logn, cipher: rtn }, nil
}

func (t *TensorCipher) PrintParms() {
	fmt.Printf("k: %v\nh: %v\nw: %v\nc: %v\nt: %v\np: %v\n", t.k, t.h, t.w, t.c, t.t, t.p)
}


func MultiplexedParallelConvolutionCipher(cnnIn *TensorCipher, co, st, fh, fw int, data, runningVar, constantWeight []float64, epsilon float64, context *testParams, cipherPool []*rlwe.Ciphertext, end bool) ( *TensorCipher, error) {

	
	ki, hi, wi, ci, ti, pi, logn := cnnIn.k, cnnIn.h, cnnIn.w, cnnIn.c, cnnIn.t, cnnIn.p, cnnIn.logn
	ko, ho, wo, to, po := 0, 0, 0, 0, 0	

	fmt.Printf("ki: %d, hi: %d, wi: %d, ci: %d, ti: %d, pi: %d, logn: %d\n", ki, hi, wi, ci, ti, pi, logn)
	// error check
	if st != 1 && st != 2 {
		panic("supported st is only 1 or 2")
	}
	if int( len(data) ) != fh*fw*ci*co {panic("the size of data vector is not ker x ker x h x h")}	// check if the size of data vector is kernel x kernel x h x h'
	if log2Long(ki) == -1 {panic("ki is not power of two")}
	if int( len(runningVar) ) != co || int( len(constantWeight) ) !=co { panic("the size of running_var or weight is not correct")}
	for num := range runningVar {
		if num<int( math.Pow(10,-16) ) && num>-int( math.Pow(10,-16) ) {panic("the size of running_var is too small. nearly zero.")}
	}

	// set ho, wo, ko
	if st == 1 {
		ho = hi
		wo = wi
		ko = ki
	} else if st == 2 {
		if hi%2 == 1 || wi%2 == 1 {panic("hi or wi is not even")}
		ho = hi/2
		wo = wi/2
		ko = 2*ki
	}

	// set to, po, q
	n := 1<<logn;
	to = (co+ko*ko-1) / (ko*ko);
	po =  pow2( int( math.Log2( float64(n) / float64(ko*ko*ho*wo*to) ) ) );
	q := (co+pi-1)/pi

	// check if pi, po | n
	if n%pi != 0 {panic("n is not divisible by pi")}
	if n%po != 0 {panic("n is not divisible by po")}
	// check if ki^2 hi wi ti pi <= n and ko^2 ho wo to po <= n
	if ki*ki*hi*wi*ti*pi > n {panic("ki^2 hi wi ti pi is larger than n")}
	if ko*ko*ho*wo*to*po > 1<<logn {panic("ko^2 ho wo to po is larger than n")}

	// Assumes fh, fw, ci, co, q, ko, ho, wo, to, logn are defined variables
	weight := newFourDSlice(fh, fw, ci, co)
	compactWeight := newFourDSlice(fh, fw, q, 1<<logn)
	selectOne := newFourDSlice(co, ko*ho, ko*wo, to)
	selectOneVec := make(twoDSlice, co)
	for i := range selectOneVec {
		selectOneVec[i] = make(oneDSlice, 1<<logn)
	}

	// weight setting
	for i1:=0; i1<fh; i1++ {
		for i2:=0; i2<fw; i2++ {
			for j3:=0; j3<ci; j3++ {
				for j4:=0; j4<co; j4++ {
					weight[i1][i2][j3][j4] = data[fh*fw*ci*j4 + fh*fw*j3 + fw*i1 + i2]
				}
			}
		}
	}

	// compact shifted weight vector setting
	for i1:=0; i1<fh; i1++ {
		for i2:=0; i2<fw; i2++ {
			for i9:=0; i9<q; i9++ {
				for j8:=0; j8<n; j8++ {
					j5 := ((j8%(n/pi))%(ki*ki*hi*wi))/(ki*wi)
					j6 := (j8%(n/pi))%(ki*wi)
					i7 := (j8%(n/pi))/(ki*ki*hi*wi)
					i8 := j8/(n/pi)
					if j8%(n/pi)>=ki*ki*hi*wi*ti || i8+pi*i9>=co || ki*ki*i7+ki*(j5%ki)+j6%ki>=ci || (j6/ki)-(fw-1)/2+i2 < 0 || (j6/ki)-(fw-1)/2+i2 > wi-1 || (j5/ki)-(fh-1)/2+i1 < 0 || (j5/ki)-(fh-1)/2+i1 > hi-1 {
						compactWeight[i1][i2][i9][j8] = 0.0
					} else {
						compactWeight[i1][i2][i9][j8] = weight[i1][i2][ki*ki*i7+ki*(j5%ki)+j6%ki][i8+pi*i9]
					}
				}
			}
		}
	}
	// select one setting
	for j4:=0; j4<co; j4++ {
		for v1:=0; v1<ko*ho; v1++ {
			for v2:=0; v2<ko*wo; v2++ {
				for u3:=0; u3<to; u3++ {
					if ko*ko*u3 + ko*(v1%ko) + v2%ko == j4 { 
						selectOne[j4][v1][v2][u3] = constantWeight[j4] / math.Sqrt( runningVar[j4]+epsilon )
					} else { selectOne[j4][v1][v2][u3] = 0.0 }
				}
			}
		}
	}
	// select one vector setting
	for j4:=0; j4<co; j4++ {
		for v1:=0; v1<ko*ho; v1++ {
			for v2:=0; v2<ko*wo; v2++ {
				for u3:=0; u3<to; u3++ {
					selectOneVec[j4][ko*ko*ho*wo*u3 + ko*wo*v1 + v2] = selectOne[j4][v1][v2][u3]
				}
			}
		}
	}


	ctxtIn := cipherPool[0]
    temp := cipherPool[2]
    sum := cipherPool[3]
    totalSum := cipherPool[4]
    varLbl := cipherPool[5]

    // Example of obtaining a vector from a tensor.
    ctxtIn = cnnIn.cipher // Assuming Vec() returns the internal vector representation.

	ctxtRot := make([][]*rlwe.Ciphertext, fh)

    for i := range ctxtRot {
        ctxtRot[i] = make([]*rlwe.Ciphertext, fw)
    }

	if fh%2 == 0 || fw%2 == 0{ panic("fh and fw should be odd") }

	for i1:=0; i1<fh; i1++ {
		for i2:=0; i2<fw; i2++ {
			if i1==(fh-1)/2 && i2==(fw-1)/2 { // i1=(fh-1)/2, i2=(fw-1)/2 means ctxt_in
				ctxtRot[i1][i2] = ctxtIn
			} else if (i1==(fh-1)/2 && i2>(fw-1)/2) || i1>(fh-1)/2{
				ctxtRot[i1][i2] = cipherPool[6+fw*i1+i2-1]
			} else { ctxtRot[i1][i2] = cipherPool[6+fw*i1+i2] }
		}
	}


	for i1:=0; i1<fh; i1++ {
		for i2:=0; i2<fw; i2++ {
			ctxtRot[i1][i2] = ctxtIn
			// fmt.Println("before Rot, Step number : ", ( ki*ki*wi*(i1-(fh-1)/2) + ki*(i2-(fw-1)/2) ) )
			// printDebug(ctxtRot[i1][i2], context, 7, 7)

			ctxtRot[i1][i2] = memorySaveRotateCipher(ctxtRot[i1][i2], context, ki*ki*wi*(i1-(fh-1)/2) + ki*(i2-(fw-1)/2), n)
			// fmt.Println("After Rot")
			// printDebug(ctxtRot[i1][i2], context, 7, 7)
		}
	}

	// generate zero ciphertext 
	zero := make( []float64, context.params.MaxSlots() )
	plain := ckks.NewPlaintext(context.params, context.remainingLevel )
	// fmt.Println("before conv encode, LogSlots: ", context.params.LogMaxSlots())
	context.encoder.Encode( zero, plain )
	ctZero, err := context.encryptor.EncryptNew( plain )
	if err != nil{
		panic(err)
	}
	

	for i9:=0; i9<q; i9++ {
		// weight multiplication
		for i1:=0; i1<fh; i1++ {
			for i2:=0; i2<fw; i2++ {
				temp, _ = context.evaluator.MulNew(ctxtRot[i1][i2], compactWeight[i1][i2][i9])

				if i1==0 && i2==0 {
					sum = temp
				} else {
					sum, _ = context.evaluator.AddNew(temp, sum)
				}
			}
		}

		context.evaluator.Rescale(sum, sum)
		varLbl = sum

		// fmt.Println("First break : ", i9)
		// printDebug(varLbl, context, 7, 7)

		// summation for all input channels
		d := log2Long(ki)
		c := log2Long(ti)

		for x:=0; x<d; x++ {
			temp = varLbl
			temp = memorySaveRotateCipher(temp, context, pow2(x), n)
			context.evaluator.Add(temp, varLbl, varLbl)
		}
		// fmt.Println("Second break : ", i9)
		// printDebug(varLbl, context, 7, 7)

		for x:=0; x<d; x++ {
			temp = varLbl
			temp = memorySaveRotateCipher(temp, context, pow2(x)*ki*wi, n)
			context.evaluator.Add(temp, varLbl, varLbl)
		}

		// fmt.Println("Third break ", i9)
		// printDebug(varLbl, context, 7, 7)

		if c==-1 {
			sum = ctZero.CopyNew()
			for x:=0; x<ti; x++ {
				temp = varLbl
				temp = memorySaveRotateCipher(temp, context, ki*ki*hi*wi*x, n)
				context.evaluator.Add(temp, sum, sum)
			}
			varLbl = sum
		} else {
			for x:=0; x<c; x++ {
				temp = varLbl
				temp = memorySaveRotateCipher(temp, context, pow2(x)*ki*ki*hi*wi, n)
				context.evaluator.Add(temp, varLbl, varLbl)
			}
		}
		// fmt.Println("Fourth break : ", i9)
		// printDebug(varLbl, context, 7, 7)
		// collecting valid values into one ciphertext.
		for i8:=0; i8<pi && pi*i9+i8<co; i8++ {
			j4 := pi*i9+i8
			if j4 >= co { panic("the value of j4 is out of range!") }
			temp = varLbl
			temp = memorySaveRotateCipher(temp, context, (n/pi)*(j4%pi) - j4%ko - (j4/(ko*ko))*ko*ko*ho*wo - ((j4%(ko*ko))/ko)*ko*wo , n )
			temp, _ = context.evaluator.MulNew(temp, selectOneVec[j4])

			if i8==0 && i9==0 {
				totalSum = temp
			} else {  
				totalSum, _ = context.evaluator.AddNew(temp, totalSum) 
			}


		}

	}

	context.evaluator.Rescale(totalSum, totalSum)

	varLbl = totalSum
	// fmt.Println("after end: ")
	// printDebug(varLbl, context, 7, 7)

	// po copies
	if !end {
		sum = ctZero.CopyNew()
		for u6:=0; u6<po; u6++ {
			temp = varLbl.CopyNew()
			temp = memorySaveRotateCipher(temp, context, -u6*(n/po), n )
			context.evaluator.Add( temp, sum, sum )
		}
		varLbl = sum
	}


	cnnOut, _ := NewTensorCipherWithCT(logn, ko, ho, wo, co, to, po, varLbl)
	
	return cnnOut, nil
}

// MultiplexedParallelBatchNormPlain converts the C++ function to Go.
func MultiplexedParallelBatchNormCipher(cnnIn *TensorCipher, bias, runningMean, runningVar, weight []float64, epsilon float64, B float64, context *testParams, end bool) ( *TensorCipher, error) {
	// Parameter setting (Based on the Tensor methods available).
	ki, hi, wi, ci, ti, pi, logn := cnnIn.k, cnnIn.h, cnnIn.w, cnnIn.c, cnnIn.t, cnnIn.p, cnnIn.logn
	ko, ho, wo, co, to, po := ki, hi, wi, ci, ti, pi
	
	// The remaining variables such as ti, pi, logn are similarly set ...

	// ... Error checks similar to those in the C++ function ...
	if (len(bias) != ci) || (len(runningMean) != ci) || (len(runningVar) != ci) || (len(weight) != ci) {
		panic("the size of bias, runningMean, runningVar, or weight are not correct")
	}

	for _, num := range runningVar {
		if num < math.Pow(10, -16) && num > -math.Pow(10, -16) {
			panic("the size of runningVar is too small. nearly zero")
		}
	}

	if hi*wi*ci > (1 << logn) {
		panic("hi*wi*ci should not be larger than n")
	}

	// Generate g vector
	g := make([]float64, 1<<logn)
	for i := range g{
		g[i] = 0.0
	}
	// Set f value
	n := 1 << logn

	// Check if pi | n	
	if n%pi != 0 {
		panic("n is not divisible by pi")
	}

	// Set g vector
	for v4 := 0; v4 < n; v4++ {
		// Your indexing calculations here as in the original code...
		v1 := ((v4%(n/pi))%(ki*ki*hi*wi))/(ki*wi) 
		v2 := (v4%(n/pi))%(ki*wi)
		u3 := (v4%(n/pi))/(ki*ki*hi*wi)
		if ki*ki*u3+ki*(v1%ki)+v2%ki>=ci || v4%(n/pi)>=ki*ki*hi*wi*ti {g[v4] = 0.0} else {
			idx := ki*ki*u3 + ki*(v1%ki) + v2%ki
			g[v4] = (runningMean[idx] * weight[idx] / math.Sqrt(runningVar[idx]+epsilon) - bias[idx])/B;
		}
	}
	// encode & encrypt

	temp := cnnIn.cipher

	plain := ckks.NewPlaintext(context.params, temp.Level())
	context.encoder.Encode( g, plain )
	cipherG, err := context.encryptor.EncryptNew( plain )
	if err != nil {
		panic(err)
	}
	context.evaluator.Sub(temp, cipherG, temp)

	return NewTensorCipherWithCT(logn, ko, ho, wo, co, to, po, temp)
}

func ReLU_cipher(cnnIn *TensorCipher, compNo int, deg []int, alpha int, tree []*Tree, scaledVal float64, context *testParams, btp *bootstrapping.Evaluator) ( *TensorCipher, error) {
	ki, hi, wi, ci := cnnIn.k, cnnIn.h, cnnIn.w, cnnIn.c
	logn := cnnIn.logn

	// Error check
	if hi*wi*ci > (1 << logn) {
		panic("hi*wi*ci should not be larger than n")
	}

	// ReLU
	temp := minimax_ReLU_cipher(compNo, deg, alpha, tree, scaledVal, context, cnnIn.cipher)
	// Create and return the output Tensor with the updated vector
	return NewTensorCipherWithCT(logn, ki, hi, wi, ci, cnnIn.t, cnnIn.p, temp)
}
func multiplexedParallelDownsamplingCipher(cnnIn *TensorCipher, context *testParams) ( *TensorCipher, error) {
	ki, hi, wi, ci, ti, logn := cnnIn.k, cnnIn.h, cnnIn.w, cnnIn.c, cnnIn.t, cnnIn.logn
	ko, ho, wo, to, co, po := 0, 0, 0, 0, 0, 0
	n := 1 << logn
	ko = 2 * ki
	ho = hi / 2
	wo = wi / 2
	to = ti / 2
	co = 2 * ci
	// Compute po based on the new dimensions and n
	po = 1 << int(math.Floor( math.Log(float64(n)/float64(ko*ko*ho*wo*to)) / math.Log(2.0) ))

	// Error check
	if ti%8 != 0 {
		panic("ti is not multiple of 8")
	}
	if hi%2 != 0 || wi%2 != 0 {
		panic("hi and wi must be even")
	}
	if n%po != 0 {
		panic("n is not divisible by po")
	}
	 
	var temp, ct, sum *rlwe.Ciphertext
	ct = cnnIn.cipher
	// Redefine select_one_vec as a slice-of-slices, since it's multidimensional
	select_one_vec := make([][][]float64, ki)
	for i := range select_one_vec {
		select_one_vec[i] = make([][]float64, ti)
		for j := range select_one_vec[i] {
			select_one_vec[i][j] = make([]float64, n)
		}
	}

	// selecting tensor vector setting
	for w1:=0; w1<ki; w1++{
		for w2:=0; w2<ti; w2++{
			for v4:=0; v4<1<<logn; v4++	{
				j5 := (v4%(ki*ki*hi*wi)) / (ki*wi)
				j6 := v4%(ki*wi)
				i7 := v4/(ki*ki*hi*wi)
				if v4<ki*ki*hi*wi*ti && (j5/ki)%2 == 0 && (j6/ki)%2 == 0 && (j5%ki) == w1 && i7 == w2{
					select_one_vec[w1][w2][v4] = 1.0
				} else {
					select_one_vec[w1][w2][v4] = 0.0
				} 
			}
		}
	}
	// fmt.Println("before add together\n\n")
	// printDebug(ct, context, 33*33*3*2+1, 7)

	for w1 := 0; w1 < ki; w1++ {
		for w2 := 0; w2 < ti; w2++ {
			temp, _ = context.evaluator.MulNew(ct, select_one_vec[w1][w2])
			w3, w4, w5 := ((ki*w2+w1)%(2*ko))/2, (ki*w2+w1)%2, (ki*w2+w1)/(2*ko)
			temp = memorySaveRotateCipher(temp, context, ki*ki*hi*wi*w2 + ki*wi*w1 - ko*ko*ho*wo*w5 - ko*wo*w3 - ki*w4 - ko*ko*ho*wo*(ti/8), n);
			// Combine the rotated tensor vectors
			if w1 == 0 && w2 == 0 {
				sum = temp.CopyNew()
			} else {
				context.evaluator.Add(sum, temp, sum)
			}
		}
	}

	context.evaluator.Rescale(sum, sum)
	ct = sum
	// Combine tensor vectors for fprime packing
	// fmt.Println("\n\n\n\nafter add rescale\n\n\n\n\n")
	// printDebug(ct, context, 7, 7)

	sum = ct.CopyNew()
	for u6 := 1; u6 < po; u6++ {
		temp = ct
		temp = memorySaveRotateCipher(temp, context, -(n/po)*u6, n)
		context.evaluator.Add(sum, temp, sum)
	}

	// Return new Tensor
	return NewTensorCipherWithCT(logn, ko, ho, wo, co, to, po, sum)
}

func cnnAddCipher(cnn1, cnn2 *TensorCipher, context *testParams) (*TensorCipher, error) {
	// Error check
	if cnn1.k != cnn2.k || cnn1.h != cnn2.h || cnn1.w != cnn2.w ||
		cnn1.c != cnn2.c || cnn1.t != cnn2.t || cnn1.p != cnn2.p || cnn1.logn != cnn2.logn {
		return &TensorCipher{}, fmt.Errorf("the parameters of cnn1 and cnn2 are not the same")
	}

	// Addition
	var temp1, temp2 *rlwe.Ciphertext
	temp1 = cnn1.cipher
	temp2 = cnn2.cipher
	context.evaluator.Add(temp1, temp2, temp1)

	return NewTensorCipherWithCT( cnn1.logn, cnn1.k, cnn1.h, cnn1.w, cnn1.c, cnn1.t, cnn1.p, temp1)
}

// averagePoolingPlainScale simulates average pooling on tensors.
func averagePoolingCipherScale(cnnIn *TensorCipher, B float64, context *testParams) (*TensorCipher, error) {
	// parameter setting
	ki, hi, wi, ci, ti, logn := cnnIn.k, cnnIn.h, cnnIn.w, cnnIn.c, cnnIn.t, cnnIn.logn
	ko, ho, wo, co, to := 1, 1, 1, ci, ti

	n := 1 << cnnIn.logn

	if log2Long( hi ) == -1 {
		panic("hi is not power of two")
	}
	if log2Long( wi ) == -1 {
		panic("wi is not power of two")
	}

	var ct, sum, temp *rlwe.Ciphertext
	ct = cnnIn.cipher

	// sum_hiwi
	for x := 0; x<log2Long(wi); x++ {
		temp = ct
		temp = memorySaveRotateCipher(temp, context, pow2(x)*ki, n)
		context.evaluator.Add(ct, temp, ct)
	}
	
	for x := 0; x<log2Long(hi); x++ {
		temp = ct
		temp = memorySaveRotateCipher(temp, context, pow2(x)*ki*ki*wi, n)
		context.evaluator.Add(ct, temp, ct)
	}

	for s := 0; s < ki; s++ {
		for u := 0; u < ti; u++ {
			p := ki*u+s
			temp = ct
			temp = memorySaveRotateCipher(temp, context, -p*ki + ki*ki*hi*wi*u + ki*wi*s, n)
			selectOne := make([]float64, n)
			
			for i := 0; i < ki; i++ {
				selectOne[(ki*u+s)*ki+i] = B / float64(hi*wi)
			}
			temp, _ = context.evaluator.MulNew(temp, selectOne)

			if u == 0 && s == 0 {
				sum = temp.CopyNew() // double scaling factor
			} else {
				context.evaluator.Add(sum, temp, sum)
			}
		}

	}
	context.evaluator.Rescale(sum, sum)

	// Create output tensor with updated values.
	cnnOut, err := NewTensorCipherWithCT(logn, ko, ho, wo, co, to, 1, sum)
	if err != nil {
		panic("avarage pooling failed!")
	}

	return cnnOut, nil
}


// matrixMultiplicationPlain 
func matrixMultiplicationCipher(cnnIn *TensorCipher, matrix, bias []float64, q, r int, context *testParams) (*TensorCipher, error) {
	// parameter setting
	ki, hi, wi, ci, ti, pi, logn := cnnIn.k, cnnIn.h, cnnIn.w, cnnIn.c, cnnIn.t, cnnIn.p, cnnIn.logn
	ko, ho, wo, co, to, po := ki, hi, wi, ci, ti, pi

	n := 1<<logn
	if len(matrix) != q*r {
		panic("the size of matrix is not q*r")
	}
	if len(bias) != q {
		panic("the size of bias is not q")
	}

	// generate matrix and bias
	W := make([][]float64, q+r-1)
	for i := range W {
		W[i] = make([]float64, n)
	}
	b := make([]float64, n)
	for z := 0; z < q; z++ {
		b[z] = bias[z]
	}
	for i := 0; i < q; i++ {
		for j := 0; j < r; j++ {
			W[i-j+r-1][i] = matrix[i*r+j]
			if i-j+r-1<0 || i-j+r-1>=q+r-1 { panic("i-j+r-1 is out of range") }
			if i*r+j<0 || i*r+j>=int( len(matrix) ) { panic("i*r+j is out of range") }
		}
	}

	var sum, temp, ct *rlwe.Ciphertext
	ct = cnnIn.cipher
	
	for s := 0; s < q+r-1; s++ {
		temp = ct 
		temp = memorySaveRotateCipher(temp, context, r-1-s, n)
		temp, _ = context.evaluator.MulNew(temp, W[s])
		if s == 0 {
			sum = temp.CopyNew()
		} else {
			context.evaluator.Add(sum, temp, sum)
		}
	}
	context.evaluator.Rescale(sum, sum)

	return &TensorCipher{ ko, ho, wo, co, to, po, logn, sum}, nil
}

// *************************Base Operations************************


func memorySaveRotateCipher(cipherIn *rlwe.Ciphertext, context *testParams, steps int, n int)  ( *rlwe.Ciphertext ) {
	steps = (steps + n) % n
	if steps == 0{return cipherIn}
	var rtnCipher *rlwe.Ciphertext
    if 34 <= steps && steps <= 55 {
        rtnCipher, _ = context.evaluator.RotateNew(cipherIn, 33)
        context.evaluator.Rotate(rtnCipher, steps-33, rtnCipher)
    } else if 57 <= steps && steps <= 61 {
        rtnCipher, _ = context.evaluator.RotateNew(cipherIn, 33)
        context.evaluator.Rotate(rtnCipher, steps-33, rtnCipher)
    } else {
        rtnCipher, _ = context.evaluator.RotateNew(cipherIn, steps)
    }
	return rtnCipher
}


func bootstrapReEnc(cipherIn *rlwe.Ciphertext, context *testParams) (freshCt *rlwe.Ciphertext) {
	plain := context.decryptor.DecryptNew(cipherIn)
	valuesTest := make([]float64, context.params.MaxSlots() )
	context.encoder.Decode(plain, valuesTest)
	PrintDebugVec(valuesTest, 7, 7)

	plain2 := ckks.NewPlaintext(context.params, context.remainingLevel)
	context.encoder.Encode( valuesTest, plain2)
	freshCt, err := context.encryptor.EncryptNew( plain2 )
	if err != nil {
		panic(err)
	}
	
	return 
}