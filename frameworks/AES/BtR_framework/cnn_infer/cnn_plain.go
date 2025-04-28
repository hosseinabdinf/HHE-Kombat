package cnn_infer

import (
	"errors"
	"fmt"
	"math"
)

type Cleartext []float64

type Tensor struct {
	k, h, w, c, t, p, logn int
	vec []float64
}

func NewTensor() Tensor {

	return Tensor{}
}

func NewTensorWithParams(logn, k, h, w, c, t, p int, vec []float64) (Tensor, error) {
	

	if logn < 1 || logn > 16 {
		return Tensor{}, fmt.Errorf("the value of logn is out of range")
	}
	if len(vec) > (1 << logn) {
		return Tensor{}, fmt.Errorf("the size of data is larger than n")
	}
	n := 1 << logn
	if len(vec) < n {
		// Zero padding if vec is smaller than expected
		tmpVec := make([]float64, n)
		copy(tmpVec, vec)
		vec = tmpVec
	}
	return Tensor{k: k, h: h, w: w, c: c, t: t, p: p, logn: logn, vec: vec}, nil
}

func (t Tensor) PrintParms() {
	fmt.Printf("k: %v\nh: %v\nw: %v\nc: %v\nt: %v\np: %v\n", t.k, t.h, t.w, t.c, t.t, t.p)
}
// Define a type for easier handling of higher dimensional slices
type fourDSlice [][][][]float64
type threeDSlice [][][]float64
type twoDSlice [][]float64
type oneDSlice []float64

// Function to initialize a 4D slice
func newFourDSlice(d1, d2, d3, d4 int) fourDSlice {
    x := make(fourDSlice, d1)
    for i := range x {
        x[i] = newThreeDSlice(d2, d3, d4)
    }
    return x
}

// Function to initialize a 3D slice
func newThreeDSlice(d1, d2, d3 int) threeDSlice {
    x := make(threeDSlice, d1)
    for i := range x {
        x[i] = twoDSlice(make([][]float64, d2))
        for j := range x[i] {
            x[i][j] = make([]float64, d3)
        }
    }
    return x
}
// *************************CNN Operations************************

func MultiplexedParallelConvolutionPlain(cnnIn Tensor, co, st, fh, fw int, data, runningVar, constantWeight []float64, epsilon float64, pool [][]float64, end bool) (Tensor, error) {
	
	ki, hi, wi, ci, ti, pi, logn := cnnIn.k, cnnIn.h, cnnIn.w, cnnIn.c, cnnIn.t, cnnIn.p, cnnIn.logn
	ko, ho, wo, to, po := 0, 0, 0, 0, 0	
	// error check
	if st != 1 && st != 2 {
		panic("supported st is only 1 or 2")
	}
	if int( len(data) ) != fh*fw*ci*co {
		// fmt.Println("len Data: ", len(data))
		// fmt.Println("len wanted: ", fh*fw*ci*co)
		// fmt.Println("len wanted: ", fh,fw,ci,co)
		panic("the size of data vector is not ker x ker x h x h")
	}	// check if the size of data vector is kernel x kernel x h x h'
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
						compactWeight[i1][i2][i9][j8] = weight[i1][i2][ki*ki*i7+ki*(j5%ki)+j6%ki][i8+pi*i9];
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
	ctxtIn := pool[0]
    ctZero := pool[1]
    temp := pool[2]
    sum := pool[3]
    totalSum := pool[4]
    varLbl := pool[5]

    // Example of obtaining a vector from a tensor.
    ctxtIn = cnnIn.vec // Assuming Vec() returns the internal vector representation.

	ctxtRot := make([][][]float64, fh)
    for i := range ctxtRot {
        ctxtRot[i] = make([][]float64, fw)
    }

	if fh%2 == 0 || fw%2 == 0{ panic("fh and fw should be odd") }

	for i1:=0; i1<fh; i1++ {
		for i2:=0; i2<fw; i2++ {
			if i1==(fh-1)/2 && i2==(fw-1)/2 { // i1=(fh-1)/2, i2=(fw-1)/2 means ctxt_in
				ctxtRot[i1][i2] = ctxtIn
			} else if (i1==(fh-1)/2 && i2>(fw-1)/2) || i1>(fh-1)/2{
				ctxtRot[i1][i2] = pool[6+fw*i1+i2-1]
			} else { ctxtRot[i1][i2] = pool[6+fw*i1+i2] }
		}
	}


	for i1:=0; i1<fh; i1++ {
		for i2:=0; i2<fw; i2++ {
			ctxtRot[i1][i2] = ctxtIn
			// fmt.Println("before, step: ", ki*ki*wi*(i1-(fh-1)/2) + ki*(i2-(fw-1)/2))
			// PrintDebugVec(ctxtRot[i1][i2],7,7)
			// fmt.Println(ctxtRot[i1][i2])
			memorySaveRotate(ctxtRot[i1][i2], &ctxtRot[i1][i2], ki*ki*wi*(i1-(fh-1)/2) + ki*(i2-(fw-1)/2), n);
			// fmt.Println("after")
			// fmt.Println(ctxtRot[i1][i2])
			// PrintDebugVec(ctxtRot[i1][i2],7,7)
			// cout << "after:" << endl;
			// for (int i = 0; i < ctxt_rot[i1][i2].size(); i++) {
			// 	cout << ctxt_rot[i1][i2][i] << " ";
			// }
			// cout << endl;
		}
	}
	fmt.Println("Chao line 221: ctxt Rot")
	PrintDebugVec(ctxtRot[0][1], 7, 7)

	for i9:=0; i9<q; i9++ {
		// weight multiplication
		// cout << "multiplication by filter coefficients" << endl;
		for i1:=0; i1<fh; i1++ {
			for i2:=0; i2<fw; i2++ {
				temp, _ = multiplyVec(ctxtRot[i1][i2], compactWeight[i1][i2][i9])
				if i1==0 && i2==0 {sum = temp} else {sum, _ = addVec(sum, temp)}
			}
		}

		// TODO: (don't worry about scales in plaintext)
		varLbl = sum

		fmt.Println("Chao line  First break: ctxt Rot")
		PrintDebugVec(varLbl, 7, 7)
		// summation for all input channels
		// cout << "summation for all input channels" << endl;
		d := log2Long(ki)
		c := log2Long(ti)

		for x:=0; x<d; x++ {
			temp = varLbl
			memorySaveRotate(temp, &temp, pow2(x), n);
			varLbl, _ = addVec(varLbl, temp)
		}
		fmt.Println("Chao line  second break: ctxt Rot")
		PrintDebugVec(varLbl, 7, 7)

		for x:=0; x<d; x++ {
			temp = varLbl
			memorySaveRotate(temp, &temp, pow2(x)*ki*wi, n)
			varLbl, _ = addVec(varLbl, temp);
		}
		fmt.Println("Chao line  third break: ctxt Rot")
		PrintDebugVec(varLbl, 7, 7)

		if c==-1 {
			sum = ctZero
			for x:=0; x<ti; x++ {
				temp = varLbl
				memorySaveRotate(temp, &temp, ki*ki*hi*wi*x, n)
				sum, _ = addVec(sum, temp)
			}
			varLbl = sum
		} else {
			for x:=0; x<c; x++ {
				temp = varLbl
				memorySaveRotate(temp, &temp, pow2(x)*ki*ki*hi*wi, n)
				varLbl, _ = addVec(varLbl, temp)
			}
		}
		fmt.Println("Chao line  fourth break: ctxt Rot")
		PrintDebugVec(varLbl, 7, 7)

		// collecting valid values into one ciphertext.
		// cout << "collecting valid values into one ciphertext." << endl;
		for i8:=0; i8<pi && pi*i9+i8<co; i8++ {
			j4 := pi*i9+i8
			if j4 >= co { panic("the value of j4 is out of range!") }
			temp = varLbl
			memorySaveRotate(temp, &temp, (n/pi)*(j4%pi) - j4%ko - (j4/(ko*ko))*ko*ko*ho*wo - ((j4%(ko*ko))/ko)*ko*wo, n)
			temp, _ = multiplyVec(temp, selectOneVec[j4])
			if i8==0 && i9==0 {
				totalSum = temp
			} else { totalSum, _ = addVec(totalSum, temp) }
		}

	}
	// evaluator.rescale_to_next_inplace(*total_sum);
	varLbl = totalSum
	fmt.Println("End point")
	PrintDebugVec(varLbl, 7, 7)
	// po copies
	if !end {
		// cout << "po copies" << endl;
		sum = ctZero
		for u6:=0; u6<po; u6++ {
			temp = varLbl
			memorySaveRotate(temp, &temp, -u6*(n/po), n)
			sum, _ = addVec(sum, temp)
		}
		varLbl = sum
	}
	fmt.Println("co infunc: ", co)
	
	return NewTensorWithParams(logn, ko, ho, wo, co, to, po, varLbl)
}

// MultiplexedParallelBatchNormPlain converts the C++ function to Go.
func MultiplexedParallelBatchNormPlain(cnnIn Tensor, bias, runningMean, runningVar, weight []float64, epsilon float64, B float64, end bool) (Tensor, error) {
	// Parameter setting (Based on the Tensor methods available).
	ki, hi, wi, ci, ti, pi, logn := cnnIn.k, cnnIn.h, cnnIn.w, cnnIn.c, cnnIn.t, cnnIn.p, cnnIn.logn
	ko, ho, wo, co, to, po := ki, hi, wi, ci, ti, pi
	
	// The remaining variables such as ti, pi, logn are similarly set ...

	// ... Error checks similar to those in the C++ function ...
	if (len(bias) != ci) || (len(runningMean) != ci) || (len(runningVar) != ci) || (len(weight) != ci) {
		fmt.Println("ci: ", ci)
		fmt.Println("bias: ",len(bias), "runningMean", len(runningMean), "runningVar", len(runningVar), "weight", len(weight))
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

	// Encode & encrypt
	temp := cnnIn.vec

	// Batch norm
	temp, _ = subVec(temp, g)

	return NewTensorWithParams(logn, ko, ho, wo, co, to, po, temp)
}

func ReLU_plain(cnnIn Tensor, compNo int, deg []int, alpha int, tree []*Tree, scaledVal float64, scalingFactor int, scale float64) (Tensor, error) {
	ki, hi, wi, ci := cnnIn.k, cnnIn.h, cnnIn.w, cnnIn.c
	logn := cnnIn.logn

	// Error check
	if hi*wi*ci > (1 << logn) {
		panic("hi*wi*ci should not be larger than n")
	}

	// ReLU
	temp, err := minimax_ReLU_plain(compNo, deg, alpha, tree, scaledVal, scalingFactor, cnnIn.vec)
	if err != nil {
		panic("ReLU failed")
	}

	// Create and return the output Tensor with the updated vector
	return NewTensorWithParams(logn, ki, hi, wi, ci, cnnIn.t, cnnIn.p, temp)
}

func multiplexedParallelDownsamplingPlain(cnnIn Tensor) (Tensor, error) {
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
		return Tensor{}, errors.New("ti is not multiple of 8")
	}
	if hi%2 != 0 || wi%2 != 0 {
		return Tensor{}, errors.New("hi and wi must be even")
	}
	if n%po != 0 {
		return Tensor{}, errors.New("n is not divisible by po")
	}

	ct := make([]float64, n)
	sum := make([]float64, n)
	var temp []float64
	copy(ct, cnnIn.vec)

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

	for w1 := 0; w1 < ki; w1++ {
		for w2 := 0; w2 < ti; w2++ {
			temp, _ = multiplyVec(ct, select_one_vec[w1][w2])
			w3, w4, w5 := ((ki*w2+w1)%(2*ko))/2, (ki*w2+w1)%2, (ki*w2+w1)/(2*ko)
			memorySaveRotate(temp, &temp, ki*ki*hi*wi*w2 + ki*wi*w1 - ko*ko*ho*wo*w5 - ko*wo*w3 - ki*w4 - ko*ko*ho*wo*(ti/8), n);
			// Combine the rotated tensor vectors
			if w1 == 0 && w2 == 0 {
				sum = temp
			} else {
				sum, _ = addVec(sum, temp)
			}
		}
	}

	// Combine tensor vectors for fprime packing
	ct = sum
	for u6 := 1; u6 < po; u6++ {
		memorySaveRotate(ct, &temp, -(n/po)*u6, n)
		sum, _ = addVec(sum, temp)
	}

	// Return new Tensor
	return NewTensorWithParams(logn, ko, ho, wo, co, to, po, sum)
}

func cnnAddPlain(cnn1, cnn2 Tensor) (Tensor, error) {
	// Error check
	if cnn1.k != cnn2.k || cnn1.h != cnn2.h || cnn1.w != cnn2.w ||
		cnn1.c != cnn2.c || cnn1.t != cnn2.t || cnn1.p != cnn2.p || cnn1.logn != cnn2.logn {
		return Tensor{}, fmt.Errorf("the parameters of cnn1 and cnn2 are not the same")
	}

	// Addition
	temp1, _ := addVec(cnn1.vec, cnn2.vec)
	return NewTensorWithParams( cnn1.logn, cnn1.k, cnn1.h, cnn1.w, cnn1.c, cnn1.t, cnn1.p, temp1)
}
 
// averagePoolingPlainScale simulates average pooling on tensors.
func averagePoolingPlainScale(cnnIn Tensor, B float64) (Tensor, error) {
	// parameter setting
	ki, hi, wi, ci, ti, logn := cnnIn.k, cnnIn.h, cnnIn.w, cnnIn.c, cnnIn.t, cnnIn.logn
	ko, ho, wo, co, to := 1, 1, 1, ci, ti

	n := 1 << cnnIn.logn
	fmt.Println("cnn_in size:", len(cnnIn.vec))
	fmt.Println("n:", n)

	if log2Long( hi ) == -1 {
		panic("hi is not power of two")
	}
	if log2Long( wi ) == -1 {
		panic("wi is not power of two")
	}

	ct := cnnIn.vec
	sum := make([]float64, n)
	temp := make([]float64, n)

	// sum_hiwi
	for x := 0; x<log2Long(wi); x++ {
		temp = ct
		memorySaveRotate(temp, &temp, pow2(x)*ki, n)
		ct, _ = addVec(ct, temp)
	}
	
	for x := 0; x<log2Long(hi); x++ {
		temp = ct
		memorySaveRotate(temp, &temp, pow2(x)*ki*ki*wi, n)
		ct, _ = addVec(ct, temp)
	}
	
	selectOne := make([]float64, n)
	zero := make([]float64, n)
	fmt.Println("ki: ", ki, "ti: ", ti)
	for s := 0; s < ki; s++ {
		for u := 0; u < ti; u++ {
			p := ki*u+s
			temp = ct
			memorySaveRotate(temp, &temp, -p*ki + ki*ki*hi*wi*u + ki*wi*s, n)
			copy(selectOne, zero)
			
			for i := 0; i < ki; i++ {
				selectOne[(ki*u+s)*ki+i] = B / float64(hi*wi)
			}
			temp, _ = multiplyVec(temp, selectOne)

			if u == 0 && s == 0 {
				sum = temp // double scaling factor
			} else {
				sum, _ = addVec(sum, temp)
			}
		}
	}

	// Create output tensor with updated values.
	cnnOut, err := NewTensorWithParams(logn, ko, ho, wo, co, to, 1, sum)
	if err != nil {
		return Tensor{}, err
	}

	return cnnOut, nil
}


// matrixMultiplicationPlain 
func matrixMultiplicationPlain(cnnIn Tensor, matrix, bias []float64, q, r int) (Tensor, error) {
	// 参数设置
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

	sum := make([]float64, n)
	temp := make([]float64, n)
	ct := cnnIn.vec
	
	for s := 0; s < q+r-1; s++ {
		temp = ct 
		memorySaveRotate(temp, &temp, r-1-s, n)
		temp, _ := multiplyVec(temp, W[s])

		if s == 0 {
			sum = temp
		} else {
			sum, _ = addVec(sum, temp)
		}
	}

	return Tensor{ ko, ho, wo, co, to, po, logn, sum}, nil
}

// *************************CNN Operations************************


// *************************Base Operations************************
// rotateVectorPlain 返回一个新的切片，该切片是对原始切片进行了旋转操作的结果。
func rotateVectorPlain(vec []float64, steps int) []float64 {
    n := len(vec)
    if steps < 0 {
        steps = steps%n + n // 如果 steps 是负数，加上n保证是正的相对位置
    }
    out := make([]float64, n)
    
    for i := 0; i < n; i++ {
        out[i] = vec[(i+steps)%n]
    }
    return out
}

// memorySaveRotate 是一个会修改传入的 out 切片的函数，
// 它使用 rotateVectorPlain 函数来对切片进行旋转操作。
func memorySaveRotate(in []float64, out *[]float64, steps, n int) {
    // 确保步数不会超出轮转范围
    steps = (steps + n) % n
	if steps == 0{return}

    if 34 <= steps && steps <= 55 {
        *out = rotateVectorPlain(in, 33)
        *out = rotateVectorPlain(*out, steps-33)
    } else if 57 <= steps && steps <= 61 {
        *out = rotateVectorPlain(in, 33)
        *out = rotateVectorPlain(*out, steps-33)
    } else {
        *out = rotateVectorPlain(in, steps)
    }
}

// addVec adds two slices together and returns a new slice.
func addVec(a, b []float64) ([]float64, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("add - len(a) != len(b)")
	}

	// Make a new slice to store the result to avoid mutating the input slices.
	out := make([]float64, len(a))
	for i := range a {
		out[i] = a[i] + b[i]
	}
	return out, nil
}

// subVec subtracts slice b from slice a and returns a new slice.
func subVec(a, b []float64) ([]float64, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("sub - len(a) != len(b)")
	}

	out := make([]float64, len(a))
	for i := range a {
		out[i] = a[i] - b[i]
	}
	return out, nil
}

// multiplyVec multiplies two slices element-wise and returns a new slice.
func multiplyVec(a, b []float64) ([]float64, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("mul - len(a) != len(b)")
	}

	out := make([]float64, len(a))
	for i := range a {
		out[i] = a[i] * b[i]
	}
	return out, nil
}