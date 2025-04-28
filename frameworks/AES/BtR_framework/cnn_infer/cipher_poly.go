package cnn_infer

import (
	"math"
	"math/bits"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

//***************************Polynomial Evaluation****************************
func evalPolynomialIntegrateCipher( cipher *rlwe.Ciphertext, deg int, decompCoeff []float64, tree *Tree, context *testParams) (rtnCipher *rlwe.Ciphertext) {
	n := 1<<context.params.LogMaxSlots()
	scale := cipher.Scale

	totalDepth := ceilToInt(math.Log2(float64(deg+1)))

	evalType := tree.typ
	decompDeg := make([]int, pow2(tree.depth+1))
	for i := range decompDeg {
		decompDeg[i] = -1
	}
	startIndex := make([]int, pow2(tree.depth+1))
	for i := range startIndex {
		startIndex[i] = -1
	}
	var T [100]*rlwe.Ciphertext
	var pt [100]*rlwe.Ciphertext

	mZero := make([]complex128, n)
	mPlain := ckks.NewPlaintext( context.params, context.params.MaxLevel())
	context.encoder.Encode(mZero, mPlain)
	ctxtZero, err := context.encryptor.EncryptNew(mPlain)
	if err != nil {
		panic(err)
	}

	var tempIndex int
	if evalType == oddbaby {
		tempIndex = 1
	} else if evalType == baby {
		tempIndex = 0
	}
	
	// evaluate decompose polynomial degrees
	decompDeg[1] = deg
	for i := 1; i <= tree.depth; i++ {
		for j := pow2(i); j < pow2(i+1); j++ {
			if j >= len(decompDeg) {
				panic("invalid index")
			}
			if j%2 == 0 {
				decompDeg[j] = tree.tree[j/2] - 1
			} else {
				decompDeg[j] = decompDeg[j/2] - tree.tree[j/2]
			}
		}
	}
	
	// compute start index
	for i := 1; i < pow2(tree.depth+1); i++ {
		if tree.tree[i] == 0 {
			startIndex[i] = tempIndex
			tempIndex += decompDeg[i] + 1
		}
	}	

	// In fact, basis_type is meaningless
	T[0], T[1] = geneT0T1( cipher, context )

	if evalType == oddbaby{
		for i := 1; i<=totalDepth; i++{
			for j := 1; j < pow2(tree.depth+1); j++{
				if tree.tree[j] == 0 && totalDepth+1 - bits.OnesCount(uint(j)) == i{
					tempIdx := startIndex[j]
					// fmt.Println("before line80 i:", i, "j: ",j)

					pt[j], err = context.evaluator.MulNew(T[1], decompCoeff[tempIdx])
					if err != nil {
						panic(err)
					}

					// fmt.Println("line80 i:", i, "j: ",j)
					tempIdx += 2
					for k := 3; k <= decompDeg[j]; k+=2{
						// fmt.Println("\n\n\nin k", i, "j: ",j)
						temp1, err := context.evaluator.MulNew(T[k], decompCoeff[tempIdx])
						if err != nil {
							panic(err)
						}
						context.evaluator.Add(pt[j], temp1, pt[j])
						tempIdx += 2
					} 
					context.evaluator.Rescale(pt[j], pt[j])
					
				}
				
			}

			// fmt.Println("first loop")
			// printDebug(&pt[1], context, 7, 7)
			// depth i computation. all intersection points.
			for j := 1; j < pow2(tree.depth+1); j++{
				if tree.tree[j] > 0 && totalDepth + 1 - bits.OnesCount(uint(j)) == i && j%2 == 1{ 	// depth i stage intersection points
					k := j
					pt[j], err = context.evaluator.MulRelinNew(T[tree.tree[k]], pt[2*k+1])			
					if err != nil {
						panic(err)
					}		
					k*=2
					for	{
						if tree.tree[k]==0 { break }
						temp1, err := context.evaluator.MulRelinNew(T[tree.tree[k]], pt[2*k+1] )	
						if err != nil {
							panic(err)
						}
						context.evaluator.Add(pt[j], temp1, pt[j])
						k *= 2
					}
					context.evaluator.Rescale(pt[j], pt[j])
					context.evaluator.Add(pt[j], pt[k], pt[j])

					// fmt.Println("\n\n\npt:", *pt[j])
				} 
			}
			// fmt.Println("second loop")
			// printDebug(&pt[1], context, 7, 7)
			// Ti evaluation
			if i <= tree.m-1{
				// fmt.Println("T: ", pow2(i) )
				T[pow2(i)] = evalT( T[pow2(i-1)], T[pow2(i-1)], T[0], context )
			}
			if i <= tree.l{
				for j := pow2(i-1)+1; j <= pow2(i)-1; j+=2{
					T[j] = evalT( T[pow2(i-1)], T[j-pow2(i-1)], T[pow2(i)-j], context )
				}
			}
			// fmt.Println("last loop")
			// printDebug(&pt[1], context, 7, 7)

		}
		// fmt.Println("last loop")
		// printDebug(&pt[1], context, 7, 7)
		return pt[1]// Placeholder; return an actual error if there are any during the computation
	}else if evalType == baby {
		for i := 1; i<=totalDepth; i++{
			for j := 1; j < pow2(tree.depth+1); j++{
				if tree.tree[j] == 0 && totalDepth+1 - bits.OnesCount(uint(j)) == i{
					tempIDX := startIndex[j]
					pt[j] = ctxtZero.CopyNew()
					for k:=0; k<=decompDeg[j]; k++	{
						// cout << "coeff[temp_idx]: " <<  coeff[temp_idx] << endl;
						if math.Abs(decompCoeff[tempIDX]) > 1.0/scale.Float64() {
							if T[k] == nil {panic("T[k] is not set")}	
							temp1, err := context.evaluator.MulNew(T[k], decompCoeff[tempIDX])
							if err != nil {
								panic(err)
							}
							context.evaluator.Add(pt[j], temp1, pt[j])		// this is lazy scaling!!
						}
						tempIDX++
					}
					context.evaluator.Rescale(pt[j], pt[j])
				}

			}

			// depth i computation. all intersection points.
			inter := make([]int, 40)
			interNum := 0;

			for j := 1; j < pow2(tree.depth+1); j++{
				if tree.tree[j] > 0 && totalDepth + 1 - bits.OnesCount(uint(j)) == i{ 	// depth i stage intersection points
					temp := j
					noExecute := false

					for k := 0; k < interNum; k++{
						for{
							if temp == inter[k]{
								noExecute = true
								break
							}
							if temp%2 == 0{
								temp /= 2
							}else{
								break
							} 

						}

					}

					if !noExecute{
						inter[interNum] = j
						interNum += 1
						k := j
						if T[tree.tree[k]] == nil {panic("T[tree.tree[k]] is not set")}
						if pt[2*k+1] == nil {panic("pt[2*k+1] is not set")}
						context.evaluator.MulRelin(T[tree.tree[k]], pt[2*k+1], pt[j])
						k *= 2
						for{
							if tree.tree[k]==0 {break}
							if T[tree.tree[k]] == nil {panic("T[tree.tree[k]] is not set")}
							if pt[2*k+1] == nil {panic("pt[2*k+1] is not set")}
							temp1, err := context.evaluator.MulRelinNew(T[tree.tree[k]], pt[2*k+1])
							if err != nil {
								panic(err)
							}
							context.evaluator.Add(pt[j], temp1, pt[j])
							k*=2;						
						}
						context.evaluator.Rescale(pt[j], pt[j])
						context.evaluator.Add(pt[j], pt[k], pt[j])
					}
				} 
			}
			// Ti evaluation TODO
			for j := 2; j<=tree.b; j++{
				g := j
				if pow2(i-1) < g && g <= pow2(i){
					if g%2 == 0{
						if T[g/2] == nil { panic("T[g/2] is not set") }
						if T[0] == nil {panic("T[0] is not set")}
						T[g] = evalT( T[g/2], T[g/2], T[0], context)
					}else{
						if T[g/2] == nil {panic("T[g/2] is not set")}
						if T[(g+1)/2] == nil {panic("T[(g+1)/2] is not set")}
						if T[0] == nil {panic("T[0] is not set")}
						T[g] = evalT( T[g/2], T[(g+1)/2], T[1], context)
					}
				}
			}
			for j := 1; j <= tree.m-1; j++{
				g := pow2(j)*tree.b
				if pow2(i-1) < g && g <= pow2(i){
					if g%2 == 0{
						if T[g/2] == nil {panic("T[g/2] is not set")}
						if T[0] == nil {panic("T[0] is not set")}
						T[g] = evalT( T[g/2], T[g/2], T[0], context)
					}else{
						if T[g/2] == nil {panic("T[g/2] is not set")}
						if T[(g+1)/2] == nil {panic("T[(g+1)/2] is not set")}
						if T[0] == nil {panic("T[0] is not set")}
						T[g] = evalT( T[g/2], T[(g+1)/2], T[1], context)
					}
				}
			}
			
		}
	}
	return pt[1] // Placeholder; return an actual error if there are any during the computation

}


func evalT( Tm, Tn, Tmminusn *rlwe.Ciphertext, context *testParams) ( ctOut *rlwe.Ciphertext ) {

	tempCipher, err := context.evaluator.MulRelinNew(Tm, Tn)
	if err != nil {
		panic(err)
	}
	context.evaluator.Add(tempCipher, tempCipher, tempCipher)

	context.evaluator.Rescale(tempCipher, tempCipher)
	ctOut, err = context.evaluator.SubNew(tempCipher, Tmminusn)
	if err != nil {
		panic(err)
	}
	return 
}

func geneT0T1(cipher *rlwe.Ciphertext, context *testParams) (*rlwe.Ciphertext, *rlwe.Ciphertext) {
	n := context.params.MaxSlots()
	mOne := make([]complex128, n)
	for i := 0; i < n; i++ {
		mOne[i] = complex(1.0, 0.0)
	}

	plain1 := ckks.NewPlaintext(context.params, context.params.MaxLevel())
	context.encoder.Encode( mOne, plain1 )
	T0, err := context.encryptor.EncryptNew(plain1)
	if err != nil {
		panic(err)
	}
	T1 := cipher
	return T0, T1 // Return new instances
}

