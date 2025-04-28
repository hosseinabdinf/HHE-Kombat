package cnn_infer

import (
	"fmt"
	"math"
	"math/bits"
)

//***************************Polynomial Evaluation****************************
func evalPolynomialIntegrate( cipher []float64, deg int, decompCoeff []float64, tree *Tree) ([]float64, error) {
	n := len( cipher )
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
	var T [100]*[]float64
	var pt [100]*[]float64

	for i := range T {
		T[i] = nil
	}
	for i := range pt {
		pt[i] = nil
	}
	T[0] = new([]float64)
	T[1] = new([]float64)

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

	//generate T0, T1
	m_one := make([]float64, n)
	for i:=0; i<n; i++{
		m_one[i] = 1.0
	}
	*T[0] = m_one
	*T[1] = cipher

	if evalType == oddbaby{
		for i := 1; i<=totalDepth+1; i++{
			for j := 1; j < pow2(tree.depth+1); j++{
				if tree.tree[j] == 0 && totalDepth+1 - bits.OnesCount(uint(j)) == i{
					tempIdx := startIndex[j]
					pt[j] = new([]float64)
					*pt[j] = multConst(*T[1], decompCoeff[tempIdx] )
					
					tempIdx += 2
					for k := 3; k <= decompDeg[j]; k+=2{
						temp1 := multConst(*T[k], decompCoeff[tempIdx])
						*pt[j], _ = addV(*pt[j], temp1)
						tempIdx += 2
					} 
					
				}
				
			}
			
			// depth i computation. all intersection points.
			for j := 1; j < pow2(tree.depth+1); j++{
				if tree.tree[j] > 0 && totalDepth + 1 - bits.OnesCount(uint(j)) == i && j%2 == 1{ 	// depth i stage intersection points
					k := j
					pt[j] = new([]float64)
					*pt[j], _ = mulV(*T[tree.tree[k]], *pt[2*k+1])
					
					k*=2
					for	{
						if tree.tree[k]==0 { break }
						temp1, _ := mulV(*T[tree.tree[k]], *pt[2*k+1])
						
						*pt[j], _ = addV(*pt[j], temp1)
						k *= 2
					}

					*pt[j], _ = addV(*pt[j], *pt[k])

					// fmt.Println("\n\n\npt:", *pt[j])
				} 
			}
			// Ti evaluation
			if i <= tree.m-1{
				// fmt.Println("T: ", pow2(i) )
				T[pow2(i)] = new([]float64)
				evalTPlain( T[pow2(i)], *T[pow2(i-1)], *T[pow2(i-1)], *T[0] )
			}
			if i <= tree.l{
				for j := pow2(i-1)+1; j <= pow2(i)-1; j+=2{
					T[j] = new([]float64)
					evalTPlain( T[j], *T[pow2(i-1)], *T[j-pow2(i-1)], *T[pow2(i)-j] )
				}
			}

		}
		return *pt[1], nil // Placeholder; return an actual error if there are any during the computation
	}else if evalType == baby {
		for i := 1; i<=totalDepth; i++{
			for j := 1; j < pow2(tree.depth+1); j++{
				if tree.tree[j] == 0 && totalDepth+1 - bits.OnesCount(uint(j)) == i{
					pt[j] = new( []float64 )
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
						pt[j] = new([]float64)
						if T[tree.tree[k]] == nil {panic("T[tree.tree[k]] is not set")}
						if pt[2*k+1] == nil {panic("pt[2*k+1] is not set")}
						*pt[j], _ = mulV(*T[tree.tree[k]], *pt[2*k+1])
						k *= 2

						for{
							if tree.tree[k]==0 {break}
							if T[tree.tree[k]] == nil {panic("T[tree.tree[k]] is not set")}
							if pt[2*k+1] == nil {panic("pt[2*k+1] is not set")}
							temp1, _ := mulV(*T[tree.tree[k]], *pt[2*k+1]);
							*pt[j], _ = addV(*pt[j], temp1);
							k*=2;						
						}

						*pt[j], _ = addV(*pt[j], *pt[k])
					}
				} 
			}
			// Ti evaluation TODO
			for j := 2; j<=tree.b; j++{
				g := j
				if pow2(i-1) < g && g <= pow2(i){
					T[g] = new([]float64)
					if g%2 == 0{
						if T[g/2] == nil { panic("T[g/2] is not set") }
						if T[0] == nil {panic("T[0] is not set")}
						evalTPlain(T[g], *T[g/2], *T[g/2], *T[0])
					}else{
						if T[g/2] == nil {panic("T[g/2] is not set")}
						if T[(g+1)/2] == nil {panic("T[(g+1)/2] is not set")}
						if T[0] == nil {panic("T[0] is not set")}
						evalTPlain(T[g], *T[g/2], *T[(g+1)/2], *T[1])
					}
				}
			}
			for j := 1; j <= tree.m-1; j++{
				g := pow2(j)*tree.b
				if pow2(i-1) < g && g <= pow2(i){
					T[g] = new([]float64)
					if g%2 == 0{
						if T[g/2] == nil {panic("T[g/2] is not set")}
						if T[0] == nil {panic("T[0] is not set")}
						evalTPlain(T[g], *T[g/2], *T[g/2], *T[0]);
					}else{
						if T[g/2] == nil {panic("T[g/2] is not set")}
						if T[(g+1)/2] == nil {panic("T[(g+1)/2] is not set")}
						if T[0] == nil {panic("T[0] is not set")}
						evalTPlain(T[g], *T[g/2], *T[(g+1)/2], *T[1])
					}
				}
			}
			
		}
	}
	return *pt[1], nil // Placeholder; return an actual error if there are any during the computation

}


func evalTPlain(Tmplusn *[]float64, Tm, Tn, Tmminusn []float64) {
    temp, _ := mulV(Tm, Tn) // Multiply Tm and Tn element-wise
	temp, _ = addV(temp, temp) // Add temp to itself (equivalent to multiplying by 2, element-wise)
	*Tmplusn, _ = subV(temp, Tmminusn) // Subtract Tmminusn from temp element-wise and store in Tmplusn
}

func coeffNumber(deg int, tree *Tree) int {
	num := 0 // Using int64 for 'long' type equivalence in Go.

	// Slice instead of explicit array. Slices in Go can dynamically resize,
	// but here we initialize it to a fixed size based on the tree's depth.
	decompDeg := make([]int, pow2(tree.depth+1))
	decompDeg[1] = deg

	for i := 1; i <= tree.depth; i++ {
		for j := pow2(i); j < pow2(i+1); j++ {
			if j%2 == 0 {
				decompDeg[j] = int(tree.tree[j/2]) - 1
			} else if j%2 == 1 {
				decompDeg[j] = decompDeg[j/2] - int(tree.tree[j/2])
			}
		}
	}

	for i := 0; i < pow2(tree.depth+1); i++ {
		if tree.tree[i] == 0 {
			num += (decompDeg[i] + 1)
		}
	}

	return num
}

// multConst multiplies each element of a slice by a constant.
func multConst(a []float64, c float64) []float64 {
	out := make([]float64, len(a))
	for i := range out {
		out[i] = a[i] * c
	}
	return out
}

// addV adds two slices element-wise.
func addV(a, b []float64) ([]float64, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("add - len(a) != len(b)")
	}
	out := make([]float64, len(a))
	for i := range a {
		out[i] = a[i] + b[i]
	}
	return out, nil
}

// subV subtracts the second slice from the first slice element-wise.
func subV(a, b []float64) ([]float64, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("subtract - len(a) != len(b)")
	}
	out := make([]float64, len(a))
	for i := range a {
		out[i] = a[i] - b[i]
	}
	return out, nil
}

// mulV multiplies two slices element-wise.
func mulV(a, b []float64) ([]float64, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("multiply - len(a) != len(b)")
	}
	out := make([]float64, len(a))
	for i := range a {
		out[i] = a[i] * b[i]
	}
	return out, nil
}