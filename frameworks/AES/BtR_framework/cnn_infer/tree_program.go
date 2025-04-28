package cnn_infer

import (
	"fmt"
	"math"
)

type evaltype int

const (
	none evaltype = iota
	oddbaby
	baby
)

type Tree struct {
	depth int
	typ   evaltype
	m     int
	l     int
	b     int
	tree  []int
}

func NewTree() *Tree {
	return &Tree{
		depth: 0,
		typ:   none,
		m:     0,
		l:     0,
		b:     0,
		tree:  []int{-1, 0},
	}
}

func NewTreeWithType(ty evaltype) *Tree {
	return &Tree{
		depth: 0,
		typ:   ty,
		m:     0,
		l:     0,
		b:     0,
		tree:  []int{-1, 0},
	}
}

func NewTreeWithMerge(a, b *Tree, g int) (*Tree, error) {
	if a.typ != b.typ {
		return nil, fmt.Errorf("the types of two trees are not the same")
	}
	depth := int(math.Max(float64(a.depth), float64(b.depth))) + 1
	t := &Tree{
		depth: depth,
		typ:   a.typ,
		tree:  make([]int, pow2(depth+1)),
	}

	for i := range t.tree {
		t.tree[i] = -1
	}
	t.tree[1] = g

	// Copy the elements from Tree 'a'
	for i := 1; i <= pow2(a.depth+1)-1; i++ {
		temp := pow2(log2(i))
		if i+temp < len(t.tree) {
			t.tree[i+temp] = a.tree[i]
		} else {
			fmt.Printf("Index out of range. Attempted to access: %d, Length: %d\n", i+temp, len(t.tree))
		}
	}
	// Copy the elements from Tree 'b'
	for i := 1; i <= pow2(b.depth+1)-1; i++ {
		temp := pow2(log2(i))
		if i+2*temp < len(t.tree) {
			t.tree[i+2*temp] = b.tree[i]
		} else {
			
			fmt.Printf("Index out of range. Attempted to access: %d, Length: %d\n", i+2*temp, len(t.tree))
		}
	}


	return t, nil
}

func pow2(exp int) int {
	return 1 << exp
}

func log2(value int) int {
	return int(math.Log2(float64(value)))
}

func log2Long(n int) (int) {
	if n > 65536 || n <= 0 {
		return -1
	}

	var d int = -1
	for i := 0; i <= 16; i++ {
		if (1 << i) == n {
			d = i
			break
		}
	}
	return d
}

func (t *Tree) Clear() {
	t.depth = 0
	t.typ = none
	t.tree = []int{-1, 0}
}

func (t *Tree) Print() {
	fmt.Printf("depth of tree: %d\n", t.depth)
	for i := 0; i <= t.depth; i++ {
		for j := pow2(i); j < pow2(i+1); j++ {
			fmt.Printf("%d ", t.tree[j])
		}
		fmt.Println()
	}

	nonscalar := 0
	switch t.typ {
	case oddbaby:
		fmt.Printf("m: %d\nl: %d\n", t.m, t.l)
		nonscalar = t.m - 1 + pow2(t.l-1) - 1
	case baby:
		fmt.Printf("m: %d\nb: %d\n", t.m, t.b)
		nonscalar = t.m + t.b - 2
	}

	for _, v := range t.tree {
		if v > 0 {
			nonscalar++
		}
	}
	fmt.Printf("nonscalar: %d\n", nonscalar)
}

func (t *Tree) Merge(a, b *Tree, g int) error {
	t.Clear()
	if a.typ != b.typ {
		return fmt.Errorf("the types of two trees are not the same")
	}
	t.typ = a.typ
	t.depth = int(math.Max(float64(a.depth), float64(b.depth))) + 1
	t.tree = make([]int, pow2(t.depth+1))

	for i := range t.tree  {
		t.tree[i] = -1
	}
	t.tree[1] = g

	// Copy the elements from Tree 'a'
	for i := 1; i <= pow2(a.depth+1)-1; i++ {
		temp := pow2(log2(i))
		if i+temp < len(t.tree) {

			t.tree[i+temp] = a.tree[i]
		} else {
			fmt.Printf("Index out of range. Attempted to access: %d, Length: %d\n", i+temp, len(t.tree))
		}
	}
	// Copy the elements from Tree 'b'
	for i := 1; i <= pow2(b.depth+1)-1; i++ {
		temp := pow2(log2(i))
		if i+2*temp < len(t.tree) {
			t.tree[i+2*temp] = b.tree[i]
		} else {
			fmt.Printf("Index out of range. Attempted to access: %d, Length: %d\n", i+2*temp, len(t.tree))
		}
	}

	return nil
}


func ceilToInt(x float64) int {
	return int(math.Ceil(x))
}


func upgradeOddbaby(n int) Tree {
	d := ceilToInt(math.Log2(float64(n)))
	var m, l, min int
	totalMin := 10000
	minM := 0
	minL := 0
	var minTree, totalMinTree Tree
	for l = 1; pow2(l)-1 <= n; l++ {
		for m = 1; pow2(m-1) < n; m++ {
			// initialization
			f := make([][]int, n+1)
			for i := range f {
				f[i] = make([]int, d+1)
			}
			G := make([][]Tree, n+1)
			for i := range G {
				G[i] = make([]Tree, d+1)
				for j := range G[i] {
					// Set each Tree in array as oddbaby
					G[i][j].Clear()
					G[i][j].typ = oddbaby
				}
			}
			f[1][1] = 0
			for i := 3; i <= n; i += 2 {
				f[i][1] = 10000
			}
			// recursion
			for j := 2; j <= d; j++ {
				for i := 1; i <= n; i += 2 {
					if i <= pow2(l)-1 && i <= pow2(j-1) {
						f[i][j] = 0
					} else {
						min = 10000
						minTree.Clear()
						for k := 1; k <= m-1 && pow2(k) < i && k < j; k++ {
							g := pow2(k)
							if f[i-g][j-1]+f[g-1][j]+1 < min {
								min = f[i-g][j-1] + f[g-1][j] + 1
								minTree.Merge( &G[g-1][j], &G[i-g][j-1], g)
							}
						}
						f[i][j] = min
						G[i][j] = minTree
					}
				}
			}
			if f[n][d]+pow2(l-1)+m-2 < totalMin {
				totalMin = f[n][d] + pow2(l-1) + m - 2
				totalMinTree = G[n][d]
				minM = m
				minL = l
			}
		}
	}
	// fmt.Printf("deg %d: %d\n", n, totalMin)
	// fmt.Printf("m: %d, l: %d\n", minM, minL)
	totalMinTree.m = minM
	totalMinTree.l = minL

	return totalMinTree
}

func upgradeBaby(n int) Tree {
	d := ceilToInt(math.Log2(float64(n))) // Required minimum depth.
	var m, b int
	totalMin := 10000
	minM := 0
	minB := 0
	// Pre-initialize totalMinTree according to `baby` evaluation type.
	totalMinTree := Tree{typ: baby}

	if n == 1 {
		totalMin = 0
		totalMinTree = Tree{typ: baby}
		minM = 1
		minB = 1
	}

	for b = 1; b <= n; b++ {
		for m = 1; pow2(m-1)*b <= n; m++ {
			f := make([][]int, n+1)
			for i := range f {
				f[i] = make([]int, d+1)
			}

			G := make([][]Tree, n+1)
			for i := range G {
				G[i] = make([]Tree, d+1)
				for j := range G[i] {
					G[i][j].Clear()
					G[i][j].typ = baby
				}
			}
			// recursion
			for j:=1; j<=d; j++ {
				for i:=1; i<=n; i++ {

					if i+1 > pow2(j) {
						f[i][j] = 10000;
						G[i][j] = Tree{typ: baby};
					} else if b==1 && m>=2 && i<=2 && i<=pow2(j-1) {
						f[i][j] = 0;
						G[i][j] = Tree{typ: baby}
					} else if i<=b && i<=pow2(j-1) {
						f[i][j] = 0;
						G[i][j] = Tree{typ: baby}
					} else {
						min := 10000;
						minTree := Tree{}
						for k:=2; k<=b; k++ {
							g := k
							if g<=pow2(j-1) && 2<=g && g<i && f[i-g][j-1] + f[g-1][j] +1 < min {
								min = f[i-g][j-1] + f[g-1][j] +1;
								minTree.Merge(&G[g-1][j], &G[i-g][j-1], g);
							} 
						}
						for k:=0; k<=m-1; k++ {
							g := pow2(k)*b
							if g<=pow2(j-1) && 2<=g && g<i && f[i-g][j-1] + f[g-1][j] +1 < min {
								min = f[i-g][j-1] + f[g-1][j] +1
								minTree.Merge(&G[g-1][j], &G[i-g][j-1], g)
							} 
						}
						f[i][j] = min;
						G[i][j] = minTree;
						if min == 10000 {
							fmt.Println("no g found ", b, m, j, i )
						}
					}
				}
			}

			if f[n][d]+m+b-2 < totalMin {
				totalMin = f[n][d] + m + b - 2
				totalMinTree = G[n][d]
				minM = m
				minB = b
			}
		}
	}

	fmt.Printf("deg %d: %d\n", n, totalMin)
	fmt.Printf("m: %d, b: %d\n", minM, minB)

	totalMinTree.m = minM
	totalMinTree.b = minB

	return totalMinTree
}
