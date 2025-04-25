package he

import (
	"github.com/tuneinsight/lattigo/v6/examples"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"testing"
)

func TestPureCKKS(t *testing.T) {
	TestVector := []ckks.ParametersLiteral{
		examples.CKKSRealParamsN14QP438,
		examples.CKKSRealParamsN15QP881,
		examples.CKKSRealParamsPN16QP1761,
	}
	for _, tc := range TestVector {
		PureCKKS(tc)
	}
}

func TestChebyshevCKKS(t *testing.T) {
	TestVector := []ckks.ParametersLiteral{
		examples.CKKSRealParamsN14QP438,
		examples.CKKSRealParamsN15QP881,
		examples.CKKSRealParamsPN16QP1761,
	}
	for _, tc := range TestVector {
		ChebyshevCKKS(tc)
	}
}
