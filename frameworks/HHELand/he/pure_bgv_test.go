package he

import (
	"testing"

	"github.com/tuneinsight/lattigo/v6/examples"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func TestPureBgv(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in -short mode")
	}
	TestVector := []bgv.ParametersLiteral{
		examples.BGVParamsN13QP218,
		examples.BGVParamsN14QP438,
		examples.BGVParamsN15QP880,
	}
	PureBgv(TestVector[1])
}
