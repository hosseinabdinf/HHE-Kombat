package cnn_infer

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func ProcessTranscipherResult( cipher *rlwe.Ciphertext, init_p, dataLenth, cur_pos int, context *testParams) ( ctOut *rlwe.Ciphertext) {
	
	//Rotate and mask zero to get data toped
	zero_mask_top := make([]float64, context.params.MaxSlots())
	
	for i:=0; i<(context.params.MaxSlots()/init_p);i++ {
		if( i < dataLenth ) {
			zero_mask_top[i] = 1.0 
		} else {
			zero_mask_top[i] = 0.0
		} 
	}

	var rotate2top *rlwe.Ciphertext
	if (cur_pos != 0){
		rotate2top = memorySaveRotateCipher(cipher, context, (dataLenth*cur_pos), context.params.MaxSlots())
	} else {
		rotate2top = cipher
	}
	
	zero_mask := ckks.NewPlaintext( context.params, cipher.Level() )
	context.encoder.Encode(  zero_mask_top, zero_mask )
	context.evaluator.Mul(rotate2top, zero_mask, rotate2top)
	context.evaluator.Rescale(rotate2top, rotate2top)
	
	var rotatedCipher []*rlwe.Ciphertext
	rotatedCipher = append(rotatedCipher, rotate2top)
	for i:=1; i<init_p; i++{
		tmp := memorySaveRotateCipher(rotate2top, context, (context.params.MaxSlots()/init_p)*i, context.params.MaxSlots())
		rotatedCipher = append(rotatedCipher, tmp)
	}
	for i:=1; i<len(rotatedCipher); i++{
		context.evaluator.Add(rotatedCipher[0], rotatedCipher[i], rotatedCipher[0])
	}
	return rotatedCipher[0]
}
