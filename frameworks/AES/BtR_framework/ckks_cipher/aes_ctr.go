package ckks_cipher

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"math"
	"strconv"
)

type AESCtr struct {
	*RtBCipher
	iv        []byte
	blockSize int
	keySize   int
	rounds    int
	// bitIndex   	[]*BitSet
	bitSbox           []*BitSet
	sboxMonomialOrder []*BitSet
	allZeroIn         bool
}

func NewAESCtr(key_ []uint8, params_ ckks.Parameters, btpParams_ bootstrapping.Parameters, btpKey_ *bootstrapping.EvaluationKeys, encoder_ *ckks.Encoder, encryptor_ *rlwe.Encryptor, decryptor_ *rlwe.Decryptor, iv_ []byte) (*AESCtr, error) {
	rtb, err := NewRtBCipher(key_, params_, btpParams_, btpKey_, encoder_, encryptor_, decryptor_)
	if err != nil {
		return nil, err
	}
	aes := &AESCtr{
		RtBCipher: rtb,
		blockSize: 128,
		keySize:   128,
		rounds:    10,
		iv:        iv_,
		allZeroIn: true, //debug mode
	}
	var monomialOrder []*BitSet
	for i := 0; i < 8; i++ {
		x := NewBitSet(8)
		x.Set(1 << i)
		monomialOrder = append(monomialOrder, x)
	}

	aes.sboxMonomialOrder, _ = LayeredCombineBin(monomialOrder)

	for i := 0; i < 256; i++ {
		tmp := NewBitSet(8)
		tmp.Set(int(AESSbox[i]))
		aes.bitSbox = append(aes.bitSbox, tmp)
	}

	return aes, err
}

func (aes *AESCtr) DebugTest(ciphertexts []byte, bits int) ([]*rlwe.Ciphertext, error) {
	if aes.allZeroIn {
		bits = aes.params.MaxSlots() * aes.blockSize
	}
	numBlocks := int(math.Ceil(float64(bits) / float64(aes.blockSize)))

	iv := NewBitSet(aes.blockSize)
	iv.Set(0) // set iv all zero
	aes.EncryptKey()
	aes.EncryptInput(iv, numBlocks)
	state := aes.inputEncrypted
	for i := 0; i < len(state); i++ {
		if state[i] == nil {
			strMsg := "state[" + strconv.Itoa(i) + "] is nil, exit!"
			panic(strMsg)
		}
		for j := 0; j < aes.totalLevel-aes.remainingLevel+6; j++ {
			aes.DropLevel(state[i], 1)
		}
	}

	for i := 0; i < 8; i++ {
		aes.DebugPrint(state[i], "before sbox: \n")
	}

	// aes.aesRoundFunction(state[:], aes.keyEncrypted)
	evals := make([]*bootstrapping.Evaluator, 128)
	for i := 0; i < 128; i++ {
		evals[i] = aes.Evaluator.ShallowCopy()
	}
	aes.RoundFunction(state, aes.keyEncrypted)

	// valuesTest := (*aes.encoder).DecodeComplex( (*aes.decryptor).DecryptNew(state[0]), aes.params.LogSlots())
	// fmt.Println("BootReEnc debug")
	// PrintVectorTrunc(valuesTest, 7, 3)

	for i := 0; i < 8; i++ {
		aes.DebugPrint(state[i], "After One Round: \n")
	}
	return state, nil
}

func (aes *AESCtr) HEDecrypt(ciphertexts []uint8, bits int) []*rlwe.Ciphertext {
	if aes.allZeroIn {
		bits = aes.params.MaxSlots() * aes.blockSize
	}
	numBlock := int(math.Ceil(float64(bits) / float64(aes.blockSize)))

	iv := NewBitSet(aes.blockSize)
	iv.Set(0) // set iv all zero

	fmt.Println(
		"--> Number of bits: ", bits,
		", Block size: ", aes.blockSize,
		", #Blocks:", numBlock,
		", element size: ", iv.size)

	aes.EncryptKey()
	aes.EncryptInput(iv, numBlock)

	for i := 0; i < len(aes.inputEncrypted); i++ {
		if aes.inputEncrypted[i].Level() > aes.remainingLevel-5 {
			aes.Evaluator.DropLevel(aes.inputEncrypted[i], aes.inputEncrypted[i].Level()-aes.remainingLevel+5)
		}
	}
	//startAES := time.Now()
	// AES encryption **********************************************
	state := aes.AddWhiteKey(aes.inputEncrypted, aes.keyEncrypted)
	for i := 1; i < 10; i++ {
		fmt.Printf("round iterator : %d\n", i)
		aes.RoundFunction(state, aes.keyEncrypted)
	}
	fmt.Println("round iterator : last round")
	aes.LastRound(state, aes.keyEncrypted)
	// AES encryption **********************************************
	for i := 0; i < 8; i++ {
		str := "Sbox: " + strconv.Itoa(i)
		aes.DebugPrint(state[i], str)
	}
	//endAES := time.Now()
	//durationAES := endAES.Sub(startAES)
	//fmt.Printf("Code Running %d s :: %d ms\n", int(durationAES.Seconds()), int(durationAES.Milliseconds())%1000)

	// // Add cipher
	// // encode_ciphertext(ciphertexts, num_block);
	// for i := 0; i < len(state); i++ {
	// 	if (i%8 == 1) || (i%8 == 2) || (i%8 == 4) || (i%8 == 5) {
	// 		NOT( evals[0], state[i], state[i])
	// 	}
	// }

	// ch := make(chan int, len(state) )
	// for i := 0; i < len(state); i++ {
	// 	go func(i int) {
	// 		XOR(evals[i], state[i], aes.encodeCipher[i], state[i])
	// 		ch <- i
	// 	}(i)
	// }
	// for i := 0; i < len(state); i++ {
	// 	<-ch
	// }

	return state
}

func (aes *AESCtr) EncryptKey() {
	if aes.encoder == nil || aes.encryptor == nil {
		panic("encoder or encryptor is not initialized")
	}

	// fmt.Println("Starting encryption")
	aes.keyEncrypted = make([]*rlwe.Ciphertext, 0, aes.keySize)

	for i := 0; i < aes.keySize; i++ {
		if i >= len(aes.symmetricKey)*8 {
			panic("input symmetric key size is not match!")
		}

		bit := (aes.symmetricKey[i/8] >> uint(i%8)) & 1

		skDuplicated := make([]float64, aes.params.MaxSlots())
		for j := 0; j < aes.params.MaxSlots(); j++ {
			skDuplicated[j] = float64(bit)
		}
		// fmt.Printf("Encoding bit %d which is %d\n", i, bit)
		skPlain := ckks.NewPlaintext(aes.params, aes.remainingLevel)
		aes.encoder.Encode(skDuplicated, skPlain)
		if skPlain == nil {
			panic("skPlain is nil after encoding")
		}

		// fmt.Println("Before encryption")
		skBitEncrypted, err := aes.encryptor.EncryptNew(skPlain)
		if err != nil {
			panic(err)
		}

		if skBitEncrypted == nil {
			panic("skBitEncrypted is nil after encryption")
		}

		aes.keyEncrypted = append(aes.keyEncrypted, skBitEncrypted)
	}

	// fmt.Println("Encryption completed")
}

func (aes *AESCtr) EncryptInput(iv *BitSet, numBlock int) {
	aes.inputEncrypted = make([]*rlwe.Ciphertext, 0, aes.blockSize)
	inputData := make([]*BitSet, aes.params.MaxSlots())
	for i, block := range inputData {
		block = NewBitSet(aes.blockSize)
		inputData[i] = block
	}

	for i := range inputData {
		if aes.allZeroIn {
			inputData[i].Set(0)
		} else {
			inputData[i].Set(int(ctr(iv, uint64(i+1)).ToULong()))
		}
	}
	for i := 0; i < aes.blockSize; i++ {
		stateBatched := make([]complex128, aes.params.MaxSlots())
		for j := 0; j < aes.params.MaxSlots(); j++ {
			stateBatched[j] = complex(float64(inputData[j].bits[i]), 0)
		}
		stateBatchedPlain := ckks.NewPlaintext(*aes.GetParameters(), aes.remainingLevel)
		aes.encoder.Encode(stateBatched, stateBatchedPlain)
		stateBatchedEncrypted := ckks.NewCiphertext(*aes.GetParameters(), 1, aes.remainingLevel)
		err := aes.encryptor.Encrypt(stateBatchedPlain, stateBatchedEncrypted)
		if err != nil {
			panic(err)
		}
		aes.inputEncrypted = append(aes.inputEncrypted, stateBatchedEncrypted)
	}
	if aes.inputEncrypted[0] == nil {
		panic("input is not stored in aesStruct")
	}
}

func (aes *AESCtr) EncodeCiphertext(ciphertexts []uint8, numBlock int) {
	aes.encodeCipher = make([]*rlwe.Ciphertext, aes.blockSize)
	if numBlock < aes.params.MaxSlots() {
		fmt.Println("data is not full pack, fill with 0...")
	}
	encryptedData := make([]*BitSet, numBlock)
	for i, bit := range encryptedData {
		bit = NewBitSet(aes.blockSize)
		encryptedData[i] = bit
	}

	for i := range encryptedData {
		if i < numBlock {
			if aes.allZeroIn {
				encryptedData[i].Set(0)
			} else {
				for k := 0; k < aes.blockSize && i*aes.blockSize+k < numBlock*aes.blockSize; k++ {
					ind := i*aes.blockSize + k
					bit := (ciphertexts[ind/8] >> uint(ind%8)) & 1
					encryptedData[i].bits[k] = uint8(bit)
				}
			}
		} else {
			encryptedData[i].Set(0)
		}
	}
	for i := 0; i < aes.blockSize; i++ {
		var dataBatched []complex128
		for j := 0; j < aes.params.MaxSlots(); j++ {
			dataBatched = append(dataBatched, complex(float64(encryptedData[j].bits[i]), 0.0))
		}
		encryptedDataPlain := ckks.NewPlaintext(*aes.GetParameters(), aes.remainingLevel)
		aes.encoder.Encode(dataBatched, encryptedDataPlain)
		encryptedDataCtxt, err := aes.encryptor.EncryptNew(encryptedDataPlain)
		if err != nil {
			panic(err)
		}
		aes.encodeCipher = append(aes.encodeCipher, encryptedDataCtxt)
	}
}

func (aes *AESCtr) RoundFunction(state []*rlwe.Ciphertext, roundKey []*rlwe.Ciphertext) {
	fmt.Printf("Chain index before sbox: %d, scale: %f\n", state[0].Level(), state[0].LogScale())

	// SubByte
	for i := range state {
		currLevel := state[i].Level()
		for currLevel > 6 {
			aes.DropLevel(state[i], 1)
			currLevel--
		}
	}

	ch := make(chan bool, 16)
	for i := 0; i < 16; i++ {
		go func(i int) {
			evalCopy := aes.Evaluator.ShallowCopy()
			aes.aesSubbyteLUT(evalCopy, state[i*8:(i+1)*8])
			ch <- true
		}(i)
	}
	for i := 0; i < 16; i++ {
		<-ch
	}
	for i := 0; i < 8; i++ {
		aes.DebugPrint(state[i], "after Sbox")
	}

	ch = make(chan bool, 128)
	// Parallel processing for bootstrapping and cleaning tensor
	for i := 0; i < 128; i++ {
		go func(i int) {
			evalCopy := aes.Evaluator.ShallowCopy()
			state[i], _ = evalCopy.BootstrapReal(state[i])
			if i == 0 {
				aes.DebugPrint(state[i], "BTS precise: ")
			}
			CleanReal(evalCopy, state[i])
			ch <- true
		}(i)
	}
	for i := 0; i < 128; i++ {
		<-ch
	}

	// ShiftRow
	aes.ShiftRow(state)
	// fmt.Printf("MixColumn Chain: %d, scale: %f\n", state[0].Level(), state[0].LogScale() )
	// MixColumn
	aes.MixColumn(state)
	// fmt.Printf("AddRoundKey Chain: %d, scale: %f\n", state[0].Level(), state[0].LogScale() )
	// AddRoundKey
	aes.AddRoundKey(state, roundKey)
}

func (aes *AESCtr) LastRound(state []*rlwe.Ciphertext, roundKey []*rlwe.Ciphertext) {
	fmt.Printf("Chain index before sbox: %d, scale: %f\n", state[0].Level(), state[0].LogScale())
	// SubByte
	for i := range state {
		currLevel := state[i].Level()
		for currLevel > 6 {
			aes.DropLevel(state[i], 1)
			currLevel--
		}
	}
	ch := make(chan bool, 16)
	for i := 0; i < 16; i++ {
		go func(i int) {
			evalCopy := aes.Evaluator.ShallowCopy()
			aes.aesSubbyteLUT(evalCopy, state[i*8:(i+1)*8])
			ch <- true
		}(i)
	}
	for i := 0; i < 16; i++ {
		<-ch
	}

	// Parallel processing for bootstrapping and cleaning tensor
	for i := 0; i < 128; i++ {
		go func(i int) {
			evalCopy := aes.Evaluator.ShallowCopy()
			state[i], _ = evalCopy.BootstrapReal(state[i])
			if i == 0 {
				aes.DebugPrint(state[i], "BTS precise: ")
			}
			CleanReal(evalCopy, state[i])
			ch <- true
		}(i)
	}
	for i := 0; i < 128; i++ {
		<-ch
	}
	// ShiftRow
	aes.ShiftRow(state)
	// AddRoundKey
	aes.AddRoundKey(state, roundKey)
}

func (aes *AESCtr) coefficientMultMonomial(eval *bootstrapping.Evaluator, mon []*rlwe.Ciphertext, coeffArr []int, pos int) (ctOut *rlwe.Ciphertext) {
	if len(mon) != len(aes.sboxMonomialOrder) {
		panic("monomial size must equal to sbox_monomial_order!")
	}
	ctOut = mon[0].CopyNew()
	i := 0
	for i < len(mon) {
		ind := int(aes.sboxMonomialOrder[i].ToULong()) - 1
		coeff := coeffArr[ind]
		if coeff == 0 {
			i++
			continue
		}
		eval.Mul(mon[i], coeff, ctOut)
		i++
		break
	}

	for i < len(mon) {
		ind := int(aes.sboxMonomialOrder[i].ToULong()) - 1
		coeff := coeffArr[ind]
		if coeff == 0 {
			i++
			continue
		}
		tmp := ctOut.CopyNew()
		eval.Mul(mon[i], coeff, tmp)
		eval.Add(tmp, ctOut, ctOut)
		i++
	}
	eval.Add(ctOut, int(aes.bitSbox[0].bits[pos]), ctOut)
	return
}

func (aes *AESCtr) aesSubbyteLUT(eval *bootstrapping.Evaluator, SBoxIn []*rlwe.Ciphertext) {
	// construct 8-bit val of the sbox
	if len(SBoxIn) != 8 {
		panic("The input length of the Sbox is wrong (8bit)!!")
	}
	sboxMonomials, _ := LayeredCombine(eval, SBoxIn)
	SBoxIn[0] = aes.coefficientMultMonomial(eval, sboxMonomials, Sbox0[:], 0)
	SBoxIn[1] = aes.coefficientMultMonomial(eval, sboxMonomials, Sbox1[:], 1)
	SBoxIn[2] = aes.coefficientMultMonomial(eval, sboxMonomials, Sbox2[:], 2)
	SBoxIn[3] = aes.coefficientMultMonomial(eval, sboxMonomials, Sbox3[:], 3)
	SBoxIn[4] = aes.coefficientMultMonomial(eval, sboxMonomials, Sbox4[:], 4)
	SBoxIn[5] = aes.coefficientMultMonomial(eval, sboxMonomials, Sbox5[:], 5)
	SBoxIn[6] = aes.coefficientMultMonomial(eval, sboxMonomials, Sbox6[:], 6)
	SBoxIn[7] = aes.coefficientMultMonomial(eval, sboxMonomials, Sbox7[:], 7)
}

func GF2FieldMul(eval *bootstrapping.Evaluator, x []*rlwe.Ciphertext) {
	y := make([]*rlwe.Ciphertext, len(x))
	for i := 0; i < 4; i++ {
		y[0+8*i] = x[1+8*i]
		y[1+8*i] = x[2+8*i]
		y[2+8*i] = x[3+8*i]
		y[3+8*i] = XORNew(eval, x[4+8*i], x[0+8*i])
		y[4+8*i] = XORNew(eval, x[5+8*i], x[0+8*i])
		y[5+8*i] = x[6+8*i]
		y[7+8*i] = x[0+8*i]
		y[6+8*i] = XORNew(eval, x[7+8*i], x[0+8*i])
	}
	copy(x, y)
}

func (aes *AESCtr) MixColumn(x []*rlwe.Ciphertext) {
	x0, x1, x2, x3 := []*rlwe.Ciphertext{}, []*rlwe.Ciphertext{}, []*rlwe.Ciphertext{}, []*rlwe.Ciphertext{}

	for i := 0; i < 128; i++ {
		mod := i % 32
		if mod < 8 {
			x0 = append(x0, x[i])
		} else if mod >= 8 && mod < 16 {
			x1 = append(x1, x[i])
		} else if mod >= 16 && mod < 24 {
			x2 = append(x2, x[i])
		} else {
			x3 = append(x3, x[i])
		}
	}

	y0, y1, y2, y3 := make([]*rlwe.Ciphertext, len(x0)), make([]*rlwe.Ciphertext, len(x1)), make([]*rlwe.Ciphertext, len(x2)), make([]*rlwe.Ciphertext, len(x3))
	z0, z1, z2, z3 := make([]*rlwe.Ciphertext, len(x0)), make([]*rlwe.Ciphertext, len(x1)), make([]*rlwe.Ciphertext, len(x2)), make([]*rlwe.Ciphertext, len(x3))

	ch := make(chan bool, 32)
	for i := 0; i < 32; i++ {
		go func(i int) {
			evalCopy := aes.Evaluator.ShallowCopy()
			y0[i] = XORNew(evalCopy, x0[i], x1[i])
			y1[i] = XORNew(evalCopy, x1[i], x2[i])
			y2[i] = XORNew(evalCopy, x2[i], x3[i])
			y3[i] = XORNew(evalCopy, x3[i], x0[i])
			ch <- true
		}(i)
	}
	for i := 0; i < 32; i++ {
		<-ch
	}

	for i := 0; i < 32; i++ {
		go func(i int) {
			evalCopy := aes.Evaluator.ShallowCopy()
			z0[i] = XORNew(evalCopy, y1[i], x3[i])
			z1[i] = XORNew(evalCopy, y2[i], x0[i])
			z2[i] = XORNew(evalCopy, y3[i], x1[i])
			z3[i] = XORNew(evalCopy, y0[i], x2[i])
			ch <- true
		}(i)
	}
	for i := 0; i < 32; i++ {
		<-ch
	}

	GF2FieldMul(aes.Evaluator, y0)
	GF2FieldMul(aes.Evaluator, y1)
	GF2FieldMul(aes.Evaluator, y2)
	GF2FieldMul(aes.Evaluator, y3)

	for i := 0; i < 32; i++ {
		go func(i int) {
			evalCopy := aes.Evaluator.ShallowCopy()
			z0[i] = XORNew(evalCopy, z0[i], y0[i])
			z1[i] = XORNew(evalCopy, z1[i], y1[i])
			z2[i] = XORNew(evalCopy, z2[i], y2[i])
			z3[i] = XORNew(evalCopy, z3[i], y3[i])
			ch <- true
		}(i)
	}
	for i := 0; i < 32; i++ {
		<-ch
	}

	z0 = append(z0, z1...)
	z0 = append(z0, z2...)
	z0 = append(z0, z3...)
	copy(x, z0)
}

func (aes *AESCtr) ShiftRow(x []*rlwe.Ciphertext) {
	for i := 0; i < 8; i++ {
		x[1*8+i], x[5*8+i], x[9*8+i], x[13*8+i] = x[5*8+i], x[9*8+i], x[13*8+i], x[1*8+i]
		x[2*8+i], x[10*8+i], x[14*8+i], x[6*8+i] = x[10*8+i], x[14*8+i], x[6*8+i], x[2*8+i]
		x[3*8+i], x[15*8+i], x[11*8+i], x[7*8+i] = x[15*8+i], x[11*8+i], x[7*8+i], x[3*8+i]
	}
}

func (aes *AESCtr) AddWhiteKey(pt, key []*rlwe.Ciphertext) []*rlwe.Ciphertext {
	ch := make(chan bool, 128)
	for i := 0; i < 128; i++ {
		go func(i int) {
			evalCopy := aes.Evaluator.ShallowCopy()
			XOR(evalCopy, pt[i], key[i], pt[i])
			ch <- true
		}(i)
	}
	for i := 0; i < 128; i++ {
		<-ch
	}
	return pt
}

func (aes *AESCtr) AddRoundKey(state, key []*rlwe.Ciphertext) {
	ch := make(chan bool, 128)
	for i := 0; i < 128; i++ {
		go func(i int) {
			evalCopy := aes.Evaluator.ShallowCopy()
			XOR(evalCopy, state[i], key[i], state[i])
			ch <- true
		}(i)
	}
	for i := 0; i < 128; i++ {
		<-ch
	}
}
