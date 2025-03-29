#include "Yu2x-16.h"

long Nks_ = 16;


// The round key is added to the state by an XOR function.
void addRoundKey(Vec<GF2E>& state, Vec<GF2E>& RoundKey, int round)
{
  int i, blockByte = Nks_;
  for(i=0;i<(blockByte);i++)
    {
      int key_id = blockByte*round+i;
	    state[i] += RoundKey[key_id];
    }
}

void encSboxFi(Vec<GF2E>& state, int begin)
{
  GF2E c0=state[begin];
  GF2E c1=state[begin+1];
  GF2E c2=state[begin+2];
  GF2E c3=state[begin+3];

  GF2E roundConstant = conv<GF2E>(GF2XFromBytes(&roundConstant_char, 1));
  GF2E temp = c0 * c1 +  c2  + c3 + roundConstant;

  state[begin] = temp;
  state[begin+1] = c0;
  state[begin+2] = c1;
  state[begin+3] = c2;
}

void encLinearLayer(Vec<GF2E>& in)
{
    Vec<GF2E> temp;
    temp.SetLength(Nks_);
    int j;
    GF2E in_all= GF2E::zero();
    for(j=0;j<Nks_;j++){
      temp[j] = in[j];
      in_all += in[j];
    }  
    // linear Layer
    for(j=0; j<Nks_; j++){
      in[j] =   in_all 
                + temp[(j)%Nks_]
                + temp[(j+4)%Nks_]
                + temp[(j+9)%Nks_]
                + temp[(j+10)%Nks_]
                + temp[(j+11)%Nks_];                 
      }
}

// Cipher is the main function that encrypts the PlainText.
void Yu2x_16_encryption(unsigned char outCh[], unsigned char inCh[], Vec<GF2E>& RoundKey, int Nr)
{
  int i,round;
  // initial key addition
  // Add Round key before first round
  Vec<GF2E> in, out;
  in.SetLength(Nks_);
  out.SetLength(Nks_);
  for(i=0;i<Nks_;i++)
  {
    unsigned char tmp[2]={inCh[2*i], inCh[2*i+1]};
    in[i] = conv<GF2E>(GF2XFromBytes(tmp, 2));
  }

  for(i=0; i<Nks_; i++){
      out[i] = in[i];
  }
  addRoundKey(out, RoundKey, 0);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for(round=1;round<Nr;round++){
    // S Layer -- 4 sbox
    for(i=0; i<4; i++){
      encSboxFi(out, i*4);
      encSboxFi(out, i*4);
      encSboxFi(out, i*4);
      encSboxFi(out, i*4);
    }
    // linear Layer
    encLinearLayer(out);
    addRoundKey(out, RoundKey, round);
  }

  // The last round is given below.
  // Linear layer is not here in the last round
  {
    for(i=0; i<4; i++){
      encSboxFi(out, i*4);
      encSboxFi(out, i*4);
      encSboxFi(out, i*4);
      encSboxFi(out, i*4);
    }
    addRoundKey(out, RoundKey, Nr);
  }

  for(i=0; i<Nks_; i++)
  {
    unsigned char p[2];
    BytesFromGF2X(p, conv<GF2X>(out[i]), 2);
    outCh[2*i] = p[0];
    outCh[2*i+1] = p[1];
  }
}

void decLinearLayer(Vec<GF2E>& in)
{
    int j;  
    Vec<GF2E> temp;
    temp.SetLength(Nks_);
    for(j=0;j<Nks_;j++){
      temp[j] = in[j];
    }  
    // invert linear Layer
    for(j=0; j<Nks_; j++){
      in[j] =    temp[j]
                + temp[(j+3)%Nks_]
                + temp[(j+4)%Nks_]
                + temp[(j+8)%Nks_]
                + temp[(j+9)%Nks_]
                + temp[(j+12)%Nks_]
                + temp[(j+14)%Nks_];
      }
}

void decSboxFi(Vec<GF2E>& state, int begin)
{
  GF2E c0=state[begin];
  GF2E c1=state[begin+1];
  GF2E c2=state[begin+2];
  GF2E c3=state[begin+3];

  GF2E roundConstant = conv<GF2E>(GF2XFromBytes(&roundConstant_char, 1));
  GF2E temp = c1 * c2 + c0 + c3 + roundConstant;

  state[begin] = c1;
  state[begin+1] = c2;
  state[begin+2] = c3;
  state[begin+3] = temp;
}

// Cipher is the main function that encrypts the PlainText.
void Yu2x_16_decryption(unsigned char outCh[], unsigned char inCh[], Vec<GF2E>& RoundKey, int Nr)
{
  int i,round;
  // initial key addition
  // Add Round key before first round

  Vec<GF2E> in, out;
  in.SetLength(Nks_);
  out.SetLength(Nks_);

  for(i=0;i<Nks_;i++)
  {
    unsigned char tmp[2]={inCh[2*i], inCh[2*i+1]};
    in[i] = conv<GF2E>(GF2XFromBytes(tmp, 2));
  }

  for(i=0; i<Nks_; i++){
      out[i] = in[i];
  }

  addRoundKey(out, RoundKey, 0);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for(round=1;round<Nr;round++){
    // S Layer -- 4 sbox
    for(i=0; i<4; i++){
      decSboxFi(out, i*4);
      decSboxFi(out, i*4);
      decSboxFi(out, i*4);
      decSboxFi(out, i*4);
    }

    // linear Layer
    decLinearLayer(out);
    addRoundKey(out, RoundKey, round);
  }

  // The last round is given below.
  // Linear layer is not here in the last round
  {
    for(i=0; i<4; i++){
      decSboxFi(out, i*4);
      decSboxFi(out, i*4);
      decSboxFi(out, i*4);
      decSboxFi(out, i*4);
    }
    addRoundKey(out, RoundKey, Nr);
  }

  for(i=0; i<Nks_; i++)
  {
    unsigned char p[2];
    BytesFromGF2X(p, conv<GF2X>(out[i]), 2);
    outCh[2*i] = p[0];
    outCh[2*i+1] = p[1];
  }
}

// This function produces Nb(Nr+1) round keys.
// The round keys are used in each round to encrypt the states.
void constantForKey(Vec<GF2E>& RCi, long round, int i)
{
    // Nr is the round number
    // Nk is the number of 64-bit Feistel works in the key 4bytes each round.
    // int Nr = round;
    RCi.SetLength(4);
    // *(GF2E *)(RC + i*4 + j)
    // The first round key is the key itself. [0-4]
    int j;

      Vec<GF2E> tmp;
      tmp.SetLength(4);
      for(j=0; j<4; j++)
      {
        unsigned char t = 4*i+j+1;
        // printf("%02x ", t);
        tmp[j] = conv<GF2E>(GF2XFromBytes(&t, 1));
      }
      // printf("!\n");
      
      //Sf(tmp)
      encSboxFi(tmp, 0);
      encSboxFi(tmp, 0);
      encSboxFi(tmp, 0);
      encSboxFi(tmp, 0);

      // mcsry RC[i]=tmp;
      RCi = tmp;
      // unsigned char p;
      // for(j=0; j<4; j++)
      // {
      //   BytesFromGF2X(&p, conv<GF2X>(RCi[j]), 1);
      //   printf("%02x ",p);
      // }
      // printf("\n");
}

// array a, length = l, <<<3
void rotation(Vec<GF2E>& a, int l, int r){
	Vec<GF2E> temp;
  temp.SetLength(l);
	for (int i = 0; i < l; i++){
		temp[i] = a[(i+r)%l];
	}
  for (int i =0; i< l; i++)
  {
    a[i]=temp[i];
  }
}

long Yu2x_16_KeyExpansion(unsigned char RoundKey[], long round, long blockByte,  unsigned char Key[])
{
    // Nr is the round number
    // Nk is the number of 64-bit Feistel works in the key 4bytes each round.
    int Nr = round;
    int Nk = blockByte; // 128/8= 16
    
    // The first round key is the key itself. [0-4]
    int i,j,k;
    for(i=0;i<Nk;i++)
    {
        RoundKey[i]=Key[i];
    }

    // the rest round key is the key it self.
    for(i=1; i<=Nr; i++) //[1-9]
    { 
      for(j=0;j<Nk;j++) //[0-16]
      {
          k = Nk * i;  // k = 8*r
          RoundKey[k+j]=Key[j]| Key[(j+i)%Nk];
      }
    }
  return Nr+1;
}


// This function produces Nb(Nr+1) round keys.
// The round keys are used in each round to encrypt the states.
// long Yu2x_16_KeyExpansion1(Vec<GF2E>& RoundKey, long round, long blockByte, unsigned char KeyCh[])
// {
//     // Nr is the round number
//     // Nk is the number of 64-bit Feistel works in the key 4bytes each round.
//     int Nr = round;
//     int Nk = blockByte; // 128/8= Nks_
    
//     // The first round key is the key itself. [0-4]
//     int i,j;
//     Vec<GF2E> Key;
//     Key.SetLength(Nks_);
//     for(i=0;i<Nks_;i++)
//     {
//       Key[i] = conv<GF2E>(GF2XFromBytes(&KeyCh[i], 1));
//     }

//     for(i=0;i<Nk;i++)
//     {
//         RoundKey[i]=Key[i];
//     }

//     Vec<Vec<GF2E>> RC;
//     int rcLength = Nk*Nr/4;
//     RC.SetLength(rcLength);
//     for(i=0;i<rcLength;i++) constantForKey(RC[i], round, i);

//     int x4id = Nk;
//     // the rest round key is the key it self.
//     for(i=0; i<rcLength; i++) //[1-9]
//     { 
//       int x0id = i*4;
//       int x1id = x0id+4;
//       int x2id = x1id+4;
//       int x3id = x2id+4;
//       // x4 = x1+x2+x3
//       Vec<GF2E> x4;
//       x4.SetLength(4);
//       for(j=0;j<4;j++) 
//       {
//         x4[j] = RoundKey[x1id+j]+ RoundKey[x2id+j]+ RoundKey[x3id+j]; 
//       }
//       // <<<3
//       rotation(x4, 4, 3);

//       // x4=Sf(x4)
//       encSboxFi(x4, 0);
//       encSboxFi(x4, 0);
//       encSboxFi(x4, 0);
//       encSboxFi(x4, 0);

//       // RK[i*4+16 ~ i*4+20] =x0+x4+RC[i]
//       for(j=0; j<4; j++)
//       {
//         x4[j] += RoundKey[x0id+j];
//         x4[j] += RC[i][j];
//         // printf("  %02x", RC[i][j]);
//         // unsigned char p;
//         // BytesFromGF2X(&p, conv<GF2X>(x4[j]), 1);
//         // printf(" %02x, ",p);
//         RoundKey[x4id+j] = x4[j];
//       }
//       // printf("\n");
//       x4id +=4;
//     }

//   return Nr+1;
// }


//  Change to Decrypt roundkey
//  1. roundkey in reversed order
//  2. Except the first and the last roundkey, 
//     others are the roundkey with inverse transformation of the linear function.
void Yu2x_16_decRoundKey(Vec<GF2E>& RoundKey_invert, Vec<GF2E>& RoundKey, long Nr, long blockByte)
{
    int Nk = blockByte; // 128/8= 16
    if (1>Nr) return; // no data/key
    int i;
    // the first and last Decrypt round key donot need linear exchange
    long Begin = 0;
    long invertBegin = Nk*(Nr);
    // memcpy(&RoundKey_invert[invertBegin], &RoundKey[Begin], Nk);
    for(i=0; i<Nk; i++)
    {
      RoundKey_invert[Nk*(Nr)+i] = RoundKey[i];
    }

    // dec round key = L^-1(key)
    for(i = 1; i<Nr; i++)
    {
        Begin = Nk*i;
        invertBegin = Nk*(Nr-i);
        Vec<GF2E> tempKey;
        tempKey.SetLength(Nk);
        for(int j=0; j<Nk; j++)
        {
          tempKey[j] = RoundKey[Begin+j];
        }
        decLinearLayer(tempKey);
        for(int j=0; j<Nk; j++)
        {
          RoundKey_invert[invertBegin+j] = tempKey[j];
        }
    }
    // the first and last Decrypt round key donot need linear exchange
    Begin = Nk*(Nr);
    invertBegin = 0;
    for(int j=0; j<Nk; j++)
    {
      RoundKey_invert[invertBegin+j] = RoundKey[Begin+j];
    }

    // printf("RoundKey_invert---:\n");
    // for(int r=0;r<(Nr+1); r++)
    // {
    //   for (int d=0; d< Nk; d++)
    //   {
    //     cout<<d;
    //     // printf(". %02x ;",RoundKey_invert[r*Nk+d]);
    //     unsigned char p;
    //     BytesFromGF2X(&p, conv<GF2X>(RoundKey_invert[r*Nk+d]), 1);
    //     printf(". %02x, ",p);
    //   }
    //   cout<< "\n";
    // }
    // printf("RoundKey_invert---END!\n");

}



