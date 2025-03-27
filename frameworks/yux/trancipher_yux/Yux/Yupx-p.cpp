
#include <cstring>
#include "Yupx-p.h"

uint64_t Yux_F_p::Model_p(uint64_t state)
{
  if(state < 0)
  {
    return (modulus-(modulus-state)%modulus) % modulus;
  }
  else
  {
    return state%modulus;
  }
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
void Yux_F_p::addRoundKey(uint64_t state[], uint64_t RoundKey[], int round)
{
  int i;
  for(i=0;i<BlockWords;i++)
    {
      int key_id = BlockWords*round+i;
	    state[i] = (state[i] + RoundKey[key_id]) % modulus;
    }
}

void Yux_F_p::subtractRoundKey(uint64_t state[], uint64_t RoundKey[], int round)
{
  int i;
  for(i=0;i<BlockWords;i++)
    {
      int key_id = BlockWords*round+i;
	    state[i] = (state[i]+ (modulus- RoundKey[key_id])) % modulus;
    }
}


void Yux_F_p::decSboxFi(uint64_t state[], int begin)
{
  uint64_t c0=state[begin];
  uint64_t c1=state[begin+1];
  uint64_t c2=state[begin+2];
  uint64_t c3=state[begin+3];

  uint64_t temp = (c1*c2+c0+c3+roundConstant) % modulus;

  state[begin] = c1;
  state[begin+1] = c2;
  state[begin+2] = c3;
  state[begin+3] = temp;
}


void Yux_F_p::decLinearLayer(uint64_t in[16])
{
    int j;  
    uint64_t temp[16];
    for(j=0;j<16;j++){
      temp[j] = in[j];
    }  
    // invert linear Layer
    for(j=0; j<16; j++){
      in[j] =    (temp[j]
                + temp[(j+3)%16]
                + temp[(j+4)%16]
                + temp[(j+8)%16]
                + temp[(j+9)%16]
                + temp[(j+12)%16]
                + temp[(j+14)%16]) % modulus;
      }
}

// Cipher is the main function that encrypts the PlainText.
void Yux_F_p::decryption(uint64_t out[], uint64_t in[], uint64_t RoundKey[])
{
  int i, r;
  // initial key addition
  // Add Round key before first round

  for(i=0; i<BlockWords; i++){
      out[i] = in[i];
  }

  subtractRoundKey(out, RoundKey, 0);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for(r=1; r<ROUND; r++){


    // S Layer -- 4 sbox
    for(i=0; i<4; i++){
      decSboxFi(out, i*4);
      decSboxFi(out, i*4);
      decSboxFi(out, i*4);
      decSboxFi(out, i*4);
    }

    // linear Layer
    decLinearLayer(out);
    subtractRoundKey(out, RoundKey, r);
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
    subtractRoundKey(out, RoundKey, ROUND);
  }

}

void Yux_F_p::encSboxFi(uint64_t state[], int begin)
{
  uint64_t c0=state[begin];
  uint64_t c1=state[begin+1];
  uint64_t c2=state[begin+2];
  uint64_t c3=state[begin+3];

  uint64_t temp = (modulus -(c0*c1+c2 +roundConstant+(modulus -(c3)%modulus))% modulus) % modulus;

  state[begin] = temp;
  state[begin+1] = c0;
  state[begin+2] = c1;
  state[begin+3] = c2;
}


void Yux_F_p::encLinearLayer(uint64_t in[16])
{
    uint64_t temp[16];
    int j;
    
    for(j=0;j<16;j++){
      temp[j] = in[j];
      
    }  
    // linear Layer
    for(j=0; j<16; j++){
      in[j] =   ( 
                  ((temp[(j)%16] + temp[(j+4)%16]) * 9363) % modulus +
                  ((temp[(j+1)%16] + temp[(j+2)%16] +temp[(j+3)%16]
                   + temp[(j+5)%16] + temp[(j+6)%16] + temp[(j+7)%16]
                   + temp[(j+13)%16] + temp[(j+14)%16] + temp[(j+15)%16]) * 53054)  % modulus +
                  ((temp[(j+8)%16] + temp[(j+12)%16]) * 9362 )  % modulus +
                  ((temp[(j+9)%16] + temp[(j+10)%16] + temp[(j+11)%16]) * 53053)  % modulus
                ) % modulus;                 
      }
}


// Cipher is the main function that encrypts the PlainText.
void Yux_F_p::encryption(uint64_t out[], uint64_t in[], uint64_t RoundKey[])
{
  int i, r;
  // initial key addition
  // Add Round key before first round

  for(i=0; i<16; i++){
      out[i] = in[i];
  }
  addRoundKey(out, RoundKey, 0);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for(r=1;r<ROUND;r++){
    // S Layer -- 4 sbox
    for(i=0; i<4; i++){
      encSboxFi(out, i*4);
      encSboxFi(out, i*4);
      encSboxFi(out, i*4);
      encSboxFi(out, i*4);
    }
    // linear Layer
    encLinearLayer(out);
    addRoundKey(out, RoundKey, r);
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
    addRoundKey(out, RoundKey, ROUND);
  }
}

// This function produces Nb(Nr+1) round keys.
// The round keys are used in each round to encrypt the states.
void Yux_F_p::constantForKey(uint64_t RC[56][4])
{
    // Nr is the round number
    // Nk is the number of 64-bit Feistel works in the key 4bytes each round.
    
    // The first round key is the key itself. [0-4]
    int i,j,k;
    for(i=0;i<56;i++)
    {
      uint64_t tmp[4];
      for(j=0; j<4; j++)
      {
        tmp[j] = 4*i+j+1;
        // printf("%04x ",tmp[j]);

      }
      
      //Sf(tmp)
      encSboxFi(tmp, 0);
      encSboxFi(tmp, 0);
      encSboxFi(tmp, 0);
      encSboxFi(tmp, 0);

      // mcsry RC[i]=tmp;
      // memcpy(&RC[i], &tmp[0], 4);
      for(j=0; j<4; j++) {
        // printf("%04x ",tmp[j]);
        RC[i][j] = tmp[j];
      }
      // cout<< endl;
      // RC[i] = &tmp;
    }
}

// array a, length = l, <<<3
void Yux_F_p::rotation(uint64_t *a, int l,int r)
{
	uint64_t temp[l];
	for (int i = 0; i < l; i++){
		temp[i] = a[(i+r)%l];
	}
  for (int i =0; i< l; i++)
  {
    a[i]=temp[i];
  }
}

// This function produces Nb(Nr+1) round keys.
// The round keys are used in each round to encrypt the states.
long Yux_F_p::KeyExpansion(uint64_t RoundKey[], uint64_t Key[])
{
    // Nr is the round number
    // Nk is the number of 64-bit Feistel works in the key 4bytes each round.
    int Nr = ROUND;
    int Nk = BlockWords; // 128/8= 16
    
    // The first round key is the key itself. [0-4]
    int i,j,k;
    for(i=0;i<Nk;i++)
    {
        RoundKey[i]=Key[i];
    }

    uint64_t RC[56][4];
    constantForKey(RC);

    int x4id = 16;
    // the rest round key is the key it self.
    for(i=0; i<Nr*4; i++) //[1-9]
    { 

      int x0id = i*4;
      int x1id = i*4+4;
      int x2id = i*4+8;
      int x3id = i*4+12;
      // x4 = x1+x2+x3
      uint64_t x4[4];
      for(j=0;j<4;j++) 
      {
        x4[j] = (RoundKey[x1id+j] + RoundKey[x2id+j] + RoundKey[x3id+j])%modulus;
      }
      // <<<3
      rotation(x4, 4, 3);

      // x4=Sf(x4)
      encSboxFi(x4, 0);
      encSboxFi(x4, 0);
      encSboxFi(x4, 0);
      encSboxFi(x4, 0);

      // RK[i*4+16 ~ i*4+20] =x0+x4+RC[i]
      for(j=0; j<4; j++)
      {
        x4[j] =  (x4[j] + RC[i][j] + RoundKey[x0id+j]) % modulus;
        // printf("RC[ij]: %04x ", RC[i][j]);
        RoundKey[x4id+j] = x4[j];
      }
      x4id +=4;
    }
  return Nr+1;
}

//  Change to Decrypt roundkey
//  1. roundkey in reversed order
//  2. Except the first and the last roundkey, 
//     others are the roundkey with inverse transformation of the linear function.
void Yux_F_p::decRoundKey(uint64_t RoundKey_invert[], uint64_t RoundKey[])
{
    int Nr = ROUND;
    int Nk = BlockWords; // 128/8= 16
    if (1>Nr) return; // no data/key
    int i;
    // the first and last Decrypt round key donot need linear exchange
    long Begin = 0;
    long invertBegin = Nk*(Nr);
    for(int j = 0; j<Nk; j++) {
      RoundKey_invert[invertBegin+j]=RoundKey[Begin+j];
    }

    // dec round key = L^-1(key)
    for(i = 1; i<Nr; i++)
    {
        Begin = Nk*i;
        invertBegin = Nk*(Nr-i);
        uint64_t tempKey[Nk];
        // memcpy(&tempKey[0], &RoundKey[Begin], Nk);
            for(int j = 0; j<Nk; j++) {
              tempKey[j]= RoundKey[Begin+j];
            }
        decLinearLayer(tempKey);
        // memcpy(&RoundKey_invert[invertBegin], &tempKey[0], Nk);
        for(int j = 0; j<Nk; j++) {
          RoundKey_invert[invertBegin+j]= tempKey[j];
        }
    }

    // for(i = 1; i<Nr; i++)
    // {
    //     Begin = Nk*i;
    //     invertBegin = Nk*(Nr-i);
    //     for(int j = 0; j<Nk; j++) {
    //       RoundKey_invert[invertBegin+j]= RoundKey[Begin+j];
    //     }
    // }
    // the first and last Decrypt round key donot need linear exchange
    Begin = Nk*(Nr);
    invertBegin = 0;
    for(int j = 0; j<Nk; j++) {
      RoundKey_invert[invertBegin+j]= RoundKey[Begin+j];
    }

    // printf("RoundKey_invert---:\n");
    // for(int r=0;r<Nk+1; r++)
    // {
    //   for (int d=0; d< Nk; d++)
    //   {
    //     cout<<d;
    //     printf(". %04x ;",RoundKey_invert[r*Nk+d]);
    //   }
    //   cout<< "\n";
    // }
    // printf("RoundKey_invert---END!\n");

}
