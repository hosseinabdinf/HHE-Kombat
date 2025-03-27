#include <cstdio>
#include "../Yux/Yupx-p.h"



#if 1
//int main(int argc, char **argv)
int main() {

  int i, Nr=12; // Nr is round number
  int Nk= 16; // a block has Nk Words
  long roundKeySize = (Nr+1)*Nk;
  uint64_t in[Nk], enced[Nk], Key[Nk], RoundKey[roundKeySize];

  // Part 1 is for demonstrative purpose. The key and plaintext are given in the program itself.
  //     Part 1: ********************************************************
  // The array temp stores the key.
  // The array temp2 stores the plaintext.
  uint64_t plain[16] = {0x09990, 0x049e1, 0x0dac4, 0x053b5, 0x0ff86, 0x06f91, 0x07a8f, 0x0e700,
         0x0152e, 0x034b6, 0x0a16f, 0x01219, 0x00b83, 0x09ab7, 0x06b12, 0x0e2b1};
  uint64_t plain1[16] = {0x09999, 0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999};
  uint64_t temp3[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  uint64_t temp2[16]= {0x30  ,0x00  ,0x22  ,0x33  ,0x30  ,0x55  ,0x66  ,0x77, 0x30  ,0x99  ,0xAA  ,0xBB  ,0xCC  ,0xDD  ,0xEE  ,0xFF};
  // Copy the Key and PlainText
  for(i=0;i<Nk;i++)
    {
      Key[i]=temp3[i];
      in[i]=plain1[i];
    }

  Yux_F_p cipher = Yux_F_p(Nk, Nr, 65537);
  //             ********************************************************
  // The KeyExpansion routine must be called before encryption.
  cipher.KeyExpansion(RoundKey, Key);
  
  // Decrypt roundkey
  uint64_t RoundKey_invert[roundKeySize];
  cipher.decRoundKey(RoundKey_invert, RoundKey);
    
    printf("roundKeySchedule---:\n");
    for(int r=0;r<Nr+1; r++)
    {
      cout<<"round" << r <<" : ";
      for (int d=0; d< Nk; d++)
      {
        cout<<d;
        printf(". %05lx ",RoundKey[r*Nk+d]);
      }
      cout<< "\n";
    }
    printf("\nroundKeySchedule---END!\n");

    printf("RoundKey_invert---:\n");
    for(int r=0;r<Nr+1; r++)
    {
      cout<<"round" << r <<" : ";
      for (int d=0; d< Nk; d++)
      {
        cout<<d;
        printf(". %05lx ",RoundKey_invert[r*Nk+d]);
      }
      cout<< "\n";
    }
    printf("\nRoundKey_invert---END!\n");

  // The next function call encrypts the PlainText with the Key using Symmetric algorithm.
  cipher.encryption(enced, in, RoundKey);
  // Output the deccrypted text.
  printf("\nText after encryption:\n");
  for(i=0;i<Nk;i++)
    {
      printf("%05lx ",enced[i]);
    }
  printf("\n\n");

  uint64_t deced[Nk];
  cipher.decryption(deced, enced, RoundKey_invert);
  // Output the encrypted text.
  printf("\nText after decryption:\n");
  for(i=0;i<Nk;i++)
    {
      printf("%05lx ",deced[i]);
    }
  printf("\n\n");
  
  printf("\nText before encryption:\n");
  for(i=0;i<Nk;i++)
    {
      printf("%05lx ",in[i]);
    }
  printf("\n\n");

  return 0;
}
#endif

#if 0
uint64_t roundConstant = 0x1122;
uint64_t Yux_p = 65537;

uint64_t Model_p(uint64_t state)
{
  cout<< "state = " << state <<endl;
  if(state < 0)
  {
    return (Yux_p-(Yux_p-state)%Yux_p) ;
  }
  else
  {
    return state%Yux_p;
  }
}
void decSboxFi(uint64_t state[], int begin)
{
  
  uint64_t c0=state[begin];
  uint64_t c1=state[begin+1];
  uint64_t c2=state[begin+2];
  uint64_t c3=state[begin+3];

  uint64_t temp = (c1*c2+c0+c3+roundConstant) % Yux_p;

  state[begin] = c1;
  state[begin+1] = c2;
  state[begin+2] = c3;
  state[begin+3] = temp;
}

void encSboxFi(uint64_t state[], int begin)
{
  uint64_t c0=state[begin];
  uint64_t c1=state[begin+1];
  uint64_t c2=state[begin+2];
  uint64_t c3=state[begin+3];

  uint64_t temp = (Yux_p -(c0*c1+c2 +roundConstant-c3)% Yux_p) % Yux_p;
  // uint64_t temp = Model_p(c3-c0*c1-c2-roundConstant) ;

  cout << "temp=" << temp << endl;


  state[begin] = temp;
  state[begin+1] = c0;
  state[begin+2] = c1;
  state[begin+3] = c2;
}
int main() {
  uint64_t x[16] = {0x04, 0x03,0x02,0x01,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999};

  uint64_t y[16];
  for(int i=0; i<4; i++){
      encSboxFi(x, i*4);
      // decSboxFi(x, i*4);
      // decSboxFi(x, i*4);
      // decSboxFi(x, i*4);
    }

  for (int d=0; d< 16; d++)
  {
    cout<<d;
    printf(". %05lx ;",x[d]);
  }
  cout << endl;

  for(int i=0; i<4; i++){
    decSboxFi(x, i*4);
    // decSboxFi(x, i*4);
    // decSboxFi(x, i*4);
    // decSboxFi(x, i*4);
  }
  for (int d=0; d< 16; d++)
  {
    cout<<d;
    printf(". %05lx ;",x[d]);
  }
  cout << endl;
}
#endif
