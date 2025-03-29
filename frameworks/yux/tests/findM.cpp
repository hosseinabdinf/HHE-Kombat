#include <cstring>
#include <stdint.h>
#include <chrono>
#include <NTL/ZZX.h>
#include <NTL/GF2X.h>

#include <helib/helib.h>
#include <helib/ArgMap.h>
#include <helib/DoubleCRT.h>
#include <helib/timing.h>

using namespace helib;
using namespace std;
using namespace NTL;
#define DEBUG

int main(int argc, char **argv){
  cout << "-----------Begin-------\n";

  // ArgMapping amap;
  //            security Level/2，L, c, p,  d=16/24,  s=预计的槽数， chosen_m=0，false)
  // long FindM(long k, long L, long c, long p, long d, long s, long chosen_m, bool verbose)

    long m = 0;
    long bits = 500;

    
    for(long m = 30813; m < 50000; m++) {
        setTimersOn();
        try
        {
        double tm = -GetTime(); 

        Context context(ContextBuilder<BGV>()
                        .m(m)
                        .p(2)
                        .r(1)
                        .c(3)
                        .bits(bits)
                        .build());
        tm += GetTime();
        
        //  context.getZMStar().printout();
        IndexSet allPrimes(0,context.numPrimes()-1);
        // cout <<"-----"<<context.numPrimes()<<" primes , total bitsize="
        //     <<context.logOfProduct(allPrimes)
        //     <<", security level: "<<context.securityLevel();

        cout << "M=" << m << ", "<<context.getZMStar().getNSlots()<<" slots , !!!!! ord(p) = "
            << (context.getZMStar().getOrdP()) << ". Done in "<<tm<<" seconds\n";

        }
        catch (...)
        {
            // m++;
            cout << "bad M" << endl;
            // continue;
        }
        
        
    }
	
	
	return 0;
    
  
}

// void func1()
// {
// 	cout << "I am func1()" << endl;

// 	throw "抛个异常没毛病";
// }

// int main()
// {
// 	try
// 	{
// 		func1();
// 	}
// 	catch (const char* s)
// 	{
// 		cout << s << endl;
// 	}
// 	return 0;
// }
