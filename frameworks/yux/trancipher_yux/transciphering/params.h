#ifndef TARANSCIPHER_PARAMS
#define TARANSCIPHER_PARAMS

#include <stdlib.h>


// 全局变量声明
static long ROUND = 12;
static long BlockSize = 128;
static long BlockByte = 16;

static long pROUND = 9;
static long BlockWords = 16;
// 分组数量
static const uint8_t roundConstant = 0xCD; // x^7+x^6+x^3+x^2+1


//#define ROUND 12
//#define BlockSize 128
//#define BlockByte BlockSize/8


#endif
