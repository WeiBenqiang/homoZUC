#include <string.h>
#include <stdio.h>
#include "zuc.h"

int main()
{
    int result = ZUC_SelfCheck();
    printf("result: %d\n", result);
    
    // return 0;
    // unsigned int a = 0x4f341234;
    // unsigned int b = 0xefd27678;;
    // unsigned int c;

    // c = (ZUC_S0[(a >> 24) & 0xFF]) << 24 | (ZUC_S1[(a >> 16) & 0xFF]) << 16 | (ZUC_S0[(a >> 8) & 0xFF]) << 8 | (ZUC_S1[a & 0xFF]);
    // // Input:        a,b: unsigned int(32bit)
    // // Output:
    // // Return:       c, c=a+b mod 2^31-1
    // c = AddMod(a, b);
    // printf("c: %x \n", c);

    // // Input:        x: input
    // // Output:       k: exponential
    // // Return:       x*2^k mod 2^31-1
    // unsigned int  k = 3;
    // c = PowMod(a, k);
    // printf("a:%x , a*2^k mod:  %x\n", a, c);


    return 0;
}