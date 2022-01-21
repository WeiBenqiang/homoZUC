/*
name: zuc.h Version:
V1.1 Date: Oct 28,2016
Description: This headfile provide macro defination,parameter definition and function declaration needed in ZUC stream cipher algorithm implementation. Function List: 1.AddMod
// calculate a+b mod 2^31-1
2.PowMod 3.L1 4.L2
5.BitValue 6.GetWord
// calculate x*2^k mod 2^31-1
// linear transformation L1:X^(X<<< 2)^(X<<<10)^(X<<<18)^(X<<<24) // linear transformation L2:X^(X<<< 8)^(X<<<14)^(X<<<22)^(X<<<30) // test if the value of M at the position i equals 0 // get a 32bit word ki from bit strings k[i],k[i+1]...,
// namely ki=k[i]||k[i+1]||...||k[i+31] 7.LFSRWithInitMode
// Initialisation mode,refresh the current state of LFSR
8.LFSRWithWorkMode 9.BR 10.F
11.ZUC_Init 12.ZUC_Work
13.ZUC_GenKeyStream
// working mode,refresh the current state of LFSR // Bit Reconstruction // nonlinear function
// Initialisation process of ZUC // working stage of ZUC // generate key stream
14.ZUC_Confidentiality // the ZUC-based condifentiality algorithm 15.ZUC_Integrity
// the ZUC-based integrity algorithm
**************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern unsigned char ZUC_S0[256];
extern unsigned char ZUC_S1[256];
extern unsigned int ZUC_d[16];

//rotate n bits to the left in a 32bit buffer
#define ZUC_rotl32(x, k) (((x) << k) | ((x) >> (32 - k)))
//si = ki¡¬di¡¬ivi,in key loading
#define ZUC_LinkToS(a, b, c) (((unsigned int)(a) << 23) | ((unsigned int)(b) << 8) | (unsigned int)(c))
unsigned int AddMod(unsigned int a, unsigned int b);
unsigned int PowMod(unsigned int x, unsigned int k);
unsigned int L1(unsigned int X);
unsigned int L2(unsigned int X);
unsigned char BitValue(unsigned int M[], unsigned int i);
unsigned int GetWord(unsigned int k[], unsigned int i);
void LFSRWithInitMode(unsigned int LFSR_S[], unsigned int u);
void LFSRWithWorkMode(unsigned int LFSR_S[]);
void BR(unsigned int LFSR_S[], unsigned int BR_X[]);
unsigned int F(unsigned int BR_X[], unsigned int F_R[]);
void ZUC_Init(unsigned char k[], unsigned char iv[], unsigned int LFSR_S[], unsigned int BR_X[], unsigned int F_R[]);
void ZUC_Work(unsigned int LFSR_S[], unsigned int BR_X[], unsigned int F_R[], unsigned int pKeyStream[], int KeyStreamLen);
void ZUC_GenKeyStream(unsigned char k[], unsigned char iv[], unsigned int KeyStream[], int KeyStreamLen);
void ZUC_Confidentiality(unsigned char CK[], unsigned int COUNT, unsigned char BEARER, unsigned char DIRECTION, unsigned int IBS[], int LENGTH, unsigned int OBS[]);
unsigned int ZUC_Integrity(unsigned char IK[], unsigned int COUNT, unsigned char BEARER, unsigned char DIRECTION, unsigned int M[], int LENGTH);

int ZUC_SelfCheck();