/*
 * @Author: Wei Benqiang 
 * @Date: 2022-01-11 20:13:47 
 * @Last Modified by: James
 * @Last Modified time: 2022-01-12 11:03:53
 */

#include <iostream>
#include <tfhe/tfhe_core.h>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_garbage_collector.h>
#include <time.h>
#include "zuc.h"
using namespace std;

const int nb_bits = 32;

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n, b, i)                      \
    {                                              \
        (b)[(i)] = (unsigned char)((n) >> 24);     \
        (b)[(i) + 1] = (unsigned char)((n) >> 16); \
        (b)[(i) + 2] = (unsigned char)((n) >> 8);  \
        (b)[(i) + 3] = (unsigned char)((n));       \
    }
#endif

typedef struct
{
    LweSample *byte;
} CipherByte;

typedef struct
{
    LweSample *word;
} CipherWord;

LweSample *TableS0[8]; //使用指针数组
LweSample *TableS1[8]; //使用指针数组

void HexToBinStr(int hex, int *bin_str)
{
    for (int i = 0; i < 8; ++i)
    {
        bin_str[i] = hex % 2; //低位比特在最左边
        hex /= 2;
    }
}

void BinStrToHex(int &dex_hex, int *bin_str)
{
    for (int i = 0; i < 8; i++)
    {
        dex_hex += bin_str[i] * pow(2, 7 - i);
    }
}

void NewCipherWord(CipherWord *sample, const TFheGateBootstrappingParameterSet *params)
{
    sample->word = new_gate_bootstrapping_ciphertext_array(32, params);
}

void CopyCipherWord(CipherWord *result, CipherWord *src, TFheGateBootstrappingSecretKeySet *key)
{
    for (int i = 0; i < 32; i++)
    {
        lweCopy(result->word + i, src->word + i, key->params->in_out_params);
    }
}

void EncryptCipherWord(CipherWord *sample, unsigned int value, const TFheGateBootstrappingSecretKeySet *key)
{
    unsigned char a[4];
    PUT_ULONG_BE(value, a, 0);
    for (int i = 0; i < 4; i++)
    {
        int bin_str[8] = {0};
        HexToBinStr(a[i], bin_str);

        for (int j = 0; j < 8; j++)
        {
            bootsSymEncrypt(sample->word + 8 * i + j, bin_str[7 - j], key);
        }
    }
}

void DecryptCipherWord(CipherWord *sample, const TFheGateBootstrappingSecretKeySet *key)
{
    for (int j = 0; j < 4; j++)
    {
        int bin[8] = {0};
        int hexvalue = 0;
        for (int k = 0; k < 8; k++)
        {
            bin[k] = bootsSymDecrypt(sample->word + 8 * j + k, key);
        }
        BinStrToHex(hexvalue, bin);
        printf("%02x", hexvalue);
    }
    cout << " ";
}

void homoWordXor(CipherWord *result, CipherWord *a, CipherWord *b, const TFheGateBootstrappingParameterSet *params,
                 TFheGateBootstrappingSecretKeySet *key)
{
    for (int i = 0; i < 32; i++)
    {
        bootsXOR(result->word + i, a->word + i, b->word + i, &key->cloud);
    }
}

void homoWordAnd(CipherWord *result, CipherWord *a, CipherWord *b, const TFheGateBootstrappingParameterSet *params,
                 TFheGateBootstrappingSecretKeySet *key)
{
    for (int i = 0; i < 32; i++)
    {
        bootsAND(result->word + i, a->word + i, b->word + i, &key->cloud);
    }
}

void homoWordOr(CipherWord *result, CipherWord *a, CipherWord *b, const TFheGateBootstrappingParameterSet *params,
                TFheGateBootstrappingSecretKeySet *key)
{
    for (int i = 0; i < 32; i++)
    {
        bootsOR(result->word + i, a->word + i, b->word + i, &key->cloud);
    }
}

void homoWordNot(CipherWord *result, CipherWord *a, const TFheGateBootstrappingParameterSet *params,
                 TFheGateBootstrappingSecretKeySet *key)
{
    for (int i = 0; i < 32; i++)
    {
        bootsNOT(result->word + i, a->word + i, &key->cloud);
    }
}

void homoZUC_rotl32(CipherWord *result, CipherWord *src, int n, const TFheGateBootstrappingParameterSet *params,
                    TFheGateBootstrappingSecretKeySet *key)
{
    for (int i = 0; i < 32 - n; i++)
    {
        lweCopy(result->word + i, src->word + i + n, params->in_out_params);
    }
    for (int i = 32 - n; i < 32; i++)
    {
        lweCopy(result->word + i, src->word + i - (32 - n), params->in_out_params);
    }
}

void add_bit(LweSample *result, LweSample *carry_out, const LweSample *a, const LweSample *b, const LweSample *carry_in, const TFheGateBootstrappingCloudKeySet *bk)
{

    LweSample *s1 = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    LweSample *c1 = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    LweSample *c2 = new_gate_bootstrapping_ciphertext_array(2, bk->params);

    bootsCONSTANT(&s1[0], 0, bk);
    bootsCONSTANT(&c1[0], 0, bk);
    bootsCONSTANT(&c2[0], 0, bk);

    bootsXOR(s1, a, b, bk);
    bootsXOR(result, s1, carry_in, bk);

    bootsAND(c1, s1, carry_in, bk);
    bootsAND(c2, a, b, bk);

    bootsOR(carry_out, c1, c2, bk);

    delete_gate_bootstrapping_ciphertext_array(2, s1);
    delete_gate_bootstrapping_ciphertext_array(2, c1);
    delete_gate_bootstrapping_ciphertext_array(2, c2);
}

void homoAdd(CipherWord *result, CipherWord *a, CipherWord *b,
             const TFheGateBootstrappingParameterSet *params, TFheGateBootstrappingSecretKeySet *key)
{
    LweSample *tmps_carry = new_gate_bootstrapping_ciphertext_array(2, params);

    //initialize the carry to 0
    bootsCONSTANT(&tmps_carry[0], 0, &key->cloud);

    //run the elementary comparator gate n times
    for (int i = 0; i < nb_bits; i++)
    {
        add_bit(&result->word[31 - i], &tmps_carry[0], &a->word[31 - i], &b->word[31 - i], &tmps_carry[0], &key->cloud);
    }

    delete_gate_bootstrapping_ciphertext_array(2, tmps_carry);
}

void homoZUC_LinkToS(CipherWord *sample, LweSample *kCipher, LweSample *ZUC_dCipher, LweSample *ivCipher,
                     TFheGateBootstrappingParameterSet *params, TFheGateBootstrappingSecretKeySet *key)
{
    //拷贝连接
    bootsSymEncrypt(sample->word + 0, 0, key);

    for (int i = 1; i < 9; i++)
    {
        lweCopy(sample->word + i, kCipher + i - 1, params->in_out_params);
    }
    for (int i = 9; i < 24; i++)
    {
        lweCopy(sample->word + i, ZUC_dCipher + i - 8, params->in_out_params);
    }
    for (int i = 24; i < 32; i++)
    {
        lweCopy(sample->word + i, ivCipher + i - 24, params->in_out_params);
    }
}

void homoBR(CipherWord *LFSR_S, CipherWord *BR_X, TFheGateBootstrappingParameterSet *params,
            TFheGateBootstrappingSecretKeySet *key)
{
    // BR_X[0] = ((LFSR_S[15] & 0x7fff8000) << 1) | (LFSR_S[14] & 0x0000ffff);
    // BR_X[1] = ((LFSR_S[11] & 0x0000ffff) << 16) | ((LFSR_S[9] & 0x7fff8000) >> 15);
    // BR_X[2] = ((LFSR_S[7] & 0x0000ffff) << 16) | ((LFSR_S[5] & 0x7fff8000) >> 15);
    // BR_X[3] = ((LFSR_S[2] & 0x0000ffff) << 16) | ((LFSR_S[0] & 0x7fff8000) >> 15);

    for (int i = 0; i < 32; i++)
    {
        if (i < 16)
            lweCopy(BR_X[0].word + i, LFSR_S[15].word + i + 1, params->in_out_params);
        else
            lweCopy(BR_X[0].word + i, LFSR_S[14].word + i, params->in_out_params);
    }

    for (int i = 0; i < 32; i++)
    {
        if (i < 16)
            lweCopy(BR_X[1].word + i, LFSR_S[11].word + i + 16, params->in_out_params);
        else
            lweCopy(BR_X[1].word + i, LFSR_S[9].word + i - 15, params->in_out_params);
    }

    for (int i = 0; i < 32; i++)
    {
        if (i < 16)
            lweCopy(BR_X[2].word + i, LFSR_S[7].word + i + 16, params->in_out_params);
        else
            lweCopy(BR_X[2].word + i, LFSR_S[5].word + i - 15, params->in_out_params);
    }
    for (int i = 0; i < 32; i++)
    {
        if (i < 16)
            lweCopy(BR_X[3].word + i, LFSR_S[2].word + i + 16, params->in_out_params);
        else
            lweCopy(BR_X[3].word + i, LFSR_S[0].word + i - 15, params->in_out_params);
    }
}

void homoL1(CipherWord *sample, CipherWord *input, TFheGateBootstrappingParameterSet *params,
            TFheGateBootstrappingSecretKeySet *key)
{
    //X ^ ZUC_rotl32(X, 2) ^ ZUC_rotl32(X, 10) ^ ZUC_rotl32(X, 18) ^ ZUC_rotl32(X, 24);
    CipherWord tmp;
    NewCipherWord(&tmp, params);

    homoZUC_rotl32(&tmp, input, 2, params, key);
    homoWordXor(sample, input, &tmp, params, key);

    homoZUC_rotl32(&tmp, input, 10, params, key);
    homoWordXor(sample, sample, &tmp, params, key);

    homoZUC_rotl32(&tmp, input, 18, params, key);
    homoWordXor(sample, sample, &tmp, params, key);

    homoZUC_rotl32(&tmp, input, 24, params, key);
    homoWordXor(sample, sample, &tmp, params, key);

    delete_gate_bootstrapping_ciphertext_array(32, tmp.word);
}

void homoL2(CipherWord *sample, CipherWord *input, TFheGateBootstrappingParameterSet *params,
            TFheGateBootstrappingSecretKeySet *key)
{
    //X ^ ZUC_rotl32(X, 8) ^ ZUC_rotl32(X, 14) ^ ZUC_rotl32(X, 22) ^ ZUC_rotl32(X, 30);
    CipherWord tmp;
    NewCipherWord(&tmp, params);

    homoZUC_rotl32(&tmp, input, 8, params, key);
    homoWordXor(sample, input, &tmp, params, key);

    homoZUC_rotl32(&tmp, input, 14, params, key);
    homoWordXor(sample, sample, &tmp, params, key);

    homoZUC_rotl32(&tmp, input, 22, params, key);
    homoWordXor(sample, sample, &tmp, params, key);

    homoZUC_rotl32(&tmp, input, 30, params, key);
    homoWordXor(sample, sample, &tmp, params, key);

    delete_gate_bootstrapping_ciphertext_array(32, tmp.word);
}

void MakeSBoxTable(LweSample **table, unsigned char Sbox[256], TFheGateBootstrappingParameterSet *params,
                   TFheGateBootstrappingSecretKeySet *key)
{
    int Sbox_binary[256][8];
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            //对SboxTable行循环,把每个十六进制转化为二进制数组
            int bin_str[8];
            HexToBinStr(Sbox[16 * i + j], bin_str);
            for (int k = 0; k < 8; k++)
            {
                Sbox_binary[i * 16 + j][k] = bin_str[7 - k];
                // cout << Sbox_binary[i * 16 + j][k] << " ";
            }
            // cout << endl;
        }
    }

    //make Sbox table: 256 * 8
    for (int j = 0; j < 8; j++)
    {
        table[j] = new_gate_bootstrapping_ciphertext_array(256, params);
        for (int i = 0; i < 256; i++)
        {
            bootsSymEncrypt(table[j] + i, Sbox_binary[i][j], key);
        }
    }
}

//查表函数 //256->128->64->32->16->8-> 4 -> 2 -> 1
void LookupTable(LweSample *result, LweSample *X, LweSample *table,
                 TFheGateBootstrappingParameterSet *params,
                 TFheGateBootstrappingSecretKeySet *key)

{
    //使用x0查表
    LweSample *ct128 = new_gate_bootstrapping_ciphertext_array(128, params);
    for (int i = 0; i < 128; i++)
    {
        bootsMUX(ct128 + i, X + 7, table + 2 * i + 1, table + 2 * i, &key->cloud);
    }

    //使用x1查表
    LweSample *ct64 = new_gate_bootstrapping_ciphertext_array(64, params);
    for (int i = 0; i < 64; i++)
    {
        bootsMUX(ct64 + i, X + 6, ct128 + 2 * i + 1, ct128 + 2 * i, &key->cloud);
    }

    //使用x2查表
    LweSample *ct32 = new_gate_bootstrapping_ciphertext_array(32, params);
    for (int i = 0; i < 32; i++)
    {
        bootsMUX(ct32 + i, X + 5, ct64 + 2 * i + 1, ct64 + 2 * i, &key->cloud);
    }
    //使用x3查表
    LweSample *ct16 = new_gate_bootstrapping_ciphertext_array(16, params);
    for (int i = 0; i < 16; i++)
    {
        bootsMUX(ct16 + i, X + 4, ct32 + 2 * i + 1, ct32 + 2 * i, &key->cloud);
    }

    //使用x4查表
    LweSample *ct8 = new_gate_bootstrapping_ciphertext_array(8, params);
    for (int i = 0; i < 8; i++)
    {
        bootsMUX(ct8 + i, X + 3, ct16 + 2 * i + 1, ct16 + 2 * i, &key->cloud);
    }

    //使用x5查表
    LweSample *ct4 = new_gate_bootstrapping_ciphertext_array(4, params);
    for (int i = 0; i < 4; i++)
    {
        bootsMUX(ct4 + i, X + 2, ct8 + 2 * i + 1, ct8 + 2 * i, &key->cloud);
    }

    //使用x6查表
    LweSample *ct2 = new_gate_bootstrapping_ciphertext_array(2, params);
    for (int i = 0; i < 2; i++)
    {
        bootsMUX(ct2 + i, X + 1, ct4 + 2 * i + 1, ct4 + 2 * i, &key->cloud);
    }
    //使用x7查表 找到结果
    bootsMUX(result, X + 0, ct2 + 1, ct2 + 0, &key->cloud);

    delete_gate_bootstrapping_ciphertext_array(128, ct128);
    delete_gate_bootstrapping_ciphertext_array(64, ct64);
    delete_gate_bootstrapping_ciphertext_array(32, ct32);
    delete_gate_bootstrapping_ciphertext_array(16, ct16);
    delete_gate_bootstrapping_ciphertext_array(8, ct8);
    delete_gate_bootstrapping_ciphertext_array(4, ct4);
    delete_gate_bootstrapping_ciphertext_array(2, ct2);
}

void homoSbox(CipherWord *output, CipherWord *input, TFheGateBootstrappingParameterSet *params,
              TFheGateBootstrappingSecretKeySet *key)
{

    //非线性函数: 4个S盒并行查表
    // F_R[1] = (ZUC_S0[(F_R[1] >> 24) & 0xFF]) << 24 | (ZUC_S1[(F_R[1] >> 16) & 0xFF]) << 16
    //         | (ZUC_S0[(F_R[1] >> 8) & 0xFF]) << 8 | (ZUC_S1[F_R[1] & 0xFF]);
    cout << " ===============SBox  SBox  SBox  SBox=============" << endl;
    // LweSample *X = new_gate_bootstrapping_ciphertext_array(8, params);

    // for (int i = 0; i < 8; i++)
    // {
    //     lweCopy(X+i, input->word+i, params->in_out_params);
    // }

    clock_t look_begin = clock();
    for (int j = 0; j < 8; j++)
    {
        LookupTable(output->word + 7 - j, input->word, TableS0[7 - j], params, key);
    }

    for (int j = 0; j < 8; j++)
    {
        LookupTable(output->word + 8 + 7 - j, input->word + 8, TableS1[7 - j], params, key); //需要查表 8次
    }

    for (int j = 0; j < 8; j++)
    {
        LookupTable(output->word + 16 + 7 - j, input->word + 16, TableS0[7 - j], params, key); //需要查表 8次
    }

    for (int j = 0; j < 8; j++)
    {
        LookupTable(output->word + 24 + 7 - j, input->word + 24, TableS1[7 - j], params, key); //需要查表 8次
    }

    clock_t look_end = clock();
    double total_time_look = 0.0;
    total_time_look = look_end - look_begin;
    cout << "total_time_look:  " << total_time_look / CLOCKS_PER_SEC << " s." << endl;
}

void homoF(CipherWord *W, CipherWord *BR_X, CipherWord *F_R, TFheGateBootstrappingParameterSet *params,
           TFheGateBootstrappingSecretKeySet *key)
{
    CipherWord tmp, W1, W2;
    NewCipherWord(&tmp, params);
    NewCipherWord(&W1, params);
    NewCipherWord(&W2, params);

    // W = (BR_X[0] ^ F_R[0]) + F_R[1];
    homoWordXor(&tmp, &BR_X[0], &F_R[0], params, key);
    homoAdd(W, &tmp, &F_R[1], params, key);

    // W1 = F_R[0] + BR_X[1];
    homoAdd(&W1, &F_R[0], &BR_X[1], params, key);
    // W2 = F_R[1] ^ BR_X[2];

    homoWordXor(&W2, &F_R[1], &BR_X[2], params, key);

    // cout << "解密tmp ：";
    // DecryptCipherWord(&tmp, key);
    // cout << endl;
    // cout << "解密W ：";
    // DecryptCipherWord(W, key);
    // cout << endl;
    // cout << "解密W1 ：";
    // DecryptCipherWord(&W1, key);
    // cout << endl;

    // cout << "解密W2 ：";
    // DecryptCipherWord(&W2, key);
    // cout << endl;

    // F_R[0] = L1((W1 << 16) | (W2 >> 16));
    for (int i = 0; i < 32; i++)
    {
        if (i < 16)
            lweCopy(tmp.word + i, W1.word + i + 16, params->in_out_params);
        else
            lweCopy(tmp.word + i, W2.word + i - 16, params->in_out_params);
    }

    homoL1(&F_R[0], &tmp, params, key);

    // cout << "解密F_R[0] ：" << endl;
    // DecryptCipherWord(&F_R[0], key);
    // cout << endl;
    // return;
    CipherWord temp;
    NewCipherWord(&temp, params);
    CopyCipherWord(&temp, &F_R[0], key);

    // F_R[0] = (ZUC_S0[(F_R[0] >> 24) & 0xFF]) << 24 | (ZUC_S1[(F_R[0] >> 16) & 0xFF]) << 16
    // | (ZUC_S0[(F_R[0] >> 8) & 0xFF]) << 8 | (ZUC_S1[F_R[0] & 0xFF]);
    homoSbox(&F_R[0], &temp, params, key);

    // cout << "box之后解密F_R[0] ：" << endl;
    // DecryptCipherWord(&F_R[0], key);
    // cout << endl;

    // F_R[1] = L2((W2 << 16) | (W1 >> 16));
    for (int i = 0; i < 32; i++)
    {
        if (i < 16)
            lweCopy(tmp.word + i, W2.word + i + 16, params->in_out_params);
        else
            lweCopy(tmp.word + i, W1.word + i - 16, params->in_out_params);
    }
    homoL2(&F_R[1], &tmp, params, key);

    // F_R[1] = (ZUC_S0[(F_R[1] >> 24) & 0xFF]) << 24 | (ZUC_S1[(F_R[1] >> 16) & 0xFF]) << 16
    //       | (ZUC_S0[(F_R[1] >> 8) & 0xFF]) << 8 | (ZUC_S1[F_R[1] & 0xFF]);
    CopyCipherWord(&temp, &F_R[1], key);
    homoSbox(&F_R[1], &temp, params, key);

    delete_gate_bootstrapping_ciphertext_array(32, tmp.word);
    delete_gate_bootstrapping_ciphertext_array(32, temp.word);
    delete_gate_bootstrapping_ciphertext_array(32, W1.word);
    delete_gate_bootstrapping_ciphertext_array(32, W2.word);
}

void homoF_work(CipherWord *BR_X, CipherWord *F_R, TFheGateBootstrappingParameterSet *params,
                TFheGateBootstrappingSecretKeySet *key)
{
    CipherWord tmp, W1, W2;
    NewCipherWord(&tmp, params);
    NewCipherWord(&W1, params);
    NewCipherWord(&W2, params);

    // W = (BR_X[0] ^ F_R[0]) + F_R[1];
    // homoWordXor(&tmp, &BR_X[0], &F_R[0], params, key);
    // homoAdd(W, &tmp, &F_R[1], params, key);

    // W1 = F_R[0] + BR_X[1];
    homoAdd(&W1, &F_R[0], &BR_X[1], params, key);
    // W2 = F_R[1] ^ BR_X[2];
    homoWordXor(&W2, &F_R[1], &BR_X[2], params, key);

    // F_R[0] = L1((W1 << 16) | (W2 >> 16));
    for (int i = 0; i < 32; i++)
    {
        if (i < 16)
            lweCopy(tmp.word + i, W1.word + i + 16, params->in_out_params);
        else
            lweCopy(tmp.word + i, W2.word + i - 16, params->in_out_params);
    }

    homoL1(&F_R[0], &tmp, params, key);

    CipherWord temp;
    NewCipherWord(&temp, params);

    CopyCipherWord(&temp, &F_R[0], key);
    // F_R[0] = (ZUC_S0[(F_R[0] >> 24) & 0xFF]) << 24 | (ZUC_S1[(F_R[0] >> 16) & 0xFF]) << 16
    // | (ZUC_S0[(F_R[0] >> 8) & 0xFF]) << 8 | (ZUC_S1[F_R[0] & 0xFF]);
    homoSbox(&F_R[0], &temp, params, key);

    // F_R[1] = L2((W2 << 16) | (W1 >> 16));
    for (int i = 0; i < 32; i++)
    {
        if (i < 16)
            lweCopy(tmp.word + i, W2.word + i + 16, params->in_out_params);
        else
            lweCopy(tmp.word + i, W1.word + i - 16, params->in_out_params);
    }
    homoL2(&F_R[1], &tmp, params, key);
    // F_R[1] = (ZUC_S0[(F_R[1] >> 24) & 0xFF]) << 24 | (ZUC_S1[(F_R[1] >> 16) & 0xFF]) << 16
    //       | (ZUC_S0[(F_R[1] >> 8) & 0xFF]) << 8 | (ZUC_S1[F_R[1] & 0xFF]);
   
    CopyCipherWord(&temp, &F_R[1], key);
    homoSbox(&F_R[1], &temp, params, key);

    delete_gate_bootstrapping_ciphertext_array(32, tmp.word);
    delete_gate_bootstrapping_ciphertext_array(32, temp.word);
    delete_gate_bootstrapping_ciphertext_array(32, W1.word);
    delete_gate_bootstrapping_ciphertext_array(32, W2.word);
}

void homoPowMod(CipherWord *result, CipherWord *input, int n,
                TFheGateBootstrappingParameterSet *params, TFheGateBootstrappingSecretKeySet *key)
{
    // (((x << k) | (x >> (31 - k))) & 0x7fffffff);
    // x*2^k mod 2^31-1
    bootsSymEncrypt(result->word + 0, 0, key);
    for (int i = 1; i < 32 - n - 1; i++)
    {
        lweCopy(result->word + i, input->word + i + n, params->in_out_params);
    }
    bootsOR(result->word + 32 - n - 1, input->word + 31, input->word + 0, &key->cloud);

    for (int i = 32 - n; i < 32; i++)
    {
        lweCopy(result->word + i, input->word + i - (32 - n) + 1, params->in_out_params);
    }
}
void homoAddMod(CipherWord *result, CipherWord *cipherA, CipherWord *cipherB,
                TFheGateBootstrappingParameterSet *params, TFheGateBootstrappingSecretKeySet *key)
{
    // unsigned int c = a + b;
    // if (c >> 31)
    // {
    //     c = (c & 0x7fffffff) + 1;
    // }
    CipherWord temp;
    NewCipherWord(&temp, params);
    homoAdd(&temp, cipherA, cipherB, params, key); //c = a + b

    //如果超过2^31-1的话
    CipherWord temp1;
    NewCipherWord(&temp1, params);
    CopyCipherWord(&temp1, &temp, key);
    bootsCONSTANT(temp1.word + 0, 0, &key->cloud); //(c & 0x7fffffff)

    //+1
    CipherWord Const1;
    NewCipherWord(&Const1, params);
    for (int i = 0; i < 32; i++)
    {
        if (i == 31)
        {
            bootsSymEncrypt(Const1.word + i, 1, key);
        }
        else
        {
            bootsSymEncrypt(Const1.word + i, 0, key);
        }
    }

    CipherWord sum;
    NewCipherWord(&sum, params);
    homoAdd(&sum, &temp1, &Const1, params, key);

    for (int i = 0; i < 32; i++)
    {
        bootsMUX(result->word + i, temp.word + 0, sum.word + i, temp.word + i, &key->cloud);
    }

    delete_gate_bootstrapping_ciphertext_array(32, temp.word);
    delete_gate_bootstrapping_ciphertext_array(32, temp1.word);
    delete_gate_bootstrapping_ciphertext_array(32, Const1.word);
    delete_gate_bootstrapping_ciphertext_array(32, sum.word);
}
void homoLFSRWithInitMode(CipherWord *LFSR_S, CipherWord *W,
                          TFheGateBootstrappingParameterSet *params, TFheGateBootstrappingSecretKeySet *key)
{

    //  unsigned int v = LFSR_S[0], i;
    CipherWord v, temp;
    NewCipherWord(&v, params);
    NewCipherWord(&temp, params);

    CopyCipherWord(&v, &LFSR_S[0], key);
    // v = AddMod(v, PowMod(LFSR_S[15], 15));
    homoPowMod(&temp, &LFSR_S[15], 15, params, key);
    homoAddMod(&v, &v, &temp, params, key);

    // v = AddMod(v, PowMod(LFSR_S[13], 17));
    homoPowMod(&temp, &LFSR_S[13], 17, params, key);
    homoAddMod(&v, &v, &temp, params, key);
    // v = AddMod(v, PowMod(LFSR_S[10], 21));
    homoPowMod(&temp, &LFSR_S[10], 21, params, key);
    homoAddMod(&v, &v, &temp, params, key);
    // v = AddMod(v, PowMod(LFSR_S[4], 20));
    homoPowMod(&temp, &LFSR_S[4], 20, params, key);
    homoAddMod(&v, &v, &temp, params, key);
    // v = AddMod(v, PowMod(LFSR_S[0], 8));
    homoPowMod(&temp, &LFSR_S[0], 8, params, key);
    homoAddMod(&v, &v, &temp, params, key);

    for (int i = 0; i < 15; i++)
    {
        // LFSR_S[i] = LFSR_S[i + 1];
        CopyCipherWord(&LFSR_S[i], &LFSR_S[i + 1], key);
    }

    // u = W>>1 舍弃最低的比特位
    CipherWord u;
    NewCipherWord(&u, params);
    bootsSymEncrypt(u.word + 0, 0, key); //首位加密0
    for (int i = 1; i < 32; i++)
    {
        lweCopy(u.word + i, W->word + i - 1, params->in_out_params);
    }

    // LFSR_S[15] = AddMod(v, u);
    homoAddMod(&LFSR_S[15], &v, &u, params, key);
    // if (!LFSR_S[15]) //Todo
    // {
    //     LFSR_S[15] = 0x7fffffff;
    // }

    delete_gate_bootstrapping_ciphertext_array(32, u.word);
    delete_gate_bootstrapping_ciphertext_array(32, v.word);
    delete_gate_bootstrapping_ciphertext_array(32, temp.word);
}

void homoZUC_Init(LweSample **kCipher, LweSample **ivCipher, LweSample **ZUC_dCipher, CipherWord *LFSR_S, CipherWord *BR_X, CipherWord *F_R,
                  TFheGateBootstrappingParameterSet *params, TFheGateBootstrappingSecretKeySet *key)
{
    unsigned char count = 32;
    int i;

    //loading key to the LFSR s0,s1,s2....s15
    cout << "------initial state of LFSR: S[0]-S[15]----" << endl;
    for (i = 0; i < 16; i++)
    {
        homoZUC_LinkToS(&LFSR_S[i], kCipher[i], ZUC_dCipher[i], ivCipher[i], params, key);
        DecryptCipherWord(&LFSR_S[i], key);
    }
    cout << endl;

    // F_R[0] = 0x00; //R1
    // F_R[1] = 0x00; //R2
    //初始化
    for (int i = 0; i < 2; i++)
    {
        for (int j = 0; j < 32; j++)
        {
            bootsSymEncrypt(F_R[i].word + j, 0, key);
        }
    }
    // unsigned int ww[32] = {0X5b8f9ac7, 0X4285372a, 0X3f72cca9, 0X8073d36d, 0Xa87c58e5,
    //                        0Xd9135e82, 0Xfd2ceb1e, 0X8d89ddde, 0X46b676f2, 0Xeef1a039, 0Xf189cdd4,
    //                        0Xcf1ac292, 0Xb2460401, 0X669f673e, 0Xe8299b6c, 0X1a8cb387, 0X77aa4733,
    //                        0X68b4cdb1, 0Xc328e213, 0X3dbd14e3, 0Xeeaa3cdc, 0Xb82e3e67, 0Xc73aac04,
    //                        0X747c8ff6, 0X7a66fae2, 0X6cc209e2, 0X73f52e05, 0Xdc070ac1, 0Xce369231,
    //                        0X100ffde4, 0X7f2284, 0Xa2ec3df2};
    // CipherWord W[32];
    // for (int i = 0; i < 32; i++)
    // {
    //     NewCipherWord(&W[i], params);
    // }

    // while (count) //32
    for (int i = 0; i < count; i++)
    {
        CipherWord W;
        NewCipherWord(&W, params);

        // BR(LFSR_S, BR_X); //construction/
        homoBR(LFSR_S, BR_X, params, key);
        // cout << "BR" << i << ": ";
        // for (int j = 0; j < 4; j++)
        // {
        //     DecryptCipherWord(&BR_X[j], key);
        // }
        // cout << endl;

        //W = F(BR_X, F_R);
        homoF(&W, BR_X, F_R, params, key);

        //32 times
        //nonlinear function
        //LFSRWithInitMode(LFSR_S, W >> 1);
        // unsigned int ww = 0x5b8f9ac7;
        //加密ww-> W

        // EncryptCipherWord(&W[i], ww[i], key);
        // EncryptCipherWord(&W[i], ww[i], key);
        // cout << "W" << i << ": " << flush;
        // DecryptCipherWord(&W, key);
        // cout << endl;

        // cout << "FR" << i << ": ";
        // for (int j = 0; j < 2; j++)
        // {
        //     DecryptCipherWord(&F_R[j], key);
        // }
        // cout << endl;

        cout << i << "轮之后：" << flush;
        homoLFSRWithInitMode(LFSR_S, &W, params, key);

        for (int j = 0; j < 16; j++)
        {
            DecryptCipherWord(&LFSR_S[j], key);
        }
        cout << endl;
        delete_gate_bootstrapping_ciphertext_array(32, W.word);
        // count--;
    }
}

void homoLFSRWithWorkMode(CipherWord *LFSR_S, TFheGateBootstrappingParameterSet *params, TFheGateBootstrappingSecretKeySet *key)
{
    //  unsigned int v = LFSR_S[0], i;
    CipherWord v, temp;
    NewCipherWord(&v, params);
    NewCipherWord(&temp, params);

    CopyCipherWord(&v, &LFSR_S[0], key);
    // v = AddMod(v, PowMod(LFSR_S[15], 15));
    homoPowMod(&temp, &LFSR_S[15], 15, params, key);
    homoAddMod(&v, &v, &temp, params, key);

    // v = AddMod(v, PowMod(LFSR_S[13], 17));
    homoPowMod(&temp, &LFSR_S[13], 17, params, key);
    homoAddMod(&v, &v, &temp, params, key);
    // v = AddMod(v, PowMod(LFSR_S[10], 21));
    homoPowMod(&temp, &LFSR_S[10], 21, params, key);
    homoAddMod(&v, &v, &temp, params, key);
    // v = AddMod(v, PowMod(LFSR_S[4], 20));
    homoPowMod(&temp, &LFSR_S[4], 20, params, key);
    homoAddMod(&v, &v, &temp, params, key);
    // v = AddMod(v, PowMod(LFSR_S[0], 8));
    homoPowMod(&temp, &LFSR_S[0], 8, params, key);
    homoAddMod(&v, &v, &temp, params, key);

    for (int i = 0; i < 15; i++)
    {
        // LFSR_S[i] = LFSR_S[i + 1];
        CopyCipherWord(&LFSR_S[i], &LFSR_S[i + 1], key);
    }

    // LFSR_S[15] = v;
    CopyCipherWord(&LFSR_S[15], &v, key);

    // if (!LFSR_S[15])
    // {
    //     LFSR_S[15] = 0x7fffffff;
    // }
}
void homoZUC_Work(CipherWord *LFSR_S, CipherWord *BR_X, CipherWord *F_R, CipherWord *KeystreamCipher, int KeyStreamLen,
                  TFheGateBootstrappingParameterSet *params, TFheGateBootstrappingSecretKeySet *key)
{
    // unsigned int LFSR_S_plain[16] = {0x5b6acbf6, 0x17060ce1, 0x35368174, 0x5cf4385a,
    //                                  0x479943df, 0x2753bab2, 0x73775d6a,
    //                                  0x43930a37, 0x77b4af31, 0x15b2e89f, 0x24ff6e20,
    //                                  0x740c40b9, 0x26a5503, 0x194b2a57, 0x7a9a1cff, 0x3d4aa9e7};
    // unsigned int BR_X_plain[4] = {0xf5342a57, 0x6e20ef69, 0x5d6a8f32, 0xce121b4}; //Bit Reconstruction X0,X1,X2,X3
    // unsigned int F_R_plain[2] = {0x129d8b39, 0x2d7cdce1};

    // for (int i = 0; i < 16; i++)
    // {
    //     EncryptCipherWord(&LFSR_S[i], LFSR_S_plain[i], key);
    // }
    // for (int i = 0; i < 4; i++)
    // {
    //     EncryptCipherWord(&BR_X[i], BR_X_plain[i], key);
    // }

    // for (int i = 0; i < 2; i++)
    // {
    //     EncryptCipherWord(&F_R[i], F_R_plain[i], key);
    // }
    //work mode

    // BR(LFSR_S, BR_X);
    homoBR(LFSR_S, BR_X, params, key);

    // F(BR_X, F_R);
    homoF_work(BR_X, F_R, params, key);

    // cout << "=========F_R之后========" << endl;
    // for (int j = 0; j < 2; j++)
    // {
    //     // ==F_R之后== 52ad4121 95b81021
    //     DecryptCipherWord(&F_R[j], key);
    // }
    // cout << endl;
    // LFSRWithWorkMode(LFSR_S);
    homoLFSRWithWorkMode(LFSR_S, params, key);

    // cout << "==homoLFSRWithWorkMode==" << endl;
    // for (int j = 0; j < 16; j++)
    // {
    //     DecryptCipherWord(&LFSR_S[j], key);
    // }
    // cout << endl;

    for (int i = 0; i < KeyStreamLen; i++)
    {
        CipherWord temp;
        NewCipherWord(&temp, params);

        // BR(LFSR_S, BR_X);
        homoBR(LFSR_S, BR_X, params, key);
        // pKeyStream[i] = F(BR_X, F_R) ^ BR_X[3];
        homoF(&temp, BR_X, F_R, params, key);
        // cout << " temp " << endl;
        // DecryptCipherWord(&temp, key);
        // cout << endl;
        homoWordXor(&KeystreamCipher[i], &temp, &BR_X[3], params, key);

        cout << " KeystreamCipher " << i<< ":";
        DecryptCipherWord(&KeystreamCipher[i], key);
        cout << endl;
        // LFSRWithWorkMode(LFSR_S);
        homoLFSRWithWorkMode(LFSR_S, params, key);
        delete_gate_bootstrapping_ciphertext_array(8, temp.word);
    }
}

//同态的ZUC密钥生成算法
void homoZUC_GenKeyStream(LweSample **kCipher, LweSample **ivCipher, LweSample **ZUC_dCipher, CipherWord *KeystreamCipher, int KeyStreamLen,
                          TFheGateBootstrappingParameterSet *params, TFheGateBootstrappingSecretKeySet *key)
{
    // unsigned int LFSR_S[16]; //LFSR state s0,s1,s2,...s15
    CipherWord LFSR_S[16];
    // unsigned int BR_X[4];    //Bit Reconstruction X0,X1,X2,X3
    CipherWord BR_X[4];
    // unsigned int F_R[2];    //R1,R2,variables of nonlinear function F
    CipherWord F_R[2];

    for (int i = 0; i < 16; i++)
    {
        NewCipherWord(&LFSR_S[i], params);
    }
    for (int i = 0; i < 4; i++)
    {
        NewCipherWord(&BR_X[i], params);
    }
    for (int i = 0; i < 2; i++)
    {
        NewCipherWord(&F_R[i], params);
    }

    //Initialisation
    homoZUC_Init(kCipher, ivCipher, ZUC_dCipher, LFSR_S, BR_X, F_R, params, key);
    
    // unsigned int LFSR_S_plain[16] = {0x10da5941, 0x5b6acbf6, 0x17060ce1, 0x35368174,
    //                                  0x5cf4385a, 0x479943df, 0x2753bab2, 0x73775d6a, 0x43930a37,
    //                                  0x77b4af31, 0x15b2e89f, 0x24ff6e20, 0x740c40b9, 0x26a5503,
    //                                  0x194b2a57, 0x7a9a1cff};
    // unsigned int BR_X_plain[4] = {0x32965503, 0xe89f8726, 0xbab2b9e8, 0xcbf6f138}; //Bit Reconstruction X0,X1,X2,X3
    // unsigned int F_R_plain[2] = {0x860a7dfa, 0xbf0e0ffc};

    // for (int i = 0; i < 16; i++)
    // {
    //     EncryptCipherWord(&LFSR_S[i], LFSR_S_plain[i], key);
    // }
    // for (int i = 0; i < 4; i++)
    // {
    //     EncryptCipherWord(&BR_X[i], BR_X_plain[i], key);
    // }

    // for (int i = 0; i < 2; i++)
    // {
    //     EncryptCipherWord(&F_R[i], F_R_plain[i], key);
    // }
    //Working
    clock_t work_begin = clock();
    homoZUC_Work(LFSR_S, BR_X, F_R, KeystreamCipher, KeyStreamLen, params, key);
    clock_t work_end = clock();
    double total_time_work = 0.0;
    total_time_work = (work_end - work_begin) / CLOCKS_PER_SEC;
    cout << "total_time_work:  " << total_time_work <<"s."<< endl;

}

int main()
{
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = {214, 1592, 657};
    tfhe_random_generator_setSeed(seed, 3);
    TFheGateBootstrappingSecretKeySet *key = new_random_gate_bootstrapping_secret_keyset(params);

    const TFheGateBootstrappingCloudKeySet *bk = &(key->cloud);

    cout << " ===============  make table=============" << endl;
    clock_t make_begin = clock();
    MakeSBoxTable(TableS0, ZUC_S0, params, key);
    // cout << "==============" << endl;
    MakeSBoxTable(TableS1, ZUC_S1, params, key);
    clock_t make_end = clock();
    double total_time_maketable = 0.0;
    total_time_maketable = (make_end - make_begin) / CLOCKS_PER_SEC;
    cout << "total_time_maketable:  " << total_time_maketable <<"s."<< endl;

    /**************** KeyStream generation validation data ***************************/
    // (all 0)
    // unsigned char k[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    // unsigned char iv[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    // unsigned int Std_Keystream[2] = {0x27bede74, 0x018082da};

    //(all 1)
    /*unsigned char k[16]={0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    unsigned char iv[16]={0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    unsigned int Std_Keystream[2]={0x0657cfa0,0x7096398b};*/

    //(random)
    unsigned char
        k[16] = {0x3d, 0x4c, 0x4b, 0xe9, 0x6a, 0x82, 0xfd, 0xae, 0xb5, 0x8f, 0x64, 0x1d, 0xb1, 0x7b, 0x45, 0x5b};
    unsigned char
        iv[16] = {0x84, 0x31, 0x9a, 0xa8, 0xde, 0x69, 0x15, 0xca, 0x1f, 0x6b, 0xda, 0x6b, 0xfb, 0xd8, 0xc7, 0x66};
    unsigned int Std_Keystream[2] = {0x14f1c272, 0x3279c419};

    int KeyStreamLen = 2; //the length of key stream
    // unsigned int Keystream[2];

    //加密 k[i]
    LweSample *kCipher[16];
    int bin[8] = {0};
    for (int i = 0; i < 16; i++)
    {
        kCipher[i] = new_gate_bootstrapping_ciphertext_array(8, params);
        HexToBinStr(k[i], bin);
        for (int j = 0; j < 8; j++)
        {
            bootsSymEncrypt(kCipher[i] + j, bin[7 - j], key);
        }
    }

    //加密 iv[i]
    LweSample *ivCipher[16];
    for (int i = 0; i < 16; i++)
    {
        ivCipher[i] = new_gate_bootstrapping_ciphertext_array(8, params);
        HexToBinStr(iv[i], bin);
        for (int j = 0; j < 8; j++)
        {
            bootsSymEncrypt(ivCipher[i] + j, bin[7 - j], key);
        }
    }

    cout << " 加密 unsigned int ZUC_d[16]" << endl;
    LweSample *ZUC_dCipher[16];
    for (int i = 0; i < 16; i++)
    {
        ZUC_dCipher[i] = new_gate_bootstrapping_ciphertext_array(16, params);
        unsigned char a[4];
        PUT_ULONG_BE(ZUC_d[i], a, 0);
        for (int j = 2; j < 4; j++)
        {
            HexToBinStr(a[j], bin);
            for (int k = 0; k < 8; k++)
            {
                bootsSymEncrypt(ZUC_dCipher[i] + 8 * (j - 2) + k, bin[7 - k], key);
            }
        }
    }
#if 0
    cout <<"解密看看"<<endl;
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            cout << bootsSymDecrypt(ZUC_dCipher[i] + j, key) << " ";
        }
        cout << endl;
    }
    return 0;
#endif
    CipherWord KeystreamCipher[2];
    for (int i = 0; i < 2; i++)
    {
        NewCipherWord(&KeystreamCipher[i], params);
    }
    clock_t start, finish;
    double totaltime;
    start = clock();
    homoZUC_GenKeyStream(kCipher, ivCipher, ZUC_dCipher, KeystreamCipher, KeyStreamLen, params, key);
    finish = clock();
    totaltime = (double)(finish - start) / CLOCKS_PER_SEC;
    cout << "同态计算ZUC算法的运行时间为" << totaltime << "秒！" << endl;

    //decrypt hashCipher Std_Keystream[2] = {0x14f1c272, 0x3279c419};
    for (int i = 0; i < 2; i++)
    {
        DecryptCipherWord(&KeystreamCipher[i], key);
    }
    cout << endl;
    return 0;
}

int main01()
{
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = {214, 1592, 657};
    tfhe_random_generator_setSeed(seed, 3);
    TFheGateBootstrappingSecretKeySet *key = new_random_gate_bootstrapping_secret_keyset(params);

    const TFheGateBootstrappingCloudKeySet *bk = &(key->cloud);

    cout << " ===============  make table=============" << endl;
    clock_t make_begin = clock();
    MakeSBoxTable(TableS0, ZUC_S0, params, key);
    // cout << "==============" << endl;
    MakeSBoxTable(TableS1, ZUC_S1, params, key);
    clock_t make_end = clock();
    double total_time_maketable = 0.0;
    total_time_maketable = make_end - make_end;
    cout << "total_time_maketable:  " << total_time_maketable << endl;

    unsigned int test1 = 0x4f341234;
    unsigned int test2 = 0xbd3e5908;

    // 加密
    CipherWord xxx, yyy, zzz;
    NewCipherWord(&xxx, params);
    NewCipherWord(&yyy, params);
    NewCipherWord(&zzz, params);

    EncryptCipherWord(&xxx, test1, key);
    EncryptCipherWord(&yyy, test2, key);

    cout << " xxx  " << endl;
    DecryptCipherWord(&xxx, key);
    cout << endl;
    // homoPowMod(&yyy, &xxx, 3, params, key);s

    // cout << "  yyy  " << endl;
    // DecryptCipherWord(&yyy, key);
    // cout << endl;

    // homoAddMod(&zzz, &xxx, &yyy, params, key);

    homoSbox(&zzz, &yyy, params, key);

    cout << "  zzz  " << endl;
    DecryptCipherWord(&zzz, key);
    cout << endl;
    return 0;
}