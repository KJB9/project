#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include "AES.h"

#define AES_keyExpSize 96

struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
};

/*prints string as hex*/
static void phex(uint8_t* str)
{
    unsigned char i;
    for (i = 0; i < 16; i++)
        printf("%.2x", str[i]);
    printf("\n");
}

/*Function that copies the arrays*/

void Copy_array(uint8_t * in, uint8_t *out, int size)
{
  for (int i = 0; i < size; i++)
  {
    out[i] = in[i];
  }
}

/*Function that creates lambda-set*/

void A_set(uint8_t A_set[][16], struct AES_ctx ctx, uint8_t pos)
{              
  uint8_t in[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  for (int i = 0 ; i < 256; i++)
  {
    in[pos] = i;
    Copy_array(in, A_set[i], 16);
    AES_encrypt(&ctx, A_set[i]);
  }
}

/*Function that performs the xor operation between two array*/

void Xor_array(uint8_t* in, uint8_t* out, int size)
{
  for (int i = 0; i < size; i++)
  {
    out[i] ^= in[i];
  }
}

/*Function that reverses the Mixcolumn transformation on a single colonne*/

void getInvertMixColumns(uint8_t *column)
{
  uint8_t a, b, c, d;

  a = column[0];
  b = column[1];
  c = column[2];
  d = column[3];

  column[0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
}

/*Function that realize the second part of the 5 round square attack*/

uint8_t Square_attack_4_round(uint8_t A_set_column_0[][4], uint8_t A_set_column_1[][4], uint8_t A_set_column_2[][4])
{
  uint8_t result = 0;
  uint8_t column_0[4], column_1[4], column_2[4];


  int guess;
  for (guess = 0; guess < 256; guess++)
  {
    uint8_t byte_0 = 0;
    uint8_t byte_1 = 0;
    uint8_t byte_2 = 0;

    for (int i = 0; i < 256; i++)
    {
      Copy_array(A_set_column_0[i], column_0, 4);
      getInvertMixColumns(column_0);
      column_0[0] ^= guess;
      byte_0 ^= getSBoxInvert(column_0[0]);

      Copy_array(A_set_column_1[i], column_1, 4);
      getInvertMixColumns(column_1);
      column_1[0] ^= guess;
      byte_1 ^= getSBoxInvert(column_1[0]);

      Copy_array(A_set_column_2[i], column_2, 4);
      getInvertMixColumns(column_2);
      column_2[0] ^= guess;
      byte_2 ^= getSBoxInvert(column_2[0]);      
    }

    if (byte_0 == 0 && byte_1 == 0 && byte_2 == 0)
    {
     result = 1;
    }
  }
  return result;
}

/*Function that creates a composite column of bytes*/

void Create_column(uint8_t *column, uint8_t *ciphertext, uint8_t num)
{
  uint8_t Index[4][4] = { {0, 7, 10, 13}, {1, 4, 11, 14}, {2, 5, 8, 15}, {3, 6, 9, 12} };

  for(int i = 0; i < 4; i++)
  {
    column[i] = ciphertext[Index[num][i]];
  }
}

/*Function that realizes the first part of 5-round square attack */

void Square_attack_5_round(struct AES_ctx ctx, uint8_t num, uint8_t *guess_key)
{ 
  int guess, result;
  uint8_t column_0[4], column_1[4], column_2[4], hyp_key[4];
  uint8_t A_set_0[256][16], A_set_1[256][16], A_set_2[256][16];
  uint8_t A_set_column_0[256][4], A_set_column_1[256][4], A_set_column_2[256][4];
  uint8_t Index[4][4] = { {0, 7, 10, 13}, {1, 4, 11, 14}, {2, 5, 8, 15}, {3, 6, 9, 12} };

  hyp_key[0] = ctx.RoundKey[80+Index[num][0]]; 
  hyp_key[1] = ctx.RoundKey[80+Index[num][1]];
  hyp_key[2] = ctx.RoundKey[80+Index[num][2]];

  A_set(A_set_0, ctx, 0);
  A_set(A_set_1, ctx, 1);
  A_set(A_set_2, ctx, 2);

  for (guess = 0; guess < 256; guess++)
  {
    hyp_key[3] = guess;

    for (int i = 0; i < 256; i++)
    {
      Create_column(column_0, A_set_0[i], num);
      Create_column(column_1, A_set_1[i], num);
      Create_column(column_2, A_set_2[i], num);

      Xor_array(hyp_key, column_0, 4);
      Xor_array(hyp_key, column_1, 4);
      Xor_array(hyp_key, column_2, 4);

      for (int j = 0; j < 4; j++)
      {
        column_0[j] = getSBoxInvert(column_0[j]);
        column_1[j] = getSBoxInvert(column_1[j]);
        column_2[j] = getSBoxInvert(column_2[j]);
      }

      Copy_array(column_0, A_set_column_0[i], 4);
      Copy_array(column_1, A_set_column_1[i], 4);
      Copy_array(column_2, A_set_column_2[i], 4);
    }

    result = Square_attack_4_round(A_set_column_0, A_set_column_1, A_set_column_2);

    if( result == 1)
    {
      guess_key[Index[num][0]] = hyp_key[0];
      guess_key[Index[num][1]] = hyp_key[1];
      guess_key[Index[num][2]] = hyp_key[2];
      guess_key[Index[num][3]] = hyp_key[3];
    }
  }
}
 
/*Function for to generate random keys*/

void Init_key(uint8_t *key)
{
 for (int i = 0; i < 16; i++)
 {
  key[i] = rand() % 256;
 }
}

/**/

int main(void)
{
  srand(time(NULL));
  uint8_t key[16];
  uint8_t guess_key[16];
  Init_key(key);

  struct AES_ctx ctx;
  AES_init_ctx(&ctx, key);
  printf("the 5 round key: ");
  phex(&ctx.RoundKey[80]);
  printf("\n");

  printf("the 5 round key found: ");
  for (int i = 0; i < 4; i++)
  {
    Square_attack_5_round(ctx, i, guess_key);
  }
  phex(guess_key);

  return 0;
}
