#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include "AES.h"

#define AES_keyExpSize 176

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

/**/

void Copy_state(uint8_t * in, uint8_t *out)
{
  for (int i = 0; i < 16; i++)
  {
    out[i] = in[i];
  }
}

/**/

void A_set(uint8_t A_set[][16], struct AES_ctx ctx, uint8_t pos)
{              
  uint8_t in[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  for (int i = 0 ; i < 256; i++)
  {
    in[pos] = i;
    Copy_state(in, A_set[i]);
    AES_encrypt(&ctx, A_set[i]);
  }
}

/**/

void Add_state(uint8_t* in, uint8_t* out)
{
  for (int i = 0; i < 16; i++)
  {
    out[i] ^= in[i];
  }
}

/**/

void Guess_byte_key(uint8_t A_set_0[][16], uint8_t A_set_1[][16], uint8_t pos, uint8_t *guess_key)
{
  uint8_t byte_0 = 0;
  uint8_t byte_1 = 0;

  int guess;
  for (guess = 0; guess < 256; guess++)
  {
    uint8_t final_byte_0 = 0;
    uint8_t final_byte_1 = 0;

    for (int i = 0; i < 256; i++)
    {
      byte_0 = A_set_0[i][pos];
      byte_0 ^= guess;
      final_byte_0 ^= getSBoxInvert(byte_0);

      byte_1 = A_set_1[i][pos];
      byte_1 ^= guess;
      final_byte_1 ^= getSBoxInvert(byte_1);
    }

    if (final_byte_0 == 0 && final_byte_1 == 0)
    {
     guess_key[pos] = guess;
    }
  }
}

/**/

void Square_attack(struct AES_ctx ctx)
{
  uint8_t A_set_0[256][16];
  uint8_t A_set_1[256][16];
  uint8_t key[16];

  A_set(A_set_0, ctx, 0);
  A_set(A_set_1, ctx, 1);

  for (uint8_t pos = 0; pos < 16; pos++)
  { 
    Guess_byte_key(A_set_0, A_set_1, pos, key); 
  }
  printf("The 4 round guess_key : ");
  phex(key);
}

/**/

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
  Init_key(key);

  struct AES_ctx ctx;
  AES_init_ctx(&ctx, key);
  printf("the 4 round key : ");
  phex(&ctx.RoundKey[64]);
  printf("\n");

  Square_attack(ctx);

  return 0;
}
