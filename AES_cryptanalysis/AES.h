

struct AES_ctx;

typedef uint8_t state_t[4][4];

void print_state(state_t* state);

void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key);

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);

void SubBytes(state_t* state);

void ShiftRows(state_t* state);

uint8_t xtime(uint8_t x);

void MixColumns(state_t* state);

void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey);

uint8_t Multiply(uint8_t x, uint8_t y);

void InvMixColumns(state_t* state);

void InvShiftRows(state_t* state);

void InvSubBytes(state_t* state);

void Cipher(state_t* state, const uint8_t* RoundKey);

void InvCipher(state_t* state, const uint8_t* RoundKey);

void AES_encrypt(const struct AES_ctx* ctx, uint8_t* buf);

void AES_decrypt(const struct AES_ctx* ctx, uint8_t* buf);

uint8_t getSBoxInvert(uint8_t num);

uint8_t getSBoxValue(uint8_t num);
