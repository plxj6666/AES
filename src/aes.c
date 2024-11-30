#include "aes.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "tables.h"
// 在文件开头添加宏定义
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \


#define rotr32(value, shift) ((value >> shift) ^ (value << (32 - shift)))

static unsigned char xtime(unsigned char x) {
    return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

static void InvMixColumns(unsigned char state[4][4]) {
    unsigned char temp[4];
    
    for(int col = 0; col < 4; col++) {
        // 保存当前列
        for(int row = 0; row < 4; row++) {
            temp[row] = state[row][col];
        }
        
        // 计算新的列值
        state[0][col] = (unsigned char)(Multiply(temp[0], 0x0e) ^ Multiply(temp[1], 0x0b) ^ 
                                      Multiply(temp[2], 0x0d) ^ Multiply(temp[3], 0x09));
        state[1][col] = (unsigned char)(Multiply(temp[0], 0x09) ^ Multiply(temp[1], 0x0e) ^ 
                                      Multiply(temp[2], 0x0b) ^ Multiply(temp[3], 0x0d));
        state[2][col] = (unsigned char)(Multiply(temp[0], 0x0d) ^ Multiply(temp[1], 0x09) ^ 
                                      Multiply(temp[2], 0x0e) ^ Multiply(temp[3], 0x0b));
        state[3][col] = (unsigned char)(Multiply(temp[0], 0x0b) ^ Multiply(temp[1], 0x0d) ^ 
                                      Multiply(temp[2], 0x09) ^ Multiply(temp[3], 0x0e));
    }
}

// Rcon array for key schedule
static const uint8_t Rcon[11] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x00  // Last 0x00 is dummy for simplification
};

int aes_make_enc_subkeys(const unsigned char key[16], unsigned char subKeys[11][16]) {
    int i;
    uint32_t *rk = (uint32_t *)subKeys;
    uint32_t temp;

    // 第一轮密钥，保持正序
    for (i = 0; i < 4; i++) {
        rk[i] = ((uint32_t)key[4*i+3]) | 
                ((uint32_t)key[4*i+2] << 8) |
                ((uint32_t)key[4*i+1] << 16) |
                ((uint32_t)key[4*i] << 24);
    }

    // 后续轮密钥生成
    for (i = 4; i < 44; i++) {
        temp = rk[i-1];
        if (i % 4 == 0) {
            // RotWord
            temp = (temp << 8) | (temp >> 24);
            
            // SubWord (保持正序)
            temp = ((uint32_t)sbox[temp & 0xFF]) |
                  ((uint32_t)sbox[(temp >> 8) & 0xFF] << 8) |
                  ((uint32_t)sbox[(temp >> 16) & 0xFF] << 16) |
                  ((uint32_t)sbox[(temp >> 24) & 0xFF] << 24);
            
            // Rcon
            temp ^= (uint32_t)Rcon[i/4 - 1] << 24;
        }
        rk[i] = rk[i-4] ^ temp;
    }

    return 0;
}

int aes_make_dec_subkeys(const unsigned char key[16], unsigned char subKeys[11][16]) {
    uint32_t *rk = (uint32_t *)subKeys;
    uint32_t temp;
    int i;

    // 1. 生成初始轮密钥（与加密相同）
    for (i = 0; i < 4; i++) {
        rk[i] = ((uint32_t)key[4*i+3]) | 
                ((uint32_t)key[4*i+2] << 8) |
                ((uint32_t)key[4*i+1] << 16) |
                ((uint32_t)key[4*i] << 24);
    }

    // 2. 生成后续轮密钥
    for (i = 4; i < 44; i++) {
        temp = rk[i-1];
        if (i % 4 == 0) {
            temp = (temp << 8) | (temp >> 24);
            temp = ((uint32_t)sbox[temp & 0xFF]) |
                  ((uint32_t)sbox[(temp >> 8) & 0xFF] << 8) |
                  ((uint32_t)sbox[(temp >> 16) & 0xFF] << 16) |
                  ((uint32_t)sbox[(temp >> 24) & 0xFF] << 24);
            temp ^= (uint32_t)Rcon[i/4 - 1] << 24;
        }
        rk[i] = rk[i-4] ^ temp;
    }

    // 3. 对中间轮密钥应用InvMixColumns
    unsigned char state[4][4];
    for (i = 1; i < 10; i++) {
        // 转换为4x4矩阵
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[r][c] = (uint8_t)(rk[i*4 + c] >> (24 - 8*r));
            }
        }
        
        // 应用InvMixColumns
        InvMixColumns(state);
        
        // 转换回32位值
        for (int c = 0; c < 4; c++) {
            rk[i*4 + c] = ((uint32_t)state[0][c] << 24) |
                         ((uint32_t)state[1][c] << 16) |
                         ((uint32_t)state[2][c] << 8) |
                         ((uint32_t)state[3][c]);
        }
    }

    // 4. 修改反转轮密钥顺序的部分
    uint32_t temp1[4];
    for (i = 0; i < 5; i++) {  // 只需要反转一半，因为是对称交换
        // 保存前面的4个32位值
        temp1[0] = rk[i*4];
        temp1[1] = rk[i*4 + 1];
        temp1[2] = rk[i*4 + 2];
        temp1[3] = rk[i*4 + 3];
        
        // 与对应的后面的4个32位值交换
        rk[i*4] = rk[40 - i*4];
        rk[i*4 + 1] = rk[40 - i*4 + 1];
        rk[i*4 + 2] = rk[40 - i*4 + 2];
        rk[i*4 + 3] = rk[40 - i*4 + 3];
        
        // 将保存的值放到后面的位置
        rk[40 - i*4] = temp1[0];
        rk[40 - i*4 + 1] = temp1[1];
        rk[40 - i*4 + 2] = temp1[2];
        rk[40 - i*4 + 3] = temp1[3];
    }

    return 0;
}


void aes_encrypt_block(const unsigned char *input, unsigned char subKeys[11][16], unsigned char *output) {
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
    const uint32_t *rk = (const uint32_t *)subKeys;
    // 按行优先加载输入数据
    s0 = ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) |
         ((uint32_t)input[2] << 8) | (uint32_t)input[3];
    s1 = ((uint32_t)input[4] << 24) | ((uint32_t)input[5] << 16) |
         ((uint32_t)input[6] << 8) | (uint32_t)input[7];
    s2 = ((uint32_t)input[8] << 24) | ((uint32_t)input[9] << 16) |
         ((uint32_t)input[10] << 8) | (uint32_t)input[11];
    s3 = ((uint32_t)input[12] << 24) | ((uint32_t)input[13] << 16) |
         ((uint32_t)input[14] << 8) | (uint32_t)input[15];

    // 轮密钥加就是直接异或,不需要移位
    s0 ^= rk[0];  // 正确的,因为rk[0]已经是正确格式的32位值
    s1 ^= rk[1];
    s2 ^= rk[2];
    s3 ^= rk[3];

    // 主轮
    for(int i = 1; i < 10; i++) {

        t0 = Te0[(s0 >> 24) & 0xff] ^ Te1[(s1 >> 16) & 0xff] ^
             Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[i*4];
        t1 = Te0[(s1 >> 24) & 0xff] ^ Te1[(s2 >> 16) & 0xff] ^
             Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[i*4 + 1];
        t2 = Te0[(s2 >> 24) & 0xff] ^ Te1[(s3 >> 16) & 0xff] ^
             Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[i*4 + 2];
        t3 = Te0[(s3 >> 24) & 0xff] ^ Te1[(s0 >> 16) & 0xff] ^
             Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[i*4 + 3];

        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }


    // 1. SubBytes: 先对所有字节进行S盒替换
    uint32_t b0 = ((uint32_t)Te4[(t0 >> 24) & 0xff] << 24) |
                  ((uint32_t)Te4[(t0 >> 16) & 0xff] << 16) |
                  ((uint32_t)Te4[(t0 >> 8) & 0xff] << 8) |
                  ((uint32_t)Te4[t0 & 0xff]);
    uint32_t b1 = ((uint32_t)Te4[(t1 >> 24) & 0xff] << 24) |
                  ((uint32_t)Te4[(t1 >> 16) & 0xff] << 16) |
                  ((uint32_t)Te4[(t1 >> 8) & 0xff] << 8) |
                  ((uint32_t)Te4[t1 & 0xff]);
    uint32_t b2 = ((uint32_t)Te4[(t2 >> 24) & 0xff] << 24) |
                  ((uint32_t)Te4[(t2 >> 16) & 0xff] << 16) |
                  ((uint32_t)Te4[(t2 >> 8) & 0xff] << 8) |
                  ((uint32_t)Te4[t2 & 0xff]);
    uint32_t b3 = ((uint32_t)Te4[(t3 >> 24) & 0xff] << 24) |
                  ((uint32_t)Te4[(t3 >> 16) & 0xff] << 16) |
                  ((uint32_t)Te4[(t3 >> 8) & 0xff] << 8) |
                  ((uint32_t)Te4[t3 & 0xff]);
    // 2. ShiftRows: 按行移位
    s0 = (b0 & 0xff000000) | (b1 & 0x00ff0000) | (b2 & 0x0000ff00) | (b3 & 0x000000ff);
    s1 = (b1 & 0xff000000) | (b2 & 0x00ff0000) | (b3 & 0x0000ff00) | (b0 & 0x000000ff);
    s2 = (b2 & 0xff000000) | (b3 & 0x00ff0000) | (b0 & 0x0000ff00) | (b1 & 0x000000ff);
    s3 = (b3 & 0xff000000) | (b0 & 0x00ff0000) | (b1 & 0x0000ff00) | (b2 & 0x000000ff);
    // 3. AddRoundKey: 与最后一轮密钥异或
    s0 ^= rk[40];
    s1 ^= rk[41];
    s2 ^= rk[42];
    s3 ^= rk[43];


    // 按行优先顺序存储输出
    output[0] = (uint8_t)(s0 >> 24);   // 第0行
    output[1] = (uint8_t)(s0 >> 16);
    output[2] = (uint8_t)(s0 >> 8);
    output[3] = (uint8_t)(s0);
    
    output[4] = (uint8_t)(s1 >> 24);   // 第1行
    output[5] = (uint8_t)(s1 >> 16);
    output[6] = (uint8_t)(s1 >> 8);
    output[7] = (uint8_t)(s1);
    
    output[8] = (uint8_t)(s2 >> 24);    // 第2行
    output[9] = (uint8_t)(s2 >> 16);
    output[10] = (uint8_t)(s2 >> 8);
    output[11] = (uint8_t)(s2);
    
    output[12] = (uint8_t)(s3 >> 24);  // 第3行
    output[13] = (uint8_t)(s3 >> 16);
    output[14] = (uint8_t)(s3 >> 8);
    output[15] = (uint8_t)(s3);
}

void aes_decrypt_block(const unsigned char *input, unsigned char subKeys[11][16], unsigned char *output) {
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3, tmp;
    const uint32_t *rk = (const uint32_t *)subKeys;
    // 按行优先加载输入数据
    s0 = ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) |
         ((uint32_t)input[2] << 8) | (uint32_t)input[3];
    s1 = ((uint32_t)input[4] << 24) | ((uint32_t)input[5] << 16) |
         ((uint32_t)input[6] << 8) | (uint32_t)input[7];
    s2 = ((uint32_t)input[8] << 24) | ((uint32_t)input[9] << 16) |
         ((uint32_t)input[10] << 8) | (uint32_t)input[11];
    s3 = ((uint32_t)input[12] << 24) | ((uint32_t)input[13] << 16) |
         ((uint32_t)input[14] << 8) | (uint32_t)input[15];
    // 初始轮密钥加
    s0 ^= rk[0];
    s1 ^= rk[1];
    s2 ^= rk[2];
    s3 ^= rk[3];
    // 主轮逻辑
    for (int i = 1; i < 10; i++) {
        t0 = TD[(s0 >> 24) & 0xFF];
        tmp = TD[(s3 >> 16) & 0xFF];
        t0 ^= rotr32(tmp, 8);
        tmp = TD[(s2 >> 8) & 0xFF];
        t0 ^= rotr32(tmp, 16);
        tmp = TD[(s1 >> 0) & 0xFF];
        t0 ^= rotr32(tmp, 24);
        // t1
        t1 = TD[(s1 >> 24) & 0xFF];
        tmp = TD[(s0 >> 16) & 0xFF];
        t1 ^= rotr32(tmp, 8);
        tmp = TD[(s3 >> 8) & 0xFF];
        t1 ^= rotr32(tmp, 16);
        tmp = TD[(s2 >> 0) & 0xFF];
        t1 ^= rotr32(tmp, 24);
        // t2
        t2 = TD[(s2 >> 24) & 0xFF];
        tmp = TD[(s1 >> 16) & 0xFF];
        t2 ^= rotr32(tmp, 8);
        tmp = TD[(s0 >> 8) & 0xFF];
        t2 ^= rotr32(tmp, 16);
        tmp = TD[(s3 >> 0) & 0xFF];
        t2 ^= rotr32(tmp, 24);
        // t3
        t3 = TD[(s3 >> 24) & 0xFF];
        tmp = TD[(s2 >> 16) & 0xFF];
        t3 ^= rotr32(tmp, 8);
        tmp = TD[(s1 >> 8) & 0xFF];
        t3 ^= rotr32(tmp, 16);
        tmp = TD[(s0 >> 0) & 0xFF];
        t3 ^= rotr32(tmp, 24);
        s0 = t0 ^ rk[i*4];
        s1 = t1 ^ rk[i*4 + 1];
        s2 = t2 ^ rk[i*4 + 2];
        s3 = t3 ^ rk[i*4 + 3];
    }

    // 逆S盒替换
    t0 = rsbox[(s0 >> 24) & 0xFF] << 24;
    t0 |= rsbox[(s0 >> 16) & 0xFF] << 16;
    t0 |= rsbox[(s0 >> 8) & 0xFF] << 8;
    t0 |= rsbox[(s0 >> 0) & 0xFF] << 0;
    // t1
    t1 = rsbox[(s1 >> 24) & 0xFF] << 24;
    t1 |= rsbox[(s1 >> 16) & 0xFF] << 16;
    t1 |= rsbox[(s1 >> 8) & 0xFF] << 8;
    t1 |= rsbox[(s1 >> 0) & 0xFF] << 0;
    // t2
    t2 = rsbox[(s2 >> 24) & 0xFF] << 24;
    t2 |= rsbox[(s2 >> 16) & 0xFF] << 16;
    t2 |= rsbox[(s2 >> 8) & 0xFF] << 8;
    t2 |= rsbox[(s2 >> 0) & 0xFF] << 0;
    // t3
    t3 = rsbox[(s3 >> 24) & 0xFF] << 24;
    t3 |= rsbox[(s3 >> 16) & 0xFF] << 16;
    t3 |= rsbox[(s3 >> 8) & 0xFF] << 8;
    t3 |= rsbox[(s3 >> 0) & 0xFF] << 0;
    // Invshiftrows
    s0 = (t0 & 0xff000000) | (t3 & 0x00ff0000) | (t2 & 0x0000ff00) | (t1 & 0x000000ff);
    s1 = (t1 & 0xff000000) | (t0 & 0x00ff0000) | (t3 & 0x0000ff00) | (t2 & 0x000000ff);
    s2 = (t2 & 0xff000000) | (t1 & 0x00ff0000) | (t0 & 0x0000ff00) | (t3 & 0x000000ff);
    s3 = (t3 & 0xff000000) | (t2 & 0x00ff0000) | (t1 & 0x0000ff00) | (t0 & 0x000000ff);
    //------------AddRoundKey-------------
    s0 = s0 ^ rk[40];
    s1 = s1 ^ rk[41];
    s2 = s2 ^ rk[42];
    s3 = s3 ^ rk[43];
    // 按行优先顺序存储输出
    output[0] = (uint8_t)(s0 >> 24);
    output[1] = (uint8_t)(s0 >> 16);
    output[2] = (uint8_t)(s0 >> 8);
    output[3] = (uint8_t)(s0);
    output[4] = (uint8_t)(s1 >> 24);
    output[5] = (uint8_t)(s1 >> 16);
    output[6] = (uint8_t)(s1 >> 8);
    output[7] = (uint8_t)(s1);
    output[8] = (uint8_t)(s2 >> 24);
    output[9] = (uint8_t)(s2 >> 16);
    output[10] = (uint8_t)(s2 >> 8);
    output[11] = (uint8_t)(s2);
    output[12] = (uint8_t)(s3 >> 24);
    output[13] = (uint8_t)(s3 >> 16);
    output[14] = (uint8_t)(s3 >> 8);
    output[15] = (uint8_t)(s3);
}