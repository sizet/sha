// ©.
// https://github.com/sizet/sha

#include <stdio.h>
#include <endian.h>
#include <stdint.h>
#include <string.h>
#include <byteswap.h>
#include "sha1_hash.h"




// SHA1 將資料分為 N 組處理, 每組長度 64byte (16 個 4byte).
typedef uint32_t   UNIT_TYPE;
#define UINT_COUNT 16
#define BLOCK_SIZE (sizeof(UNIT_TYPE) * UINT_COUNT)

// 資料結束標誌.
typedef uint8_t     ENDING_TYPE;
#define ENDING_LEN  sizeof(ENDING_TYPE)
#define ENDING_BYTE 0x80

// 資料長度單位.
typedef uint64_t   LENGTH_TYPE;
#define LENGTH_LEN sizeof(LENGTH_TYPE)

// 填充.
#define PADDING_BYTE 0x00

#define RLEFT(x, n) (((x) << (n)) | ((x) >> ((sizeof(UNIT_TYPE) * 8) - (n))))

#define ROUND(a, b, c, d, e, x) \
    e = d;            \
    d = c;            \
    c = RLEFT(b, 30); \
    b = a;            \
    a = x




void sha1_hash(
    void *data_con,
    size_t data_len,
    char *out_buf,
    size_t out_size)
{
    UNIT_TYPE h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}, w[80] = {0};
    UNIT_TYPE a, b, c, d, e, x, *input_data = NULL;
    uint8_t data_buf[BLOCK_SIZE * 2], *fill_offset = NULL;
    size_t padding_len, input_len, raw_len, i;


    // SHA1 將資料分為 64byte 為一組做處理, 所以總長度必須是 64 的倍數, 不足的話需要填充 :
    // [原始資料] + [0x80] + [0x00 x N (N = 0...)] + [原始資料長度 (8byte)]

    // 計算需要多填充幾個 0x00.
    // 1. 計算 [原始資料] + [0x80] + [資料長度 (8byte)] 除 64 會餘多少.
    // 2. 餘的值是 0, 不需要填充 0x00.
    //    餘的值非 0, 需要填充 [64 - 餘] 個 0x00.
    padding_len = (data_len + ENDING_LEN + LENGTH_LEN) % BLOCK_SIZE;
    padding_len = padding_len == 0 ? 0 : BLOCK_SIZE - padding_len;

    // 總共要處理的資料長度.
    input_len = data_len + ENDING_LEN + padding_len + LENGTH_LEN;

    raw_len = data_len;

    while(input_len > 0)
    {
        // 計算要的處理的原始資料長度, 將資料分為 64byte 為一組做處理,
        // 剩餘的原始資料長度 >= 64byte, 直接處理原始資料.
        // 剩餘的原始資料長度 <  64byte, 複製到緩衝處理剩餘的 (後面會加上額外資料一起處理).
        if(raw_len >= BLOCK_SIZE)
        {
            input_data = (UNIT_TYPE *) data_con;
            data_con += BLOCK_SIZE;
            raw_len -= BLOCK_SIZE;
        }
        else
        {
            // 剩餘的原始資料長度 < 64byte 時,
            // 需要補上 [0x80] + [0x00 x N (N = 0...)] + [原始資料長度 (8byte)] 一起處理.
            // 如果剩餘的原始資料長度 <= 55byte, 加上額外資料之後是  64byte, 需要處理一次.
            // 如果剩餘的原始資料長度 >  55byte, 加上額外資料之後是 128byte, 需要處理二次.

            // 加上額外資料.
            if(fill_offset == NULL)
            {
                // 複製剩下的原始資料.
                memcpy(data_buf, data_con, raw_len);
                // 加入 0x80.
                fill_offset = data_buf + raw_len;
                *((ENDING_TYPE *) fill_offset) = ENDING_BYTE;
                // 填充 0x00.
                fill_offset += ENDING_LEN;
                memset(fill_offset, PADDING_BYTE, padding_len);
                // 加入原始資料長度, SHA1 要求大端格式, 如果是小端系統需要轉換.
                fill_offset += padding_len;
                *((LENGTH_TYPE *) ((void *) fill_offset)) =
#if __BYTE_ORDER == __LITTLE_ENDIAN
                    bswap_64(((LENGTH_TYPE) data_len) * 8);
#elif __BYTE_ORDER == __BIG_ENDIAN
                    ((LENGTH_TYPE) data_len) * 8;
#else
#error "please check endian type"
#endif
                input_data = (UNIT_TYPE *) ((void *) data_buf);
            }
            // 剩餘的原始資料長度 > 55byte, 處理第二次.
            else
            {
                input_data = (UNIT_TYPE *) ((void *) (data_buf + BLOCK_SIZE));
            }
        }
        input_len -= BLOCK_SIZE;

        // 開始 SHA1 處理.

        // 填入要處理的資料, SHA1 要求大端格式, 如果是小端系統需要轉換.
        for(i = 0; i < UINT_COUNT; i++)
#if __BYTE_ORDER == __LITTLE_ENDIAN
            w[i] = bswap_32(input_data[i]);
#elif __BYTE_ORDER == __BIG_ENDIAN
            w[i] = input_data[i];
#else
#error "please check endian type"
#endif

        for(i = UINT_COUNT; i < 80; i++)
            w[i] = RLEFT(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

        a = h[0];
        b = h[1];
        c = h[2];
        d = h[3];
        e = h[4];

        for(i = 0; i < 20; i++)
        {
            x = RLEFT(a, 5) + ((b & c) | (~b & d)) + e + w[i] + 0x5A827999;
            ROUND(a, b, c, d, e, x);
        }
        for(i = 20; i < 40; i++)
        {
            x = RLEFT(a, 5) + (b ^ c ^ d) + e + w[i] + 0x6ED9EBA1;
            ROUND(a, b, c, d, e, x);
        }
        for(i = 40; i < 60; i++)
        {
            x = RLEFT(a, 5) + ((b & c) | (b & d) | (c & d)) + e + w[i] + 0x8F1BBCDC;
            ROUND(a, b, c, d, e, x);
        }
        for(i = 60; i < 80; i++)
        {
            x = RLEFT(a, 5) + (b ^ c ^ d) + e + w[i] + 0xCA62C1D6;
            ROUND(a, b, c, d, e, x);
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
    }

    snprintf(out_buf, out_size, "%08x%08x%08x%08x%08x", h[0], h[1], h[2], h[3], h[4]);
}
