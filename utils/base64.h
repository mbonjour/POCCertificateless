/**
 * @file base64.h
 * @author https://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c
 * @date 13 juillet 2020
 * @brief File to encode/decode base64
 */

#ifndef POCCERTIFICATELESSCRYPTOGRAPHY_BASE64_H
#define POCCERTIFICATELESSCRYPTOGRAPHY_BASE64_H

#include <glob.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Encode a byte array of len to base64
 * @param src Byte array to encode
 * @param len Length of the source array
 * @param out_len Length of the resulting bas64 encoding
 * @return Return a pointer to the resulting base64 encoded string (need to be free'd)
 */
unsigned char * base64_encode(const unsigned char *src, size_t len,
                              size_t *out_len);

/**
 * @brief Decoding base64 encoded string
 * @param src Source string of base64 encoded data
 * @param len Length of the data to decode
 * @param out_len Length of the resulting data
 * @return Pointer to decoded data (need to be free'd)
 */
unsigned char * base64_decode(const unsigned char *src, size_t len,
                              size_t *out_len);

#endif //POCCERTIFICATELESSCRYPTOGRAPHY_BASE64_H
