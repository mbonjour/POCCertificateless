/**
 * @file aesUtils.h
 * @author Mickael Bonjour mickael.bonjour@heig-vd.ch
 * @date 13 juillet 2020
 * @brief A file to encrypt/decrypt AES and generate a key
 */
#ifndef AES_UTILS_H
#define AES_UTILS_H

#include "sodium.h"
#include "relic.h"

/**
 * @brief Encrypt a message with the AES_GCM in libsodium
 * @param m message to encrypt
 * @param key The key used for encryption
 * @param nonce The IV used for encryption
 * @param cipher The cipher after encryption
 * @param cipher_len THe cipher length
 * @param m_len The length of the message to encrypt
 * @param ad_data The data that needs to be authentified
 * @param ad_len The length of the authenticated data
 */
void encrypt_message(const unsigned char* m, unsigned char* key, unsigned char* nonce, unsigned char* cipher, unsigned long long* cipher_len, const size_t* m_len, unsigned char* ad_data, size_t ad_len);
/**
 *
 * @param decrypted Decrypted data
 * @param cipher Cipher to decrypt
 * @param nonce IV used at encryption
 * @param key Key to decrypt the cipher
 * @param cipher_len The length of the cipher
 * @param ad_data The data that needs to be authentified
 * @param ad_len The length of the authenticated data
 */
void decrypt_message(unsigned char* decrypted, unsigned char* cipher, unsigned char* nonce, unsigned char* key, unsigned long long cipher_len, unsigned char* ad_data, size_t ad_len);

/**
 * @brief Generate an AES key with a gt element, hashing the binary data of the gt element.
 * @param aesk Where the key will be stored
 * @param originalM The GT element transforming to an AES key
 */
void get_key(char *aesk, gt_t originalM);

#endif //AES_UTILS_H