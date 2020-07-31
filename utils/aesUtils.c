// Utils function for encrypting / decrypting AES_GCM
#include "aesUtils.h"

void encrypt_message(const unsigned char* m, unsigned char* key, unsigned char* nonce, unsigned char* cipher, unsigned long long* cipher_len, const size_t* m_len, unsigned char* ad_data, size_t ad_len){
    // Get a nonce randomly
    randombytes_buf(nonce, crypto_aead_aes256gcm_NPUBBYTES);
    // Encrypt with AES256_GCM
    crypto_aead_aes256gcm_encrypt(cipher, cipher_len, m, *m_len, ad_data, ad_len,NULL, nonce, key);
}

void decrypt_message(unsigned char* decrypted, unsigned char* cipher, unsigned char* nonce, unsigned char* key, unsigned long long cipher_len, unsigned char* ad_data, size_t ad_len){
    unsigned long long decrypted_len;
    // Decrypt using the given key and AES256_GCM
    if (cipher_len < crypto_aead_aes256gcm_ABYTES ||
        crypto_aead_aes256gcm_decrypt(decrypted, &decrypted_len,
                                      NULL,
                                      cipher, cipher_len,
                                      ad_data,
                                      ad_len,
                                      nonce, key) != 0) {
        /* message forged! */
        printf("Message not correctly authenticated ! Aborting decryption...\n");
    }
}

void get_key(char *aesk, gt_t originalM) {
    // Get the binary data of the Gt element
    int sizeAESK = gt_size_bin(originalM,1);
    uint8_t aeskBin[sizeAESK];
    gt_write_bin(aeskBin, sizeAESK, originalM, 1);
    uint8_t master_key[32];
    // Hash with SHA-256 to have an master key for KDF from the Gt binary data
    md_map_sh256(master_key, aeskBin, sizeAESK);
    // KDF the "master key" to have a usable key to encrypt the data
    crypto_kdf_derive_from_key(aesk, 32, 1, "AES-KEY", master_key);

    /*
    printf("AES Key : ");
    for(int i=0;i < 32;i++)
        printf("%02X",(unsigned char)aesk[i]);
    printf("\n");
    */
}
