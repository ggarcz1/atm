#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes_funs.h"

#include <unistd.h>
#include <fcntl.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>


/* Pulled from OpenSSL.org */
static void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

/* Given a 256 bit key and a 128 bit iv, this function will encrypt "plaintext" using
 * AES256 in CBC mode.  It will return the length of 'ciphertext'.  It will put the cipher text
 * into the memory location pointed to by 'ciphertext'.
 * 
 * NOTE: It is assumed that plaintext is a nul-byte appended string, and 'ciphertext' points
 * to a large enough block of memory.
 */
int encrypt(unsigned char *key, unsigned char *iv, unsigned char *plaintext, unsigned char *ciphertext) {

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    int ptextlen = strlen((const char *) plaintext);


    /* Create and initialize the context. */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*Initializes encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    
    /*Perform the encryption (message is small enough to do once)*/
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, ptextlen))
        handleErrors();
    ciphertext_len = len;

    /* Finalize encryption */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/* This function will take a key, iv, ciphertext length, and a ciphertext.  It will
 * return the corresponding plaintext string, nul-byte appended.  
 */
int decrypt(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned char *plaintext, int ciphertext_len) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    /* Used to make decrypted string identical to plaintext.*/
    char *returntext = calloc(2*ciphertext_len, 1);

    /*Create and initialize context*/
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*Initialize decryption operation.*/
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*Perform decryption operation.  Only needs to be done once*/
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*Finalize decryption*/
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;
      
    /*Clean up*/
    EVP_CIPHER_CTX_free(ctx);

    /* Manually remove padding. */
    strncpy(returntext, (char *) plaintext, plaintext_len);
    strncpy((char *) plaintext, returntext, ciphertext_len);

    free(returntext);

    return plaintext_len;
}