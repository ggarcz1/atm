#include <stdio.h>

/* Given a 256 bit key and a 128 bit iv, this function will encrypt "plaintext" using
 * AES256 in CBC mode.  It will return the length of 'ciphertext'.  It will put the cipher text
 * into the memory location pointed to by 'ciphertext'.
 * 
 * NOTE: It is assumed that plaintext is a nul-byte appended string, and 'ciphertext' points
 * to a large enough block of memory.
 */
int encrypt(unsigned char *key, unsigned char *iv, unsigned char *plaintext, unsigned char *ciphertext);

/* This function takes a key, iv, ciphertext, plaintext, and ciphertext length.  It will return
 * the length of the plaintext, and it will store the plaintext in the block of memory pointed
 * to by 'plaintext'.
 */
int decrypt(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned char *plaintext, int ciphertext_len);
