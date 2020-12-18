#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes_funs.h"




int main(){

    unsigned char *key = (unsigned char *) "11583052300000000000000000000000";
    unsigned char *iv = (unsigned char *) "0000000000000000";

    char *plaintext = "Authorized   ";
    char *decrypted = calloc(512,1);
    char *ciphertext = calloc(512, 1);
    int ctextlen;
    int ptextlen;

    printf("Plaintext: %s\n", plaintext);

    ctextlen = encrypt(key, iv, plaintext, ciphertext);
    printf("Ciphertext: %s\n", ciphertext);
    printf("Ciphertext length: %d\n", ctextlen);

    ptextlen = decrypt(key, iv, ciphertext, decrypted, ctextlen);
    printf("Decrypted: %s\n", decrypted);
    printf("Decrypted text length: %d\n", ptextlen);

    if (!strcmp(decrypted, plaintext))
        printf("The plaintext string and decrypted string are exactly the same!!\n");
    else
        printf("The plaintext string and decrypted string are different!\n");
    


    free(ciphertext);
    free(decrypted);


    return 0;
}