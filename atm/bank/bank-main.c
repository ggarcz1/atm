/* 
 * The main program for the Bank.
 *
 * You are free to change this as necessary.
 */

#include <string.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include "encryption/aes_funs.h"
#include "bank.h"
#include "ports.h"

static const char prompt[] = "BANK: ";



int main(int argc, char**argv)
{
   int n;
   char sendline[1000];
   char recvline[1000];
   unsigned char *plaintext_buf = calloc(300,1);

   char *atm_id = "8174";
   unsigned char *key;
   unsigned char *iv;

   Bank *bank = bank_create();

   /* Initialize bank init file*/
   char *bankFilename = argv[1];
   int open_init = check_file(bank, bankFilename);

   if(open_init != 0)
       return 64;

   printf("%s", prompt);
   fflush(stdout);


   while(1)
   {
       fd_set fds;
       FD_ZERO(&fds);
       FD_SET(0, &fds);
       FD_SET(bank->sockfd, &fds);
       select(bank->sockfd+1, &fds, NULL, NULL, NULL);

       if(FD_ISSET(0, &fds))
       {
           fgets(sendline, 1000,stdin);
           bank_process_local_command(bank, sendline, strlen(sendline));
           printf("%s", prompt);
           fflush(stdout);
       }
       else if(FD_ISSET(bank->sockfd, &fds))
       {
           n = bank_recv(bank, recvline, 300);

           /* If temp fields are set, then retrieve them*/
           if(bank->temp_key && bank->temp_iv) {
               key = bank->temp_key;
               iv = bank->temp_iv;
           }
           else {
                /* Retrieve key and iv from init file. */
                key = malloc(33);
                iv = malloc(17);
                fscanf(bank->initfile, "%s", key);
                fscanf(bank->initfile, "%s", iv);
           }

           /*Decrypt text*/
           int ptextlen = decrypt(key, iv, (unsigned char *) recvline, plaintext_buf, n);
           plaintext_buf[ptextlen] = '\0';


            /* If the packet was from the atm, then process the command*/
           if(strstr((char *) plaintext_buf, atm_id)){
               bank->temp_key = NULL;
               bank->temp_iv = NULL;
               free(key);
               free(iv);
               bank_process_remote_command(bank, (char *) plaintext_buf, ptextlen);
           }
           else {
               /* IF this code is reached, then the packet received was unsolicited. */

               if(!(bank->temp_key && bank->temp_iv)){
                   bank->temp_key = key;
                   bank->temp_iv = iv;
                   key = NULL;
                   iv = NULL;
               }
           }


       }
   }

   free(plaintext_buf);

   return EXIT_SUCCESS;
}
