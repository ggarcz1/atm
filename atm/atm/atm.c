#include "atm.h"
#include "ports.h"
#include "encryption/aes_funs.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>

#define MAX_NAME_LEN 250


ATM* atm_create()
{
    ATM *atm = (ATM*) malloc(sizeof(ATM));
    if(atm == NULL)
    {
        perror("Could not allocate ATM");
        exit(1);
    }

    // Set up the network state
    atm->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&atm->rtr_addr,sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    atm->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&atm->atm_addr, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);
    bind(atm->sockfd,(struct sockaddr *)&atm->atm_addr,sizeof(atm->atm_addr));

    // Set up the protocol state
    // TODO set up more, as needed
    //setup the original values for the atm class that i added -gil
    atm->username = NULL;
    atm->pin = 0;
    atm->max_attempts = 3;
    atm-> attempts = 0;
    atm->lockoutMinutes = 2;
    atm->atm_id = "8174";
    

    /*These fields are used to prevent unsolicited packets from messing up the key,iv order.
     * See function msg_from_bank below.
     */
    atm->temp_key = NULL;
    atm->temp_iv = NULL;
    
    return atm;
}

void atm_free(ATM *atm)
{
    if(atm != NULL)
    {
        close(atm->sockfd);
        fclose(atm->initfile);
        free(atm);
    }
}

ssize_t atm_send(ATM *atm, char *data, size_t data_len)
{
    /* Retrieve key and iv from init file. */
    unsigned char *key = malloc(33);
    unsigned char *iv = malloc(17);
    fscanf(atm->initfile, "%s", key);
    fscanf(atm->initfile, "%s", iv);

    /*Encrypt data*/
    unsigned char *ciphertext = calloc(data_len * 2, 1);
    int ctextlen = encrypt(key, iv, (unsigned char *) data, ciphertext);

    free(key);
    free(iv);


    return sendto(atm->sockfd, ciphertext, ctextlen, 0,
                  (struct sockaddr*) &atm->rtr_addr, sizeof(atm->rtr_addr));
}

ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(atm->sockfd, data, max_data_len, 0, NULL, NULL);
}

void atm_process_command(ATM *atm, char *command)
{
    check_command(atm, command);
}

int check_command(ATM *atm, char *command){
    char inpu[1000];
    //copy *commands into the input array
    strcpy(inpu, command);
    // printf("%s\n", input);
    // printf("%s\n", commands);
    // printf("%s\n", input);
    char *str;
    int counter = 0;
    char arg2[251] = {'\0'};
    // 0, invalid, 1, begin-session, 2 balance, 3 withdraw, 4 end-session
    int cmdNumber =  0;
    regex_t regex;
    // break up inpu into commands
    str = strtok(inpu, " ");
    
    while( str != NULL ) {
        // too many arguments
        if(counter == 2){
            printf("Invalid command\n");
            return -1;
        }

        if(counter == 0){
            if(!strcmp(str, "begin-session"))
                cmdNumber = 1;
            else if(!strcmp(str, "balance"))
                cmdNumber = 2;
            else if(!strcmp(str, "withdraw"))
                cmdNumber = 3;
            else if(!strcmp(str, "end-session"))
                cmdNumber = 4;
        }else if(counter == 1){
            // get second argument
            strncpy(arg2, str, strlen(str));
        }
        
        counter++;
        str = strtok(NULL, " ");
        }

        // 0, invalid, 1, begin-session, 2 balance, 3 withdraw, 4 end-session
        if(cmdNumber == 1){
            if(counter==1){
                printf("Usage: begin-session <user-name>\n");
            }else{
                regcomp(&regex, "^[a-zA-Z][a-zA-Z]*$", 0);
                int return_value = regexec(&regex, arg2, 0, NULL, 0);
                regfree(&regex);
                if(!return_value && strlen(arg2) <= 250){
                   begin_session(atm, arg2);
                   // printf("begin %s\n", arg2);
                }else
                    printf("Usage: begin-session <user-name>\n");
            }

        }else if(cmdNumber == 2){
            if(counter == 1)
                // printf("call balance\n");
                balance(atm);
            else{
               printf("Usage: balance\n");
            }

        }else if(cmdNumber == 3){
            regcomp(&regex, "^[0-9][0-9]*$", 0);
            int withdrawAmount = atoi(arg2);
            char val[251];
            sprintf(val, "%d", withdrawAmount); 
            int return_value = regexec(&regex, val, 0, NULL, 0);
            regfree(&regex);
            // correct regex and value2 is < max int value, value2 is not negative
            if(!return_value && withdrawAmount < 2147483647 && withdrawAmount > 0 ){
                // regex ok. call begin-session method passing username, value2 in
                withdraw(atm, withdrawAmount);
            }else
                printf("Usage: withdraw <amt>\n");

        }else if(cmdNumber == 4){
            if(counter == 1)
                end_session(atm);
            else{
                printf("Invalid command\n");
            }
            
        }else {
            printf("Invalid command\n");
            return -1;
        }
    return 0;
}

// functions TODO
/* Decryption of bank messages will happen within functions.*/

void attempts(ATM *atm){
    atm->attempts = atm->attempts + 1;
    if(atm->attempts == atm->max_attempts){
        printf("Error. 3 failed login attempts.\n");
        printf("Try again in %d minutes", atm->lockoutMinutes);
        //sleep for 2*60 seconds
        sleep(atm->lockoutMinutes*60);
        atm->attempts = 0;
    }
    
}

int begin_session(ATM *atm, char *username){
    int user_len = strlen(username);
    char *recvline;
    unsigned char *plaintext;     //250+4+1
    char *ctext_lenstr;
    int cipher_len;
    int delin;
    int pin;
    char card_user[251];
    FILE *card;
    char *pin_input;

    char *message;
    char *received;
    char *status;

    if(atm->username != NULL){
        printf("A user is already logged in\n");
        return -1;
    }
    // check the database for *username (send message to bank)
    // if it !exist, (Receive message from bank.  If Unauthorized,)
    // printf("No such user\n"); 

    /* Prepare message */
    message = calloc(300,1);
    sprintf(message,"%s s %s", atm->atm_id, username);
    //printf("Begin_session() message sent to bank\n");

    /* Send message to bank*/
    atm_send(atm, message, strlen(message));

    /* Receive message from bank (This should return Authorized or Unauthorized*/
    received = (char *) msg_from_bank(atm);
    //printf("begin_session() Received: %s from bank\n", received);

    /* Parse message */
    status = calloc(20,1);
    sscanf((const char *) received, "%*s %s", status);

    if (strstr(status, "Authorized")) {
        ctext_lenstr = calloc(16,1);
        recvline = calloc(256, 1);
        plaintext = calloc(255, 1);

        //------ Start of .card reading code ------
        char *card_name = calloc(user_len+8+1, 1); //length of name + ./ + .card + \0
        sprintf(card_name, "./%s.card", username);
        card = fopen(card_name, "r");
        if(card == NULL){
            printf("Unable to access %s's card\n",username);
            return 0;
        }
        //read line and length from .card
        fscanf(card, "%[^\n]", recvline);
        fscanf(card, "\n%s", ctext_lenstr);
        //decrypt line from .card
        cipher_len = atoi(ctext_lenstr);
        decrypt(atm->cardkey, atm->card_iv, (unsigned char *) recvline, plaintext, cipher_len);
        //get username and pin from plaintext
        //printf("plaintext: %s\n", plaintext);
        delin = strlen((char *) plaintext);
        delin -= 4;
        strncpy(card_user, (char *) plaintext, (delin-1));
        pin = atoi((const char *) plaintext+delin);

        //printf("username received from card (card_user): %s\n", card_user);
        //checks if the cards have been tampered with or lost
        if (strcmp(card_user, username)!=0){
            //printf("here\n");
            printf("Not authorized\n");
            return 0;
        }
        fclose(card);
        free(ctext_lenstr);
        free(recvline);
        free(plaintext);
        free(card_name);
        //------ End of .card reading code ------
        // no errors
        // if(noErrors) (If message from bank reads Authorized,)
        // printf("PIN?\n")
        // get pin from command line  - compare to pin variable

        pin_input = calloc(6,1);
        printf("PIN? ");
        fgets(pin_input, 6, stdin);


        if (atoi(pin_input) == pin) {
            printf("Authorized\n");
            atm->username = calloc(strlen(username) + 1, 1);
            strncpy(atm->username, username, strlen(username));
        }
        else {
            printf("Not Authorized\n");
        }
        free(pin_input);

    }
    else {
        printf("No such user\n");
    }

    free(message);
    free(received);
    free(status);

    return 0;
}

int withdraw(ATM *atm, int amount){
     if(atm->username == NULL){
        printf("No user is logged in\n");
        return -1;
    }else{
        char *message;
        unsigned char *received;
        char *status;

        /* Prepare message */
        message = calloc(300,1);
        sprintf(message,"%s w %s %d", atm->atm_id, atm->username, amount);

        /* Send message to bank*/
        atm_send(atm, message, strlen(message));

        /* Receive message from bank (This should return Authorized or Unauthorized*/
        received = msg_from_bank(atm);

        /* Parse message */
        status = calloc(16,1);
        sscanf((const char *) received, "%*s %s", status);

        if(!strcmp(status, "Unauthorized")){
            printf("Insufficient funds\n");
        }else{
            printf("$%d dispensed\n", amount);
        }

        free(message);
        free(received);
        free(status);
    }
        
    return 0;
}

int balance(ATM *atm){
    char *message;
    unsigned char *received;
    char *bal;
    int bal_num;

    if(atm->username == NULL){
        printf("No user is logged in\n");
        return -1;
    }else{
        /* Prepare message */
        message = calloc(300,1);
        sprintf(message,"%s b %s", atm->atm_id, atm->username);

        /* Send message to bank*/
        atm_send(atm, message, strlen(message));

        /* Receive message from bank (This should ALWAYS return a balance)*/
        received = msg_from_bank(atm);
        //printf("Balance received: %s\n", received);

        /* Parse message */
        bal = calloc(16,1);
        sscanf((const char *) received, "%*s %s", bal);
        bal_num = atoi(bal);

        printf("$%d\n", bal_num);
    }

    /*cleanup*/
    free(message);
    free(received);
    free(bal);

    return 0;
}

int end_session(ATM *atm){
    if(atm->username == NULL){
        printf("No user is logged in\n");
        return -1;
    }else{
        atm->attempts = 0;
        free(atm->username);
        atm->username = NULL;
        printf("User logged out\n");
        return 0;
    }
}
int check_file(ATM *atm, char *filename){	
  	FILE *fd = fopen(filename, "r");
  	if(fd == NULL){
    	printf("Error opening ATM initialization file\n");
    	return 64;
    }

    atm->initfile = fd;
    //set up values for key and iv for cards this needs to be the first scan of atm->initfile
    //atm and bank will have the same cardkey and card_iv to encrypt and decrypt cards using secret key-iv pair
    //This is done immediatly to make sure atm and bank have the same keys
    fscanf(atm->initfile, "%s", atm->cardkey);
    atm->cardkey[32]='\0';
    fscanf(atm->initfile, "%s", atm->card_iv);
    atm->card_iv[16] = '\0';

    /*Note: fd will be closed in the free atm function. */
	return 0;
}

/*Function processes messages that the bank sends in response to the atm.  Length
 * of message received should never be more than 64. This function will never be called
 * unless a packet is expected from the bank. If an unsolicited packet is received, the function will wait until
 * a packet from the bank is received.  NOTE: This function returns a pointer to the message.  It is up to the caller to free
 * that memory.
 */
unsigned char *msg_from_bank(ATM *atm) {
    char* bank_id = "4823";
    int bank_response = 0;
    char *recvline;
    unsigned char *plaintext_buf;

    int n;

    unsigned char *key;
    unsigned char *iv;

    do {
        /*64 just to be safe*/
        recvline = calloc(64,1);
        n = atm_recv(atm, recvline, 64);
        //printf("ATM received %d bytes of data\n", n);

        plaintext_buf = calloc(64,1);

        /*If temp_key fields are set, then retrieve them.  Else, get new ones fron init*/
        if(atm->temp_key && atm->temp_iv){
            key = atm->temp_key;
            iv = atm->temp_iv;
        }
        else {
            key = malloc(33);
            iv = malloc(17);
            fscanf(atm->initfile, "%s", key);
            fscanf(atm->initfile, "%s", iv);
        }

        /*Decrypt text*/
        decrypt(key, iv, (unsigned char *) recvline, plaintext_buf, n);
        //printf("Plaintext buf: %s\n", plaintext_buf);

        if (strstr((char *) plaintext_buf, bank_id)){
            atm->temp_key = NULL;
            atm->temp_iv = NULL;
            free(key);
            free(iv);
            bank_response = 1;
        }
        else{
            /*If this code is reached, the packet that the atm received was unsolicited.*/

            /*If temps are not set, set them.*/
            if(!(atm->temp_key && atm->temp_iv)) {
                atm->temp_key = key;
                atm->temp_iv = iv;
                key = NULL;
                iv = NULL;
                free(plaintext_buf);
            }
        }
        
        free(recvline);
    } while(!bank_response);


    return plaintext_buf;
}

