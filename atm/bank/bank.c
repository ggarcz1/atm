#include "bank.h"
#include "ports.h"
#include "encryption/aes_funs.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>


Bank* bank_create()
{
    Bank *bank = (Bank*) malloc(sizeof(Bank));
    if(bank == NULL)
    {
        perror("Could not allocate Bank");
        exit(1);
    }

    // Set up the network state
    bank->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&bank->rtr_addr,sizeof(bank->rtr_addr));
    bank->rtr_addr.sin_family = AF_INET;
    bank->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&bank->bank_addr, sizeof(bank->bank_addr));
    bank->bank_addr.sin_family = AF_INET;
    bank->bank_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->bank_addr.sin_port = htons(BANK_PORT);
    bind(bank->sockfd,(struct sockaddr *)&bank->bank_addr,sizeof(bank->bank_addr));

    // Set up the protocol state
    // TODO set up more, as needed
    bank->bank_id = "4823";

    /*Create users table (max 20 users)*/
    bank->users = list_create();

    bank->temp_key = NULL;
    bank->temp_iv = NULL;

    return bank;
}

void bank_free(Bank *bank)
{
    if(bank != NULL)
    {
        close(bank->sockfd);
        fclose(bank->initfile);
        list_free(bank->users);
        free(bank);
    }
}

ssize_t bank_send(Bank *bank, char *data, size_t data_len)
{
    /* Retrieve key and iv from init file. */
    unsigned char *key = malloc(33);
    unsigned char *iv = malloc(17);
    fscanf(bank->initfile, "%s", key);
    fscanf(bank->initfile, "%s", iv);

    /* Encrypt data */
     unsigned char *ciphertext = calloc(data_len * 2, 1);
     int ctextlen = encrypt(key, iv, (unsigned char*) data, ciphertext);

     free(key);
     free(iv);
    
    // Returns the number of bytes sent; negative on error
    return sendto(bank->sockfd, ciphertext, ctextlen, 0,
                  (struct sockaddr*) &bank->rtr_addr, sizeof(bank->rtr_addr));
}

ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(bank->sockfd, data, max_data_len, 0, NULL, NULL);
}

int create_user(Bank *bank, char *username, int pin, int balance){
    int user_len = strlen(username);
    char pin_str[5];
    int cipher_len;
    FILE *card;
    char *bal_str;
    char *usr_str;

    /*These are used to save the length of the ciphertext*/
    int ctext_len = 0;
    char *ctext_lenstr;

    /*Check if the user already exists*/
    if (!list_find(bank->users, username)) {

        /*Create user in table users*/
        bal_str = calloc(11,1);
        usr_str = calloc(user_len+1, 1);
        sprintf(bal_str, "%d", balance); //conversion to string for list
        strncpy(usr_str, username, user_len);
        list_add(bank->users, usr_str, bal_str);
        usr_str = NULL;
        bal_str = NULL;



        //------ Start of .card creation code ------
        sprintf(pin_str, "%d", pin);
        char *card_name = calloc(user_len+9, 1);
        sprintf(card_name, "./%s.card", username);
        //The card is supposed to be created in the current directory and I think thats what this does 
        //probably relies on comand line data but idk
        card = fopen (card_name, "w+");
        if(card == NULL){
            printf("Error creating card file for user %s\n",username);
            //now roll back any changes made - it shouldn't have made any yet?
            return 0;
        }

        cipher_len = (user_len+6)*2;
        unsigned char *ciphertext = calloc(cipher_len, 1);
        char *plaintext = calloc((cipher_len/2), 1);
        strncpy(plaintext,username,user_len);
        strcat(plaintext," ");
        strcat(plaintext,pin_str);

        //printf("plaintext for card file: %s\n", plaintext);

        ctext_len = encrypt(bank->cardkey, bank->card_iv, (unsigned char *) plaintext, ciphertext);

        /*Pass actual length of ciphertext to card so that it could be decrypted*/
        ctext_lenstr = calloc(16, 1);
        sprintf(ctext_lenstr, "\n%d", ctext_len);

        fputs((char *)ciphertext, card);
        fputs(ctext_lenstr, card);
        free(card_name);
        free(ctext_lenstr);
        free(ciphertext);
        free(plaintext);
        fclose(card);
        //----- End of .card creation code ------
    }
    else
        printf("Error:  user %s already exists\n", username);
    


    return 0;
}


void bank_process_remote_command(Bank *bank, char *command, size_t len)
{
    // TODO: Implement the bank side of the ATM-bank protocol

    char mode = command[5];
    char *user = calloc(251,1);
    char *amount = calloc(11,1);


    int exists = 0;

    char *authorized = "4823 Authorized";
    char *unauthorized = "4823 Unauthorized";

    if (mode == 's') {
        sscanf(command, "%*s %*s %s", user);
        //Check that user exists
        exists = user_exists(bank, user);
        
        if (exists)
            bank_send(bank, authorized, strlen(authorized));
        else
            bank_send(bank, unauthorized, strlen(unauthorized));

        
    }
    else if (mode == 'w') {
        sscanf(command, "%*s %*s %s %s", user, amount);
        withdraw(bank, user, atoi(amount));
    }
    else if (mode == 'b') {
        sscanf(command, "%*s %*s %s", user);
        check_balance(bank, user, 1);
    }
    else {
        printf("Bank was unable to determine mode\n");
    }

    free(user);
    free(amount);
    
}


int check_file(Bank *bank, char *filename){	
  	FILE *fd = fopen(filename, "r");
  	if(fd == NULL){
    	printf("Error opening BANK initialization file\n");
    	return 64;
    }

    bank->initfile = fd;
    //set up values for key and iv for cards this needs to be the first scan of bank->initfile
    //atm and bank will have the same cardkey and card_iv to encrypt and decrypt cards using secret key-iv pair
    //This is done immediatly to make sure atm and bank have the same keys
    fscanf(bank->initfile, "%s", bank->cardkey);
    bank->cardkey[32]='\0';
    fscanf(bank->initfile, "%s", bank->card_iv);
    bank->card_iv[16] = '\0';

    /*Note: fd will be closed in the free bank function. */
	return 0;
}


void bank_process_local_command(Bank *bank, char *command, size_t len) {
    // When the command doesnt match any correct command
    char emsg[] = "Invalid command\n";
    char emsg1[] = "Usage:  create-user <user-name> <pin> <balance>\n";
    char emsg2[] = "Usage:  deposit <user-name> <amt>\n";
    char emsg3[] = "Usage:  balance <user-name>\n";

    
    if (len == 0) {
        printf("%s", emsg);
        return;
    }

    // Local copy of command for processing
    char local[1000];
    strcpy(local, command);

    /*Eliminate newline char*/
    local[strlen(local)-1] = '\0';

    int counter = 0;

    // For storing arguments to commands
    char user[251] = {'\0'};
    char pin[5] = {'\0'};
    char balance[11] = {'\0'};
    char amt[11] = {'\0'};

    int cmd =  0;

    char *str;
    str = strtok(local, " ");
    
    // Sets the cmd (int) and the corresponding argument strings
    while( str != NULL ) {
        // too many arguments
        if(counter > 4){
            printf("%s", emsg);
            return;
        }

        if(counter == 0){
            if(!strcmp(str, "create-user"))
                cmd = 1;
            else if(!strcmp(str, "deposit"))
                cmd = 2;
            else if(!strcmp(str, "balance"))
                cmd = 3;
            else { 
                printf("%s", emsg);
                return;
            }
        }

        // create-user (user-name pin balance)
        if(cmd == 1 && counter > 0 && counter < 4) {
            switch (counter) {
                case 1:
                    if (strlen(str) > sizeof(user)-1){
                        printf("%s", emsg1);
                        return;
                    }
                    strncpy(user, str, (sizeof(user)-1));
                    break;
                case 2:
                    if (strlen(str) > sizeof(pin)-1){
                        printf("%s", emsg1);
                        return;
                    }
                    strncpy(pin, str, (sizeof(pin)-1));
                    break;
                case 3:
                    if (strlen(str) > sizeof(balance)-1){
                        printf("%s", emsg1);
                        return;
                    }
                    strncpy(balance, str, (sizeof(balance)-1)); 
                    break;
                default:
                    printf("%s", emsg);
                    return;
                    break;
            }
        }

        // deposit (user-name amt)
        if(cmd == 2 && counter > 0 && counter < 3) {
            switch (counter) {
                case 1:
                    if (strlen(str) > sizeof(user)-1){
                        printf("%s", emsg2);
                        return;
                    }
                    strncpy(user, str, (sizeof(user)-1));
                    break;
                case 2:
                    if (strlen(str) > sizeof(amt)-1){
                        printf("%s", emsg2);
                        return;
                    }
                    strncpy(amt, str, (sizeof(amt)-1));
                    break;
                default:
                    printf("%s", emsg);
                    return;
                    break;
            }
        }

        // balance (user-name)
        if(cmd == 3 && counter == 1) {
            if (strlen(str) > sizeof(user)-1){
                printf("%s", emsg3);
                return;
            }
            strncpy(user, str, (sizeof(user)-1));     
        } 
        
        counter++;
        str = strtok(NULL, " ");
    }

    // Check parsed input validity using regex and forward to respective 
    // function
    switch (cmd) {
    case 1:
        //printf("Balance length: %ld\n", strlen(balance));
        //printf("Balance: %s\n", balance);
        //printf("%d %d %d\n", regx_user(user), regx_money(balance), regx_pin(pin));
        // Check arguments using regex -> if OK? call create_user otherwise return usage
        if (regx_user(user) && regx_money(balance) && regx_pin(pin)) {
            int ipin = atoi(pin);
            int ibalance = atoi(balance);
            create_user(bank, user, ipin, ibalance);
        } else {
            printf("%s", emsg1);
            return;
        }
        break;
    case 2:
        if (regx_user(user) && regx_money(amt)) {
            int iamt = atoi(amt);
            create_deposit(bank, user, iamt);
        } else {
            printf("%s", emsg2);
            return;
        }    
        break;
    case 3:
    if (regx_user(user)) {
        check_balance(bank, user, 0);
    } else {
        printf("%s", emsg3);
        return;
    }
    break;
    default:
        printf("%s", emsg);
        return;
        break;
    }
    return;
}

// Does this user conform to valid user name?
int regx_user(char *user) {
    regex_t rx;
    // Check if regex was compiled correctly
    if (regcomp(&rx, "^[a-zA-Z][a-zA-Z]*$", 0) != 0)
        return -1;
    int diff = regexec(&rx, user, 0, NULL, 0);
    regfree(&rx);
    return  (!diff) ? 1 : 0;
}

// Does this money conform to valid money?
int regx_money(char *money) {
    regex_t rx;
    // Check if regex was compiled correctly
    if (regcomp(&rx, "^[0-9][0-9]*$", 0) != 0)
        return -1;
    int diff = regexec(&rx, money, 0, NULL, 0);
    regfree(&rx);
    return  (!diff) ? 1 : 0;
}

// Does this pin conform to valid money?
int regx_pin(char *pin) {
    regex_t rx;
    // Check if regex was compiled correctly
    if (regcomp(&rx, "^[0-9][0-9][0-9][0-9]$", 0) != 0)
        return -1;
    int diff = regexec(&rx, pin, 0, NULL, 0);
    regfree(&rx);
    return  (!diff) ? 1 : 0;
}

// Assumes clean inputs to create a deposit in the bank's user
void create_deposit(Bank *bank, char *user, int amt) {
    char *amt_str;
    char *username;
    int old_bal;

    // If no user, 
    if (list_find(bank->users, user)){
        old_bal = atoi(list_find(bank->users, user));

        if ((old_bal + amt) >= INT32_MAX)
            printf("Too rich for this program\n");
        else {
            amt_str = calloc(11,1);
            sprintf(amt_str, "%d", (amt+old_bal));

            list_del(bank->users, user);

            username = calloc(251, 1);
            strncpy(username, user, strlen(user));

            list_add(bank->users, username, amt_str);

            printf("$%d added to %s's account\n", amt, user);
        }

    }
    else
        printf("No such user\n");

    return;
}

// Check the balance of bank's user
void check_balance(Bank *bank, char *user, int remote) {
    char *balance = list_find(bank->users, user);
    char *message;

    /*If atm sent command...*/
    if (remote) {
        message = calloc(16, 1);
        sprintf(message, "4823 %s", balance);

        bank_send(bank, message, 16);
        //printf("check_balance() sent %s\n", message);
        free(message);
    }
    else
    {
        /*If user exists*/
        if (balance)
            printf("$%s\n", balance);
        else
            printf("No such user\n");
    }

    return;
}

/*Withdraw only available from ATM.  It is already assumed that the user exists.*/
void withdraw(Bank *bank, char *user, int amount){
    char *balance = list_find(bank->users, user);
    int bal_num = atoi(balance);
    int new_bal = bal_num - amount;

    /*Dont free these*/
    char *newbalance;
    char *newuser;

    char *authorized = "4823 Authorized";
    char *unauthorized = "4823 Unauthorized";

    if (new_bal < 0)
        bank_send(bank, unauthorized, strlen(unauthorized));
    else {
        newbalance = calloc(11,1);
        newuser = calloc(strlen(user) + 1, 1);
        sprintf(newbalance, "%d", new_bal);
        strncpy(newuser, user, strlen(user));
        list_del(bank->users, user);
        list_add(bank->users, newuser, newbalance);

        newbalance = NULL;
        bank_send(bank, authorized, strlen(authorized));
    }


    return;
}

/*Function returns 1 if user exists, else 0*/
int user_exists(Bank *bank, char* user) {
    //printf("user_exists() got username %s\n", user);
    if (list_find(bank->users, user))
        return 1;

    return 0;
}