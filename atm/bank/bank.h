/*
 * The Bank takes commands from stdin as well as from the ATM.  
 *
 * Commands from stdin be handled by bank_process_local_command.
 *
 * Remote commands from the ATM should be handled by
 * bank_process_remote_command.
 *
 * The Bank can read both .card files AND .pin files.
 *
 * Feel free to update the struct and the processing as you desire
 * (though you probably won't need/want to change send/recv).
 */

#ifndef __BANK_H__
#define __BANK_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include "util/list.h"

typedef struct _Bank
{
    // Networking state
    int sockfd;
    struct sockaddr_in rtr_addr;
    struct sockaddr_in bank_addr;

    // Protocol state
    // TODO add more, as needed
    FILE *initfile;
    unsigned char cardkey[33];
    unsigned char card_iv[17];

    /*User table*/
    List *users;

    char *bank_id;
    unsigned char *temp_key;
    unsigned char *temp_iv;
} Bank;

Bank* bank_create();
void bank_free(Bank *bank);
ssize_t bank_send(Bank *bank, char *data, size_t data_len);
ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len);
void bank_process_local_command(Bank *bank, char *command, size_t len);
void bank_process_remote_command(Bank *bank, char *command, size_t len);
int check_file(Bank *bank, char *filename);

/* ***************************** Helper Functions *************************** */

// Assumes clean inputs to create a deposit in the bank's user
void create_deposit(Bank *bank, char *user, int amt);

// Check the balance of bank's user
void check_balance(Bank *bank, char *user, int remote);

// Does this user conform to valid user name?
int regx_user(char *user);

// Does this money conform to valid money?
int regx_money(char *money);

// Does this pin conform to valid money?
int regx_pin(char *pin);

int user_exists(Bank *bank, char *user);

int create_user(Bank *bank, char *username, int pin, int balance);

void withdraw(Bank *bank, char *user, int amount);

#endif

