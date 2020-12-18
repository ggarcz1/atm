/*
 * The ATM interfaces with the user.  User commands should be
 * handled by atm_process_command.
 *
 * The ATM can read .card files, but not .pin files.
 *
 * Feel free to update the struct and the processing as you desire
 * (though you probably won't need/want to change send/recv).
 */

#ifndef __ATM_H__
#define __ATM_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>

typedef struct _ATM
{
    // Networking state
    int sockfd;
    struct sockaddr_in rtr_addr;
    struct sockaddr_in atm_addr;

    // Protocol state
    // TODO add more, as needed
    char *username;
    int pin;
    int attempts;
    int max_attempts;
    int lockoutMinutes;
    char *atm_id;

    FILE *initfile;

    unsigned char cardkey[33];
    unsigned char card_iv[17];

    unsigned char *temp_key;
    unsigned char *temp_iv;

} ATM;

ATM* atm_create();
void atm_free(ATM *atm);
ssize_t atm_send(ATM *atm, char *data, size_t data_len);
ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len);
void atm_process_command(ATM *atm, char *command);

void attempts(ATM *atm);

int begin_session(ATM *atm, char *username);

int withdraw(ATM *atm, int amount);

int balance(ATM *atm);

int end_session(ATM *atm);

int check_file(ATM *atm, char *filename);

int check_command(ATM *atm, char *command);

unsigned char *msg_from_bank(ATM *atm);

#endif
