/* 
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */

#include "atm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char prompt[] = "ATM: ";

int main(int argc, char **argv)
{
    char user_input[1000];

    ATM *atm = atm_create();

    /* Initialize atm init file*/
    char *atmFilename = argv[1];
    int open_init = check_file(atm, atmFilename);

    if(open_init != 0)
        return 64;

    printf("%s", prompt);
    fflush(stdout);

    while (fgets(user_input, 1000,stdin) != NULL)
    {
        user_input[strlen(user_input) - 1] = '\0';
        check_command(atm, user_input);

        // check if someone is logged in
        if(atm->username == NULL){
            printf("%s", prompt);
        }else{
            printf("ATM (%s): ", atm->username);
        }
        fflush(stdout);
    }
	return EXIT_SUCCESS;
}
