# Format of `.card` files

Each card will contain a single line of cyphertext.
The plaintext of this cyphertext will be the username of the user and the pin of the user in the form:
`<username> <pin>`

# Use and security purposes of `.card` files

The `.card` files allow both the `atm` and `bank` programs to access the pin of each user.
These files are encyrpted using AES256. All `.card` files are encrypted and decrypted using the
same key so that the order of the creation of `.card` files does not affect the atm's ability to decrypt them.
Although the only peice of information that we need to store on the cards is the pin number the name is added to increase security.
There are no rules stopping users from all having the same pin but users may not have the same name. 
This means that if only pins were in the card files then malicious users could find their pins even though they are encrypted.
The inclusion of the name allows for a unique ciphertext for each `.card` file as well as acting as verification to prevent 
successful tampering or creation of false `.card` files.

# Programing level stuff
Note: I don't think this section needs to in the final product but may be helpful for development

The bank creates cards in the `create_user()` function in `bank.c`. Currently cards are stored in bin but that will be changed so they are
stored in the current directory relatively soon. 

The atm reads the cards in the `begin_session()` function in `atm.c`. Currently cards are read from bin but that will be changed so they are read from the current directory relatively soon. In the `begin_session()` function the atm will read in the user-name and pin
from the card, stored in `card_user` and `pin` respectively.