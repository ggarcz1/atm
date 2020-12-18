# The Init protocol

## Format of `.atm` and `.bank` files

The init program creates the .bank and .atm files. 

These files are identical and contain 50,000 lines of text.

Each line of text is made up of a key-iv pair in the form: `<key> <iv>\n`

The key is 32 bytes long while the iv is 16 bytes long. For example:
`03725037581982818719952053443852 2616581354903609`

## How its created files are used

These key-iv pairs are used in AES256 encryption and decryption similar to what was done in the cryptography project for this class. 

The `.bank` and `.atm` files will work as symmetric key books for encrypting messages between the bank and the atm as well as encrypting the `.card` files.