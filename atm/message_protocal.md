# The message protocol

The messages that the atm sends to the bank will take the form:

`8174<whitespace><operation char><whitespace><username><whitespace><amount(if needed)>`

Note: 8174 is the atm id.  This lets the bank know that the packet came from the atm.  It would be infeasible for an attacker to guess this id.

Here are the instances in which the atm will send a message to the bank, along with what the bank`s response should look like:

## Begin Session

Atm will send: 

`8174 s <username>`

Example:

`8174 s alice`

The bank will respond with:

`4823 Authorized`

Note: 4823 is the bank id.  This lets the atm know that the packet came from the bank.  It would be infeasible for an attacker to guess this id.

if alice exists in the user table, or

`4823 Unauthorized`

if there is no such user.


## Withdraw

Atm will send:

`8174 w <username> <amount>`

Example:

`8174 w bob 240`

Bank will respond with:

`4823 Authorized`

if bob has sufficient funds, or

`4823 Unauthorized`

if bob has insufficient funds.

## Balance

Atm will send:

`8174 b <username>`

Example:

`8174 b alice`

Bank will respond with:

`4823 <userbalance>`

Example:

`4823 200`


