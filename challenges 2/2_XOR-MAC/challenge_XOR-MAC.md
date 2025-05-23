XOR-MAC
=======

A bank uses the following format to log transactions:

| Bytes  | Fields                                        |
|--------|-----------------------------------------------|
| 0..9   | Date in format YYYY:MM:DD                     |
| 10     | Separator ’|’                                 |
| 11..18 | Time in format HH:MM:SS                       |
| 19     | Separator ’|’                                 |
| 20..24 | Transaction ID (monotonically increasing)     |
| 25     | Separator ’|’                                 |
| 26..31 | Source account ID                             |
| 32     | Separator ’|’                                 |
| 33..38 | Destination account ID                        |
| 39     | Separator ’|’                                 |
| 40..47 | Amount                                        |

An example transaction record is the following:

	2020:02:23|11:23:38|21450|A74635|B29846|00002500

The integrity of the transaction records is protected with a MAC which is computed as follows: The bank splits the transaction record into blocks of size 128 bit, it XORs all such blocks together, and it encrypts the resulting 128-bit block with AES (in ECB mode) using a secret key known only to the bank.

You have an account in the bank, and your account ID is B29846. You obtained the latest transaction record (`t.txt`) and its corresponding MAC (`t-mac.bin`), where someone from account ID A74635 transferred 2500 USD to your account:

	2020:02:23|11:23:38|21450|A74635|B29846|00002500

Can you exploit this to obtain more money from account A74635? For this, you need to generate a new transaction record with a valid MAC. In the new transaction record, both the transaction time and the transaction number should be larger than they are in the latest transaction record (given above). Preferably, you could also try to increase the amount. Finally, the given MAC (`t-mac.bin`) should verifiy correctly for your fake transaction record.
