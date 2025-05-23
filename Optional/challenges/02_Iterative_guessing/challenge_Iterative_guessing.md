Iterative guessing
==================

A security application uses the PRNG shown below to generate cryptographic parameters:

```
             X_i
              |
        +-----+
        |     |
        |     |
   T_i ----->(+)--->[ MD5 ]---+---> output_i = MD5(X_i + T_i)
        |                     |
        |                     |
        +--->(+)<-------------+
              |
              |
             X_i+1 = X_i + output_i
```

where
- `X_i` is the 16-byte internal state of the PRNG when the i-th output is generated
- `T_i` is a timestamp encoded as a 16-byte ASCII string, obtained from the clock of the computer when the i-th output is generated
- the hash function MD5 is used to generate the output, so the output is 16 bytes long
- the (+) operator denotes XOR (as usual).

The format of input `T_i` is YYYYMMDDhhmmsscc, where YYYY is the year, MM is the month, DD is the day, hh is the hour, mm is the minute, ss is the second, and cc is the centisecond value. For example, 2017.03.06. 21:23:34:78 would be encoded as the string ”2017030621233478”. An implementation `prng.py` of the PRNG is provided in the handout folder.

The security application used this PRNG to generate a 16-byte MAC key and a 16-byte encryption key by two consecuitve invocations of the PRNG. We don’t exactly know when the PRNG was invoked, but we observed the first message that was protected with these keys at 12:10 on March 19, 2022. We also obtained from a backup disk the PRNG’s saved state `prngstate.txt` before the generation of the MAC key.

The observed message is  saved in `message.bin` in the handout folder. The message format is the following:

```
	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	|  Ver  | T |  Len  |      SQN      |       random IV        ...|
	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	|...            random IV           |                           |
	+---+---+---+---+---+---+---+---+---+                           +
	|                                                               |
	+                                                               +
	|                              Payload                          |
	+                                                               +
	|                                                               |
	+       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	|       |x80 x00 x00 x00 x00 x00 x00|                           |
	+---+---+---+---+---+---+---+---+---+            MAC         ...+
	|                                                               |
	+...             MAC                +---+---+---+---+---+---+---+
	|                                   |
	+---+---+---+---+---+---+---+---+---+
```

We obtained the programs `msg-gen.py` and `msg-ver.py` that generate and verify such messages. It is clear from these programs that the payload is first encrypted with AES in CBC mode using the random IV in the message, and then a MAC is computed on the header (Ver, T, Len, SQN), the IV, and the encrypted (and padded) payload. 

Your task is to decode the payload and obtain the flag hidden in it (the flag is in the line that starts with the string ”FLAG”).
