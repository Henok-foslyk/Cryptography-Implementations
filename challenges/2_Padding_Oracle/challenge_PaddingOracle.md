Padding oracle attack
=====================

A single 16-byte long plaintext block was encrypted with AES using an unknown key and the resulting ciphertext block is (in hex format):

   5f8043943189c3a3c3e6bd0d2237f73f
   
We have access to a Padding Oracle that decrypts anything we send to it in CBC mode using the unknown key and tells us if the padding is correct or not in the resulting decrypted data. The oracle checks for ISO-7816 style padding (i.e. looks for a byte sequence x80 x00 x00 ... at the end of the decrypted data) and only the min length padding needed is supported (i.e., the largest padding length can be 16 bytes). The oracle interprets the first block (first 16 bytes) of its input as the IV.

Your task is to implement a padding oracle attack by completing the skeleton PO_attack_skeleton.py provided as an attachement to this challenge.

Note that the oracle is implemented in a separate script called oracle.py, and the attack skeleton begins by importing the oracle function:

```python
	from oracle import oracle
```

The oracle function takes a single input of type bytes (byte string) which is interpreted as the ciphertext submitted to the oracle for CBC decoding, and it returns a boolean value signaling the correctness of the padding in the decoded data (where True means PADDING_ERROR and False means PADDING_OK).

If you have any byte string B (the length of which is a multiple of 16 bytes, as the AES block size is 16 bytes), then you can call the oracle as oracle(B) and check for the return value:

```python
	if oracle(B) == PADDING_ERROR:
		...
	else:
		...
```
Of course, you can construct the input from smaller segments, for instance:

```python
	iv = b'\x00'*16
	ct = b'\xff'*16

	if oracle(iv+ct) == PADDING_OK:
		...
```

This should be sufficient to know about the operation of the Oracle. In particular, you do not need to look into oracle.py at all, and you SHOULD NOT!

The attack skeleton provided is actually an almost complete attack script. It has to be fixed by replacing the __TODO_x__ placeholders (for x = 1, 2, 3, 4, 5) with the appropriate code segments. For this, of course, you need to understand what the script is trying to do, which is supported by a lot of comments.

For instance, you have to initialize variable R towards the beginning of the script by replacing

```python
	R = __TODO_1__
```

with an appropriate line of code, such as

```python
	R = b'\x00'*16
```

Have fun!

