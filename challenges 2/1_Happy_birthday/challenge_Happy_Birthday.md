Happy Birthday
==============

We have two messages with somewhat contradictory content:

"Dear Mr. Jones, I'm delighted to inform you that you have been selected as one of the winners of our competition. Your prize will be 1,000,000 USD, which we will transfer to your bank account within one week. Best regards, Andrew B. Clark"

"Dear Mr. Jones, I regret to inform you that your complaint was not approved by our management. This, unfortunately means that you cannot reclaim your cost of 1,234 USD and in addition you have to cover our investigation cost of 345 USD as well. Yours sincerely, Andrew B. Clark"

Your task is to produce a variant of the first message and a variant of the second message such that the two variants have the same hash value, where the hash function is defined in Python as

	from Crypto.Hash import MD5
	def trhash(x):
		h = MD5.new()
		h.update(x)
		return h.digest()[0:4]

So, assuming your variant of the first message is stored in string variable t and your variant of the second message is stored in string variable s, we want the following to be True:

	trhash(t.encode('ascii')) == trhash(s.encode('ascii'))

A variant should have the same semantic meaning as the original message, but syntactically it may differ from the original. For example, "I'm delighted" and "I am delighted" are semantically equivalent, but they are syntactically different strings. Similarly, "1,000,000 USD" and "1 million USD" are semantically the same, but syntactically different.


