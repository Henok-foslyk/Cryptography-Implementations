Hint for the challenge "Happy Birthday"
=======================================

Notice that the hash function trhash() produces 4-byte (32-bit) outputs. This is rather small as hash length, and we may be able to mount a birthday attack of complexity sqrt(2^32) = 2^16, which looks quite feasible in practice.

We use the following variant of the Birthday Paradox: Let's assume we have a set S of size N. We randomly choose a subset S1 of size N1 from S and record the chosen elements. Then we put back the chosen elements in S, and we choose again randomly a subset S2 of size N2 from S. It is known that the probability that S1 and S2 have at least one common element (i.e., they have a non-empty intersection) is larger than 1/2 when N1 and N2 are both around sqrt(N).

The idea is then to produce 2^16 variants of the given first message, and compute and store the trhash values of those variants (this will be the first subset of all possible trhash values). Then we produce 2^16 variants of the given second message, compute the trhash values of those variants (this will be the second subset), and check if any of these hash values occurs in the stored hashes of the first message variants. If a match is found (which should happen with probabilty larger than 1/2), then we found two variants that have the same trhash value.

The question is, how to produce 2^16 semantically equivalent variants of the given messages. For that, we can find 16 places within a given message where we can use one of two possible options with equivalent meaning, like "I'm delighted" and "I am delighted" or "to inform you" or "to inform  you" (notice the two spaces between "inform" and "you" in the latter variant), and produce all possible 2^16 variants by choosing either one or the other option in each of the 16 places. 

It may happen that generating 2^16 variants is not sufficient, and you don't succeed, as the probability of success is not 1, but it is just larger than 1/2. So you may try with 2^17 or 2^18 variants (i.e., having 17 or 18 places in the texts where you may choose from two options). This will only be slightly more effort, and certainly still feasible.
 
