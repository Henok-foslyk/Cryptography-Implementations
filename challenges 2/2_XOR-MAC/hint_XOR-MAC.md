Hint for the challenge XOR-MAC
==============================

The MAC function used by the bank is weak. We can change bits in the same position in even number of blocks, and the XOR sum of the blocks will remain the same. In other words, if we have a valid transaction with a valid MAC, that MAC value will be valid also for a new transaction that we obtain by making the same changes in even number of blocks (e.g., 2) of the original transaction. The question is if we can make those changes to the original transaction such that we get a higher transaction number, later transaction time, larger sum, and a still correct format.

Here’s again the transaction we have (with position numbers printed above):

    0123456789abcdef0123456789abcdef0123456789abcdef
    2020:02:23|11:23:38|21450|A74635|B29846|00002500

Fortunately, the first digit 0 in the amount and the last digit 0 of the transaction number happen to be in the same position within the 16-byte block (both are in position 8), so we can change them in an identical way. For instance, the new transaction record could be:

    0123456789abcdef0123456789abcdef0123456789abcdef
    2020:02:23|11:23:38|21459|A74635|B29846|90002500
                            ^               ^

Can you do similar a change to the transaction time or date?