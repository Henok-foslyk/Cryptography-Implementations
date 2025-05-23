from Crypto.Hash import MD5

def trhash(x):
    h = MD5.new()
    h.update(x)
    return h.digest()[0:4]

def produce_hashmaps():
    A = ["Mr.", "Mister"]
    B = ["I'm", "I am"]
    C = ["1,000,000 USD", "1 million USD"]
    D = ["1", "one"]
    E = ["1,234", "one thousand two hundred thirty four"]
    F = ["USD", "US dollars"]
    G = ["345", "three hundred forty five"]
    S = [" ", "  ",]

    thsh = dict()
    for a in A:
        for b in B:
            for c in C:
                for d in D:
                    for s1 in S:
                        for s2 in S:
                            for s3 in S:
                                for s4 in S:
                                    for s5 in S:
                                        for s6 in S:
                                            for s7 in S:
                                                for s8 in S:
                                                    for s9 in S:
                                                        for s10 in S:
                                                            for s11 in S:
                                                                for s12 in S:
                                                                    trial = f"Dear {a} Jones, {b} delighted{s1}to{s2}inform{s3}you{s4}that{s5}you{s6}have{s7}been{s8}selected{s9}as{s10}one{s11}of the{s12}winners of our competition. Your prize will be {c}, which we will transfer to your bank account within {d} week. Best regards, Andrew B. Clark"
                                                                    thsh[trhash(trial.encode("ascii"))] = trial
    shsh = dict()
    for s1 in S:
        for s2 in S:
            for s3 in S:
                for s4 in S:
                    for s5 in S:
                        for s6 in S:
                            for s7 in S:
                                for s8 in S:
                                    for s9 in S:
                                        for s10 in S:
                                            for s11 in S:
                                                for s12 in S:
                                                    for e in E:
                                                        for e2 in E:
                                                            for a in A:
                                                                for f in F:
                                                                    for g in G:
                                                                        strial = f"Dear {a} Jones, I{s1}regret{s2}to{s3}inform{s4}you{s5}that{s6}your{s7}complaint{s8}was{s9}not{s10}approved{s11}by{s12}our management. This, unfortunately means that you cannot reclaim your cost of {e} {f} and in addition you have to cover our investigation cost of {g} {f} as well. Yours sincerely, Andrew B. Clark"
                                                                        shsh[trhash(strial.encode("ascii"))] = strial
    

    return thsh, shsh


if __name__ == "__main__":
    t_hashes, s_hashes = produce_hashmaps()

    for hash in t_hashes:
        if hash in s_hashes:
            t = t_hashes[hash]
            s = s_hashes[hash]

            print(t)
            print(trhash(t.encode("ascii")))
            print(s)
            print(trhash(s.encode("ascii")))

            break


