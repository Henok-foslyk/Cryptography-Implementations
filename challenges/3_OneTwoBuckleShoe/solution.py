def find_first_line(file1, file2):
    eof = False
    while (eof == False):
        line1 = file1.read(16)
        line11 = file2.read(16)
        if len(line1) == 16 and len(line11) == 16:
            xor = "".join([chr(b1 ^ b2) for b1, b2 in zip(line1, line11)])
            if xor != '\x00' * 16:
                break
        else:
            eof = True

    return "".join([chr(b1 ^ b2) for b1, b2 in zip(xor.encode('utf-8'), [0x20] * 16)])

def recover_text(file1, file2, first_line):
    res = prev = first_line
    eof = False
    while not eof:
        line = file1.read(16)
        line2 = file2.read(16)
        if len(line) != 16 or len(line2) != 16:
            break
        else:
            xor = "".join([chr(b1 ^ b2 ^ b3) for b1, b2, b3 in zip(line, line2, prev.encode('utf-8'))])
            prev = xor
            res += xor

    print(res)


if __name__ == "__main__":
    v1 = open("LabProfile-v1.crypt", "rb")
    v1_1 = open("LabProfile-v1.1.crypt", "rb")

    result = find_first_line(v1, v1_1)
    recover_text(v1, v1_1, result)