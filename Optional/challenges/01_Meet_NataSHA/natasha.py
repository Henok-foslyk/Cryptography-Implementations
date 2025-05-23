from Crypto.Hash import SHA
from Crypto.Util.strxor import strxor 

class TypeError(Exception):
    def __init__(self, message):
        self.message = message

class LengthError(Exception):
    def __init__(self, message):
        self.message = message

def RF(L, R, K):
    sha = SHA.new()
    sha.update(K+R+K)
    return strxor(L, sha.digest()), R

def ENC(X, K):

    if type(K) != bytes:
        raise TypeError("Key must be of type bytes!")
        return
    
    if len(K) != 6:
        raise LengthError("Key length must be of length 6 bytes!")
        return
    
    if type(X) != bytes:
        raise TypeError("Input block must be of type bytes!")
        return
    
    if len(X) != 40:
        raise LengthError("Block length must be of length 40 bytes!")
        return    
    
    K0 = K[0:1]
    K1 = K[1:2]
    K2 = K[2:3]
    K3 = K[3:4]
    K4 = K[4:5]
    K5 = K[5:6]

    L, R = X[0:20], X[20:40]
    R, L = RF(L, R, K0)
    R, L = RF(L, R, K1)
    R, L = RF(L, R, K2)
    R, L = RF(L, R, K3)
    R, L = RF(L, R, K4)
    L, R = RF(L, R, K5)
    Y = L + R
    
    return Y 

def DEC(Y, K):

    if type(K) != bytes:
        raise TypeError("Key must be of type bytes!")
        return
    
    if len(K) != 6:
        raise LengthError("Key length must be of length 6 bytes!")
        return
    
    if type(Y) != bytes:
        raise TypeError("Input block must be of type bytes!")
        return
    
    if len(Y) != 40:
        raise LengthError("Block length must be of length 40 bytes!")
        return    
    
    K0 = K[0:1]
    K1 = K[1:2]
    K2 = K[2:3]
    K3 = K[3:4]
    K4 = K[4:5]
    K5 = K[5:6]

    L, R = Y[0:20], Y[20:40]
    R, L = RF(L, R, K5)
    R, L = RF(L, R, K4)
    R, L = RF(L, R, K3)
    R, L = RF(L, R, K2)
    R, L = RF(L, R, K1)
    L, R = RF(L, R, K0)
    X = L + R
    
    return X 
