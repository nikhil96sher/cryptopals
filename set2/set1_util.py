#Utility Functions
import base64
import operator
from Crypto.Cipher import AES

def hex2base64(a):
    return base64.b64encode(a.decode('hex'))

def xor_string(a,b):
    c = ""
    for i,j in zip(a.decode('hex'),b.decode('hex')):
        c = c + chr(ord(i)^ord(j))
    return c.encode('hex')

def score_string(s):
    ct = 0.0
    for j in s.decode('hex'):
        if ord(j) in xrange(65,91) or ord(j) in xrange(97,123) or ord(j) == 32:
            ct+=1.0
        elif ord(j) in xrange(48,58):
            ct+=0.75
        elif ord(j) in xrange(33,48) or ord(j) in xrange(58,65) or ord(j) in xrange(123,127):
            ct+=0.5
    return ct/(len(s))

def find_single_key_xor(a):
    key,ansk,maxi = 0,0,0
    ans = a
    while key<256:
        #create a string of length equal to len(c)
        s = str(hex(key)[2:])*len(a)
        d = xor_string(a,s)
        y = score_string(d)
        if(y>maxi):
            ansk,maxi,ans = key,y,d
        key+=1
    return ans.decode('hex'),ansk,maxi

def edit_distance(a,b):
    ct = 0
    for i,j in zip(a,b):
        ct += bin(ord(i)^ord(j)).count("1")
    return ct

def is_ecb_mode(k):
    BLOCKSIZE = 16
    s = [k[i:i+BLOCKSIZE] for i in xrange(0,len(k),BLOCKSIZE)]
    if(len(s) - len(set(s)) != 0):
        return True
    else:
        return False