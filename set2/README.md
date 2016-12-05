

```python
import set1_util as set1
import set2_util as set2
import base64
import os
import random
from Crypto.Cipher import AES

KEYSIZE = 16
```

```python
#Challenge 9 - Implement PKCS#7 Padding Scheme

inp = "YELLOW SUBMARINE"
out = "YELLOW SUBMARINE\x04\x04\x04\x04"
print "Testing PKCS#7 Padding : ",set2.pkcs7(inp,20) == out
```

```python
#Challenge 10 - Implement CBC Mode using ECB Mode and IV

key = "YELLOW SUBMARINE"
aes = AES.new(key,AES.MODE_ECB)
a = open('10.txt').read().split('\n')
a = ''.join(a)
c = base64.b64decode(a)

BLOCKSIZE = 16
cipher = [c[i:i+BLOCKSIZE] for i in xrange(0,len(c),BLOCKSIZE)]
iv = '\x00'*BLOCKSIZE

prev = iv
s = ""
for i in xrange(0,len(cipher)):
    plain = set1.xor_string(aes.decrypt(cipher[i]).encode('hex'),prev.encode('hex'))
    prev = cipher[i]
    s = s + plain.decode('hex')
print s
```

```python
#Challenge 11 - Detect ECB or CBC Mode

def random_pad(string):
    append = random.randint(5,10)
    pad = os.urandom(append)
    return set2.pkcs7(pad+string+pad,16)

def black_box(data):
    key = os.urandom(KEYSIZE)
    mode = random.randint(0,2)
    if mode == 1:
        aes = AES.new(key,AES.MODE_ECB)
        print "Actual ECB Mode"
        return aes.encrypt(random_pad(data))
    else:
        iv = os.urandom(KEYSIZE)
        aes = AES.new(key,AES.MODE_CBC,iv)
        print "Actual CBC Mode"
        return aes.encrypt(random_pad(data))

if set1.is_ecb_mode(black_box("A"*48)) == True:
    print "Detected ECB Mode"
else:
    print "Detected CBC Mode"
```

```python
#Challenge 12 - Byte At A Time ECB

key = os.urandom(KEYSIZE)

a = open('12.txt').read().split('\n')
a = ''.join(a)
fixed = base64.b64decode(a)

def fixed_key_black_box(data):
    aes = AES.new(key,AES.MODE_ECB)
    return aes.encrypt(set2.pkcs7(data+fixed,KEYSIZE))

def find_keysize():
    MAX = 32
    prev = fixed_key_black_box('a')
    for i in xrange(2,MAX):
        curr = fixed_key_black_box('a'*i)
        if(curr[:i-1] == prev[:i-1]):
            return i-1
        prev = curr
    return -1 #Error in black box

def brute_force():
    #Whilte bruteforcing, remove one 'a' try to add extra character. While giving input, give one less a in input
    BLOCKS = 15 #No of blocks I can decrypt
    build = 'a'*(KEYSIZE*BLOCKS-1) #Initial Input
    tbuild = build
    block = BLOCKS
    res = ""
    for i in xrange(0,KEYSIZE*BLOCKS):
        try:
            if(i>=KEYSIZE):
                i-=KEYSIZE
            cipher = {}
            for j in xrange(0,256):
                possible = tbuild+chr(j)
                cipher[fixed_key_black_box(possible)[(block-1)*KEYSIZE:(block)*KEYSIZE]] = j
            target = fixed_key_black_box(build)
            build = build[1:]
            tbuild = tbuild[1:] + chr(cipher[target[(block-1)*KEYSIZE:(block)*KEYSIZE]])
            res = res + chr(cipher[target[(block-1)*KEYSIZE:(block)*KEYSIZE]])
        except:
            return res
    return res
print brute_force()
```

```python
#Challenge 13 - ECB Cut and Paste
key = os.urandom(KEYSIZE)

def encode(email):
    return set2.pkcs7('email=%s&uid=10&role=user'%email,16)

def profile_for(email):
    if email.find("&")!=-1 or email.find("=")!=-1:
        print "Hacking Attempt Detected"
    else:
        aes = AES.new(key,AES.MODE_ECB)
        return aes.encrypt(encode(email))
    
def decrypt_profile(data):
    aes = AES.new(key,AES.MODE_ECB)
    print aes.decrypt(data)
```

```python
#Challenge 13 - ECB Cut and Paste
# Nicely Presented by f0xtr0t
# 0123456789abcdef0123456789abcdef0123456789abcdef <--- Just counter of things, not really part of attack
# email=XXXXXXXXXXXXX&uid=10&role=user <--------------------- (1) made from oracle
# email=XXXXXXXXXXadmin...........&uid=10&role=user <-------- (2) made from oracle
# email=XXXXXXXXXXXXX&uid=10&role=admin........... <--------- (attack) used in the attack
payload = (16-len('email='))*'a'+set2.pkcs7('admin')
email_len = 32 - len('email=&uid=10&role=')
email = 'nikhilsh@sher' #len = 13
decrypt_profile(profile_for(email)[:2*KEYSIZE]+profile_for(payload)[KEYSIZE:2*KEYSIZE])
```

```python
#Challenge 14 - Black Box
RANDOM_LENGTH = 20
RANDOM = os.urandom(RANDOM_LENGTH)
FIXED = 'flag{Y0u_4r3_4w3s0m3}'
def random_prefix_fixed_key(data):
    aes = AES.new(key,AES.MODE_ECB)
    return aes.encrypt(set2.pkcs7(RANDOM+data+FIXED,KEYSIZE))
```

```python
#Challenge 14 - Logic To Break

def findcommon(prev,curr):
    s1 = [prev[i:i+KEYSIZE] for i in range(0,len(prev),KEYSIZE)]
    s2 = [curr[i:i+KEYSIZE] for i in range(0,len(curr),KEYSIZE)]
    for i in xrange(0,len(s1)):
        if s1[i] != s2[i]:
            return i
    return len(s1)

def get_random_length():
    payload = 'a'
    prev = random_prefix_fixed_key('')
    curr = random_prefix_fixed_key(payload)
    #common b/w these two gives me no of blocks initial thus the multiple of 16 in length of random
    base = findcommon(prev,curr)
    while True:
        prev = curr
        payload = payload + 'a'
        curr = random_prefix_fixed_key(payload)
        common = findcommon(prev,curr)
        if common > base:
            return (base,16 - len(payload)+1)
        if len(payload)>17:
            return (base,-1)

def break_rpf():
    START_BLOCK,LEN = get_random_length()
    BLOCKS = 15 #No of blocks I can decrypt
    build = 'a'*(KEYSIZE*BLOCKS-1 - LEN) #Initial Input
    tbuild = build
    block = BLOCKS+START_BLOCK
    res = ""
    for i in xrange(0,KEYSIZE*BLOCKS):
        try:
            if(i>=KEYSIZE):
                i-=KEYSIZE
            cipher = {}
            for j in xrange(0,256):
                possible = tbuild+chr(j)
                cipher[random_prefix_fixed_key(possible)[(block-1)*KEYSIZE:(block)*KEYSIZE]] = j
            target = random_prefix_fixed_key(build)
            build = build[1:]
            tbuild = tbuild[1:] + chr(cipher[target[(block-1)*KEYSIZE:(block)*KEYSIZE]])
            res = res + chr(cipher[target[(block-1)*KEYSIZE:(block)*KEYSIZE]])
        except:
            return res
    return res
    
print break_rpf()
```

```python
#Challenge 15 - PKCS#7 Padding Validation

print set2.validate_pkcs("ICE ICE BABY\x04\x04\x04\x04",16)
print set2.validate_pkcs("ICE ICE BABY\x05\x05\x05\x05",16)
print set2.validate_pkcs("ICE ICE BABY\x01\x02\x03\x04",16)
```

```python
#Challenge 16 - CBC BitFlipping Attack

PREFIX = "comment1=cooking%20MCs;userdata="
SUFFIX = ";comment2=%20like%20a%20pound%20of%20bacon"
KEY = os.urandom(KEYSIZE)
IV = os.urandom(KEYSIZE)

def cbc_encrypt(DATA):
    if DATA.find("=")!=-1 or DATA.find(";")!=-1:
        print "You want flag? You ain't getting that"
        DATA.replace("=","")
        DATA.replace(";","")
    cbc = AES.new(KEY,AES.MODE_CBC,IV)
    return cbc.encrypt(set2.pkcs7(PREFIX+DATA+SUFFIX,KEYSIZE))

def check_hacked(DATA):
    cbc = AES.new(KEY,AES.MODE_CBC,IV)
    if cbc.decrypt(DATA).find(";admin=true;")!=-1:
        print "You did it. Here is your flag : flag{cbc_n0t_50_53cu73_4nym0r3}"
        return True
    else:
        print "Try Harder"
        return False
```

```python
#Challenge 16 - Payload Generation
#Logic : Pn = decrypt(C(n))^C(n-1)
# P'(n) = decrypt(C(n))^C'(n-1)
# C'(n-1) = C(n-1)^P'(n)^P(n)

given =  "nikh1admin1true1"
target = "nikh;admin=true;"
base = cbc_encrypt(given)
blocks = [base[i:i+KEYSIZE] for i in xrange(0,len(base),KEYSIZE)]
temp = blocks[1]
s = ""
for i in xrange(0,16):
    s = s + chr(ord(temp[i])^ord(given[i])^ord(target[i]))
blocks[1] = s
check_hacked(''.join(blocks))
```
