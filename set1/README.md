```python
import set1_util as set1
import base64
import operator
from Crypto.Cipher import AES
```

```python
#Challenge 1 - hex to base64
inp = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
out = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
print "Testing Hex to Base64 : ",set1.hex2base64(inp) == out
```

```python
#Challenge 2 - xor of two strings
inp1 = "1c0111001f010100061a024b53535009181c"
inp2 = "686974207468652062756c6c277320657965"
out = "746865206b696420646f6e277420706c6179"
print "Testing String XOR : ",set1.xor_string(inp1,inp2) == out
```

```python
#Challenge 3 - Finding Key based on Score
inp = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
print set1.find_single_key_xor(inp)
```

```python
#Challenge 4 - Finding Various Strings from Text which may have been single key xored based on score
f = open('4.txt')
s = f.read()
s = s.split('\n')
maxi,maxk = 0,0
for a in s:
    string,key,sc = set1.find_single_key_xor(a)
    if(sc>maxi):
        maxi,maxk,maxs = sc,key,string
print maxs
```

```python
#Challenge 5 - Repeat a Key and XOR with given string

def repeated_key_xor(key,p):
    s = key*((len(p)/len(key)) + 1)
    s = s[:len(p)]
    return set1.xor_string(s.encode('hex'),p.encode('hex'))

inp ='''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''
key = "ICE"
out = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
print "Testing Repeated Key : ",repeated_key_xor(key,inp) == out
```

```python
#Challenge 6 - Breaking Repeating Key XOR
def getKey(a):
    keys = {}
    mini = len(a)*8
    for keysize in xrange(1,40):
        s = [a[i:i+keysize] for i in range(0,len(a),keysize)]
        score,ct = 0,0
        for i in range(0,len(s)-1):
            ct+=1
            score+=set1.edit_distance(s[i],s[i+1])
        keys[keysize] = (score*1.0)/(ct*keysize)
        keysize+=1
    return sorted(keys.items(),key = operator.itemgetter(1))[:1][0]

def breakVigenere(a):
    keys = getKey(a)
    key = keys[0]

    #Divide string into blocks of size key
    s = [a[i:i+key] for i in range(0,len(a),key)]

    #Take ith character of each block and create a string
    ch = {}
    for i in range(0,key):
        ch[i] = ""
    for k in s:
        for i in range(0,len(k)):
            ch[i] = ch[i] + k[i]

    #Decrypt each ch[i]
    keystr = ""
    score = 0.0
    for i in xrange(0,key):
        string,key,sc = set1.find_single_key_xor(ch[i].encode('hex'))
        score += sc
        keystr = keystr + chr(key)
    score = score*key
    return score,keystr

inp1 = "this is a test"
inp2 = "wokka wokka!!!"
print "Testing Edit Distance : ",set1.edit_distance(inp1,inp2) == 37

a = open('6.txt').read().split('\n')
a = base64.b64decode(''.join(a))
print breakVigenere(a)
```

```python
#Challenge 7 - AES in ECB Mode

a = open('7.txt').read().split('\n')
cipher = base64.b64decode(''.join(a))
key = "YELLOW SUBMARINE"
aes = AES.new(key,AES.MODE_ECB)
print aes.decrypt(cipher)
```

```python
#Challenge 8 - Detect AES in ECB Mode

a = open('8.txt').read().split('\n')
#Check if two identical blocks?
for j in a:
    k = j.decode('hex')
    if set1.is_ecb_mode(k):
        print j
```