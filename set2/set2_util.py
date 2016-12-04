#Utility Functions

def pkcs7(string,size = 16):
    rem = size - len(string)%size
    return string + chr(rem)*rem

def validate_pkcs(string,size = 16):
    if len(string)%size == 0 and len(string)>=size:
        strip = ord(string[len(string)-1])
        if strip<=size:
            validate = string[-strip:]
            for j in validate:
                if ord(j) != strip:
                    return False
            return True
        else:
            return False
    else:
        return False