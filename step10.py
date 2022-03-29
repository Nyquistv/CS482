import hashlib
import hmac
import itertools
from operator import xor

# we want to see if the password is right 
# input a password() 
# sha256(password) = vo,v1,...vs55
# KDF(v0,v1) = key[16]
# HMAC256(key[16], ciphertext)
# compare if it is equal to d_word_416FB0


def input_password():
    print("input_password\n")

def KDF(v):
    # for i in range(8):
    #     key = bytearray()
    #     key.append(xor(v[1], 0x23))
    #     key.append(xor(v[0], 0x8e))
    #     key.append(xor(key[1], 0x60))
    #     key.append(xor(key[0], 0xe1))
    #     key.append(xor(key[3], 0xd2))
    #     key.append(xor(key[2], 0x96))
    #     key.append(xor(key[5], 0x38))
    #     key.append(xor(key[4], 0xc7))
    #     key.append(xor(key[7], 0xa5))
    #     key.append(xor(key[6], 0xc0))
    #     key.append(xor(key[9], 0x22))
    #     key.append(xor(key[8], 0x74))
    #     key.append(xor(key[11], 0x4f))
    #     key.append(xor(key[10], 0x31))
    #     key.append(xor(key[13], 0x5b))
    #     key.append(xor(key[12], 0xcd))
    # return key

    print("KDF\n")
    key = bytearray()
    key.append(xor(v[1], 0x23))
    key.append(xor(v[0], 0x8e))
    key.append(xor(key[1], 0x60))
    key.append(xor(key[0], 0xe1))
    key.append(xor(key[3], 0xd2))
    key.append(xor(key[2], 0x96))
    key.append(xor(key[5], 0x38))
    key.append(xor(key[4], 0xc7))
    key.append(xor(key[7], 0xa5))
    key.append(xor(key[6], 0xc0))
    key.append(xor(key[9], 0x22))
    key.append(xor(key[8], 0x74))
    key.append(xor(key[11], 0x4f))
    key.append(xor(key[10], 0x31))
    key.append(xor(key[13], 0x5b))
    key.append(xor(key[12], 0xcd))
    return key

def readbinaryfile(filename, length):
    file_byte = bytearray()
    try: 
        with open(filename,"rb") as file:
            for x in range(length):
                byte = file.read(1)
                file_byte += byte
        return file_byte
    except IOError:
     print('Error While Opening the file!')  


def HMAC256(key, ciphertext):
    print("HMAC\n")
    #hmac256 = hmac.new(key,"sha256")
    messagedigest = hmac.digest(key, ciphertext, 'sha256')
    return messagedigest

def verify(messagedigest):
    print("verify\n")
    file_name = "correcthash.bin"
    z = readbinaryfile(file_name, 32)
    #print(z)
    return hmac.compare_digest(messagedigest,z)

def generate_poss_keys():
    print("generating possible keys\n")
    possiblekeys = []
    for one in range(256):
        for two in range(256):
            byte_pair = bytearray()
            byte_pair.append(one)
            byte_pair.append(two)
            possiblekeys.append(byte_pair)
    #nodups = {possiblekeys}
    return possiblekeys

def brute_force(possiblekeys, ciphertext):
    key = bytearray()
    #bool found_match = False
    #m = byte(1)
    found_match = False
    while(not found_match):
        for x in possiblekeys:
            key = KDF(x)
            m = HMAC256(key, ciphertext)
            if(verify(m)):
                print("found the first two bytes of the key\n")
                print(x)
                print(key)
                # dic = [x,key]
                # return dic
                return x
                break
def password():
    def foo(l):
        yield from itertools.product(*([l] * 3))
    passwords = []    
    for x in foo('abcdefghijklmnopqrstuvwxyz'): 
        # you could also use string.ascii_lowercase or ["a","b","c"]
        passwords.append("".join(x))
    return passwords
       # print()

def find_password(poss_key, x):
    found_match = False
    print("\n")
    sha256_ = hashlib.sha256()
    #sha256_.update(poss_key[0])
    #print(sha256_.digest())
    #print(hashlib.sha256("ndnd".encode().__annotations__))
    #hashlib.sha256("password".encode()).digest()
    #hashlib.sha256().hexdigest()
    while(not found_match):
        for password in poss_key:
            # password.encode('')
            sha256_.update(password.encode("ascii"))
            m1 = sha256_.digest()
            if(m1[0] == x[0] & m1[1] == x[1]):
                print("found password\n")
                print(password)
                return password
                break

# #def generate_passwords():
#     alphabet_string = string.ascii_lowercase
#     alphabet_list = list(alphabet_string)
#     password()
#     #li = ['a', 'b', 'c', 'd', 'e', 'f','g']
    #new_li = [a+b+c for a in li for b in li for c in li]
    #return li
    #print(size(key))

def main():
    print("main\n")
    #input_password()
    #sha256()
    #HMAC256(00,)
    #
    
    ciphertext = readbinaryfile("ciphertext.bin", 240)
    print(ciphertext)
    print("\n")
    poss_key = generate_poss_keys()
    x = brute_force(poss_key,ciphertext)
    passwords = password()
    find_password(passwords, x)

    

    #         #m1 = hashlib.sha256(str(password).encode('utf-8'))
    #         #if(m1[0] == x[0] & m1[1] == x[1]):
    #         #    print("found password\n")
    #             print()
    #             break

    # bytes_array = bytearray()
    # bytes_array.append(1)
    # bytes_array.append(1)
    #key = KDF(bytes_array)
    # m = HMAC256(key, ciphertext)
    # print("message \n")
    # print(m)
    # print(verify(m))
    #readciphertext()


if __name__ == "__main__":
    main()




