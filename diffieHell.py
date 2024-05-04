import random as r
import sympy
import base64


def makePrime():
    while True:
        num = r.randint(10, 1000)
        if sympy.isprime(num):
            return num

def AlicePublicKeys():
    # make prime numbers 
    p = makePrime()

    # find primitive roots
    g = sympy.primitive_root(p)

    a = r.randint(1, p-1) #Alice private key

    A = pow(g, a, p) # Alice public key

    return A, p, g, a

def BobPublicKeys(p, g):

    b = r.randint(1, p-1) # Bob's private key
    B = pow(g, b, p) # Bob's public key
    return B, b


def AliceSecret(B, a, p):
    return pow(B, a, p)

def BobSecret(A, b, p):
    return pow(A, b, p)

def encrypt(message, key):
    messagebinaries = []
    encrypted = []
    for i in range(len(message)):
        temp = ''
        binaryChar = format(ord(message[i]),'08b')
        messagebinaries.append(binaryChar)
        for j in range(len(binaryChar)):
            if binaryChar[j] == '1' and key[j] == '1':
                temp+='0'
            elif binaryChar[j] == '1' or key[j] == '1':
                temp+='1'
            else:
                temp+='0'
        encrypted.append(temp)
    
    encryptedMessage = binToAscii(encrypted)
    encryptedMessageBase64 = base64.b64encode(encryptedMessage.encode()).decode()
    return encryptedMessageBase64

def decrypt(encrypted, key):

    decryptBinary = []

    for binary in encrypted:
        temp = ''
        # messagebinaries.append(binaryChar)
        for j in range(len(binary)):
            if binary[j] == '1' and key[j] == '1':
                temp+='0'
            elif binary[j] == '1' or key[j] == '1':
                temp+='1'
            else:
                temp+='0'


        decryptBinary.append(temp)

    return decryptBinary

def binToAscii(encrypted):
    finalText = ''
    for binary in encrypted:
        char = int(binary,2)

        finalText += chr(char)

    return finalText

def textToBin(message):
    messagebinaries = []
    for i in range(len(message)):
        binaryChar = format(ord(message[i]),'08b')
        messagebinaries.append(binaryChar)

    return messagebinaries


def openFile(fileDir):
    message = ''
    with open(fileDir, 'r') as file:
        for line in file:
            message += line.strip()

    return message


if __name__=='__main__':


    choice = int(input("[+] Would you like to encrypt(1) or decrypt(2): "))


    if choice == 1:
        Apublic, p, g, a = AlicePublicKeys()
        print(f"[-] Your public key has been created. Give this to Bob: {Apublic}")
        print(f"p = {p}")
        print(f"g = {g}")
        Bpublic = int(input("[+] What is Bob's public key: "))
        SharedSecret = AliceSecret(Bpublic, a, p)
        SharedSecret = format(SharedSecret, '08b') # turn their shared secret key into binary to perform XOR operation

        messageDir = input("[+] Enter directory with text to encrypt: ")
        message = openFile(messageDir)  
        encryptedMessage = encrypt(message, SharedSecret)
        # encryptedMessage = binToAscii(encryptBin)
        with open('encrypted.txt', 'w+') as f:
            f.write(encryptedMessage)


    elif choice == 2:
        Apublic = int(input("[+] What is Alice's public key: "))
        p = int(input("[+] Enter Alice's p value: "))
        g = int(input("[+] Enter Alice's g balue: "))
        Bpublic, b = BobPublicKeys(p, g)
        print(f"[-] Your public key has been created. Give this to Alice: {Bpublic}")
        SharedSecret = BobSecret(Apublic,b,p)
        SharedSecret = format(SharedSecret, '08b')

        messageDir = input("[+] Enter directory with text to decrypt: ")
        message = openFile(messageDir)
        message = base64.b64decode(message).decode()

        binaries = textToBin(message)
        decryptBin = decrypt(binaries, SharedSecret)
        decryptedMessage = binToAscii(decryptBin)
        with open('decrypted.txt', 'w+') as f:
            f.write(decryptedMessage)

    else:
        print("[-] Not an option")



    


