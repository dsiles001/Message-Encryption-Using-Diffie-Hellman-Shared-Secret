# Message-Encryption-Using-Diffie-Hellman-Shared-Secret

This script replicates the process of the Diffie Hellman key exchange except this time, we are using the shared secret generated by Alice and Bob's public and private keys to encrypt and decrypt a message. This code especially shows it's functionality when used by two people on two seperate devices, where one person wants to encrypt a message and send it (Alice) while the other user is the recipient of the encrypted message and wants to decrypt it (Bob). 

# Input - !!! Regardless of what action you are peforming, both Alice and Bob will be requesting information from each other in order to achieve     the same shared secret/key at the end:
1. Enter what you will be wanting to do on your side of the exchange, encrypting(1) or decrypting(2)
2. Your private and public keys will be made for you. You will have to follow instructions and the prompt shown when it comes to entering the keys and values of the other user.
3. Once the values and keys are exchanged between the two, they will both create the shared secret/key using each other's public keys and their own private keys.
4. Once the shared key has been generated, you will then be prompted to enter the path to the .txt file that has the text that you would like to encrypt/decrypt, depending on whatever you chose to do at the beginning.
5. If you chose to encrypt a text, the encrypted version of that text will be found in "encrypted.txt" in the same directory the python scrypt was ran. If you chose to decrypt a text, the decrypted version will be found in "decrypted.txt" in the same directory the python scrypt was ran.
