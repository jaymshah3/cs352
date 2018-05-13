#!/usr/bin/python

# this is example code that shows how to use the Python nacl (salt) library for
# public/private key encryption 
# The example code is modified from:

#https://pynacl.readthedocs.io/en/latest/public/#example

import nacl.utils
import nacl.secret
import nacl.utils

from nacl.public import PrivateKey, Box

# Generate Bob's private key, which must be kept secret
skbob = PrivateKey.generate()

# Bob's public key can be given to anyone wishing to send
#   Bob an encrypted message
pkbob = skbob.public_key

# Alice does the same and then Alice and Bob must exchange public keys
skalice = PrivateKey.generate()
pkalice = skalice.public_key

# Bob wishes to send Alice an encrypted message so Bob must make a Box with
# his private key and Alice's public key
bob_box = Box(skbob, pkalice)

# Alice creates a second box with her private key to decrypt the message
alice_box = Box(skalice, pkbob)

# This is our message to send, it must be a bytestring as Box will treat it
# as just a binary blob of data.

# this is the plaintext message from Bob to Alice
messageB2A = b"This is a binary message from Bob to Alice"

# this is plaintext method from Alice to Bob 
messageA2B = b"This is a binary message from Alice to Bob"

# Encrypt our message, it will be exactly 40 bytes longer than the
# original message as it stores authentication information and the
# nonce alongside it.

# This is a nonce, it *MUST* only be used once, but it is not considered
#  secret and can be transmitted or stored alongside the ciphertext. A
#  good source of nonces are just sequences of 24 random bytes.

nonceB2A = nacl.utils.random(Box.NONCE_SIZE)
nonceA2B = nacl.utils.random(Box.NONCE_SIZE)
encryptedB2A = bob_box.encrypt(messageB2A, nonceB2A)
encryptedA2B = alice_box.encrypt(messageA2B,nonceA2B)

# Decrypt our message, an exception will be raised if the encryption was
# tampered with or there was otherwise an error.
plaintextB2A = alice_box.decrypt(encryptedB2A)
plaintextA2B = bob_box.decrypt(encryptedA2B)

print ("the plaintext Bob sent is: %s" %(plaintextB2A))
print ("the plaintext Alice sent is: %s" %(plaintextA2B))

# the following code illustrates that decryption should fail when we modify the message

# make a copy of the message into a byte-array which is mutable 
bogusMessage = bytearray(encryptedB2A)

# we have to wrap the message with a bytes() function to make an immutable copy acceptable
# for the nacl library 
plaintext_should_work = alice_box.decrypt(bytes(bogusMessage))
print ("the plaintext Bob sent is: %s" % (plaintext_should_work))

# change 1 byte of the encrypted text
# if one byte is not zero, set to zero, else, set it to a non-zero value 
if (bogusMessage[41] != 0): 
    bogusMessage[41] = 0
else:
    bogusMessage[41] = 0xFE

# decrypting bad data should throw an exception
try: 
    plaintext_should_fail = alice_box.decrypt(bytes(bogusMessage))
except nacl.exceptions.CryptoError:
    print "decryption of modified encrypted text failed"
    


    


    