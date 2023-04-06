#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" 
-------------------------------------------------
Manually encrypt a wep message
-------------------------------------------------
authors Jean Gachet, David Gallay, Yanick Thomann
date    06.04.2023

"""

from scapy.all import *
import binascii
from rc4 import RC4
import os

"""
#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]  

# rc4 seed est composé de IV+clé
seed = arp.iv+key

# recuperation de icv dans le message (arp.icv) (en chiffre) -- je passe au format "text". Il y a d'autres manières de faire ceci...
icv_encrypted='{:x}'.format(arp.icv)

# text chiffré y-compris l'icv
message_encrypted=arp.wepdata+bytes.fromhex(icv_encrypted)

# déchiffrement rc4
cipher = RC4(seed, streaming=False)
cleartext=cipher.crypt(message_encrypted)

# le ICV est les derniers 4 octets - je le passe en format Long big endian
icv_enclair=cleartext[-4:]
icv_enclair = icv_enclair
icv_numerique=struct.unpack('!L', icv_enclair)

# le message sans le ICV
text_enclair=cleartext[:-4]

print ('Text: ' + text_enclair.hex())
print ('icv:  ' + icv_enclair.hex())
print ('icv(num): ' + str(icv_numerique))

"""

# The WEP key used for encryption: AA:AA:AA:AA:AA
WEP_KEY = b'\xAA\xAA\xAA\xAA\xAA'

# All fields contained in an ARP Frame
ARP_HEADER = b'\xAA\xAA\x03\x00\x00\x00\x08'
HARDWARE_TYPE = b'\x06'
PROTO_TYPE = b'\x00\x01'
HARDWARE_SIZE = b'\x08\x00'
PROTO_SIZE = b'\x04'
OPCODE = b'\x00\x01'
SENDER_MAC = b'\xDE\xAD\xF0\x00\x0D'
SENDER_IP = b'\x0A\x0A\x0A\x01'
TARGET_MAC = b'\xDE\xAD\xC0\xFF\xEE'
TARGET_IP = b'\x00\x00\x00\x00\x00'

def generate_iv():
    byte = bytes(os.urandom(3))
    return byte

def calculate_icv(message):
    icv = hmac.new(WEP_KEY, message.encode(), hashlib.sha256).digest()
    print(icv.hex())

def main():
    print(generate_iv())
    calculate_icv("Some message")


if __name__ == "__main__":
    main()

