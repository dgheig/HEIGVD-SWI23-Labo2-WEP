#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Authors:
# - Yanick Thomann
# - Jean Gachet
# - David Gallay
#
# This script is made for exercise 2
# Manually encrypt a wep message given the WEP key

from scapy.all import *
import binascii
from rc4 import RC4

# WEP key AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'

# ARP
llc = b'\xaa\xaa\x03\x00\x00\x00\x08\x06'  # Header LLC/SNAP
hwtype = b'\x00\x01'  # hardware type = Ethernet
ptype = b'\x08\x00'  # protocole type = IPv4
hwlen = b'\x06'  # length of the hardware addresses = 6 bytes
plen = b'\x04'  # length of the protocole addresses = 4 bytes
op = b'\x00\x01'  # opcode = request
hwsrc = b'\x90\x27\xe4\xea\x61\xf2'  # MAC address of the source
psrc = b'\xc0\xa8\x01\x64'  # IP address of the source
hwdst = b'\x00\x00\x00\x00\x00\x00'  # MAC address of the destination (unknown, what we are requesting)
pdst = b'\xc0\xa8\x01\xc8'  # IP address of the destination

arp = ARP(hwtype=hwtype, ptype=ptype, hwlen=hwlen, plen=plen, op=op, hwsrc=hwsrc, psrc=psrc, hwdst=hwdst, pdst=pdst)

# RC4
iv = b'\x00\x00\x00'
rc4_seed = iv + key

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

# rc4 seed est composé de IV+clé
seed = arp.ivarp+key

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
