#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Julien Huguet & Antoine Hunkeler"
__copyright__   = "Copyright 2020, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__status__ 	= "Prototype"

from scapy.all import *
import binascii
import sys
from rc4 import RC4

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

#Donnee a encrypter
data = ("Voici une trame encryptee pour test ").encode('ascii')

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]  

# rc4 seed est composé de IV+clé
seed = arp.iv+key

#Creation de ICV
dataICV = binascii.crc32(data).to_bytes(sys.getsizeof(data), 'little')

#Encapsulation des donnees
dataWithICV = data + dataICV

#Generation de l'encrpytion
cipher = RC4(seed, streaming=False)
encrypt = cipher.crypt(dataWithICV)

#Transformation de l'ICV en long
encryptICV = encrypt[-4:]
(encryptICVL,) = struct.unpack('!L', encryptICV)

#Recuperation des donnees encryptee de la sortie
encryptData = encrypt[:-4]

#Creation de la trame encryptee
arpEncrypt = rdpcap('arp.cap')[0]
arpEncrypt.wepdata = encryptData
arpEncrypt.icv = encryptICVL

#Creation du fichier Wireshark
wrpcap("arp_encryption.cap", arpEncrypt)




