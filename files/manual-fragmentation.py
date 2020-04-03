#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Julien Huguet & Antoine Hunkeler"
__copyright__   = "Copyright 2020, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__status__ 	= "Prototype"
__source1__	= "https://scapy.readthedocs.io/en/latest/api/scapy.utils.html"
__source2__	= "https://stackoverflow.com/questions/7574092/python-scapy-wrpcap-how-do-you-append-packets-to-a-pcap-file"

from scapy.all import *
import binascii
import sys
from rc4 import RC4

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

# Creation des trois fragments et encodage en ascii pour la creation du crc
DATA = []
DATA.append(b'WATERS'*6)
DATA.append(b'QWERTZ'*6)
DATA.append(b'SWITCH'*6)

# Lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]  

# Rc4 seed est composé de IV+clé
seed = arp.iv+key

# Nombre de fragment totaux
NB_FRAGS = 3

# Bit pour more fragment
MORE_FRAGMENT = 0x4

# Taille de la donnee
DATA_SIZE = len(DATA)

# Taille d'un fragment
SIZE_OF_ONE_FRAG = int(DATA_SIZE/NB_FRAGS)

# Encryption de chaque fragment
for i in range(NB_FRAGS):
	# Creation de ICV
	dataICV = binascii.crc32(DATA[i]).to_bytes(sys.getsizeof(DATA), 'little')

	# Encapsulation des donnees
	dataWithICV = DATA[i] + dataICV

	# Generation de l'encrpytion
	cipher = RC4(seed, streaming=False)
	encrypt = cipher.crypt(dataWithICV)
	
	# Transformation de l'ICV en long
	encryptICV = encrypt[-4:]
	(encryptICVL,) = struct.unpack('!L', encryptICV)

	# Recuperation des donnees encryptee de la sortie
	encryptData = encrypt[:-4]

	# Creation de la trame encryptee
	arpFrag = rdpcap('arp.cap')[0]
	arpFrag.wepdata = encryptData
	arpFrag.icv = encryptICVL
	arpFrag.SC = i

	# Ajout du flag more fragment sauf au dernier fragment
	if i != NB_FRAGS - 1:
		arpFrag.FCfield |= MORE_FRAGMENT
	
	# Ajout du fragment dans le fichier cap
	wrpcap("arp_fragmentation.cap", arpFrag, append=True)
	
	

