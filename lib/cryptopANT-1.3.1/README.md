
# CryptoPANT

CryptopANT is a C library for IP address anonymization using crypto-PAn
algorithm, originally defined by Georgia Tech.
The library supports anonymization and de-anonymization (provided you possess a
secret key) of IPv4, IPv6, and MAC addresses.
The software release includes
sample utilities that anonymize IP addresses in text,
but we expect most use of the library will be as part of other programs.
The Crypto-PAn anonymization scheme was developed by Xu, Fan, Ammar, and Moon at Georgia Tech and described
in <a href='http://authors.elsevier.com/sd/article/S1389128604001197'>
"Prefix-Preserving IP  Address Anonymization", Computer Networks,
Volume 46, Issue 2, 7 October 2004, Pages 253-272, Elsevier</a>.
Our library is independent (and not binary compatible) of theirs.

# Building CryptopANT

To build cryptopANT:

	./configure --with-scramble_ips
	make
	sudo make install

or if building from git, start with:

    	./autogen.sh



# Crypto algorithms used

Our library supports several pluggable crypto algorithms for anonymization.
Currently supported are:
 * AES
 * SHA1
 * Blowfish
 * MD5
These algorithms come from openssl library.

Beginning v1.4.0 cryptopANT when creating new keys will use AES by default
as preferred crypto.  Previously, it was defaulting to Blowfish.  The reason for switch
is that after switching to openssl v3 api (EVP), we noticed a marked slowdown in Blowfish.
Old keys using Blowfish will still remain usable, but if the performance is too slow, we
advise switching to new keys using AES or sticking with an older version of cryptopANT.    

