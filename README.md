PBKDF2-GCC-PolarSSL-library
===========================

GCC and PolarSSL library based PBKDF2 implementation.  Works in Linux.  Should work in Windows with MinGW once PolarSSL libraries are compiled.

      
Licensed under GNU Public License Version 2.0 (GPL v2.0) and any later versions of this License.

      

At this time, it has been briefly checked (SHA-512 only) under Debian 7 with PolarSSL 1.2.9.

Requires compiled PolarSSL libraries.
Debian command to install PolarSSL components:
sudo apt-get install -y libpolarssl-dev 

Should you not find <polarssl/sha2.h> and <polarssl/sha4.h>, please try <polarssl/sha256.h> and <polarssl/sha512.h> (which include SHA-224 and SHA-384 respectively).

