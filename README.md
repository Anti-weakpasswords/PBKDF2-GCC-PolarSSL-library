PBKDF2-GCC-PolarSSL-library
===========================

GCC and PolarSSL library based PBKDF2 implementation.  Works in Linux.  Should work in Windows with MinGW once PolarSSL libraries are compiled.

      
Licensed under GNU Public License Version 2.0 (GPL v2.0) and any later versions of this License.

      

At this time, it has been briefly checked (SHA-512 only) under Debian 7 with PolarSSL 1.2.9.

Requires compiled PolarSSL libraries.
Debian command to install PolarSSL components:
sudo apt-get install -y libpolarssl-dev 

Should you not find polarssl/sha2.h and polarssl/sha4.h, please try polarssl/sha256.h and polarssl/sha512.h (which include SHA-224 and SHA-384 respectively), or vice versa - there was a naming change on the headers somewhere between PolarSSL 1.2.9 and 1.3.4.

To compile on Windows, the easiest way is to install MinGW via the MinGW Builds installer, which can be found at http://sourceforge.net/projects/mingwbuilds/    (or, apparently, at links off of there since they've joined the overall MinGW-w64 project for both 32-bit and 64-bit Windows MinGW).
