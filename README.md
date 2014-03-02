PBKDF2-GCC-PolarSSL-library
===========================

      Code     Issues 0     Pull Requests 0     Wiki      Pulse     Graphs     Network      Settings  HTTPS clone URL  
      
      
      
You can clone with HTTPS, SSH, or Subversion.  

GCC based PBKDF2 implementation using PolarSSL libraries; works in Linux. Should work in Windows with MinGW once PolarSSL libraries are compiled.

Licensed under GNU Public License Version 2.0 (GPL v2.0) and any later versions of this License.
      
      
Requires compiled PolarSSL libraries.

At this time, it has been briefly checked (SHA-512 only) under Debian 7 with PolarSSL 1.2.9.

Debian command to install PolarSSL components:
sudo apt-get install -y libpolarssl-dev 

Should you not find <polarssl/sha2.h> and <polarssl/sha4.h>, please try <polarssl/sha256.h> and <polarssl/sha512.h> (which include SHA-224 and SHA-384 respectively).

