# dnrverify
Denarius (DNR), Bitcoin (BTC) and Bitcoin-based Altcoins signed message verification.

The code was mostly extracted from https://github.com/carsenk/denarius

Digital signing is the core feature of a cryptocurrency. Every spending must be digitally signed and recorded in the blockchain. Only the person with the private key can do the signing. However, anyone with the public key can verify the signature. Since the signing standard is based on the Digital Signature Algorithm (DSA), or more specifically the Elliptic Curve Digital Signature Algorithm (ECDSA) so the same private key can also be used to digitally sign any message outside of the blockchain. Hence, the signed message can also be verified outside of the blockchain. 

This code has been extracted from Denarius. A slight modification has been made so that to make the code compact and stand alone. The code reveals the original signed-message verification algorithm used in Denarius.

## Bitcoin-based Altcoins
The code can also be used to verify Bitcoin and Bitcoin-based Altcoins signed messages. The code was originally from Bitcoin. Denarius only made one simple change:
```c++
const string strMessageMagic = "Denarius Signed Message:\n";
```
from the original
```c++
const string strMessageMagic = "Bitcoin Signed Message:\n";
```
Hence, any Bitcoin-based Altcoin can use this code to verify its signed messages by setting the proper **strMessageMagic** according to the Altcoin.

## Address prefix
This code which is mostly the original Bitcoin code ignores address prefix. A messsage was signed with the *private key* which had no idea of the address prefix. The verification process of a signed message will reveal its *public key*. An address is made up of a prefix, its public key digest and a checksum. The public key digest can simply be reconstructed from the revealed public key. The message is assumed to be valid when the digests matched.

