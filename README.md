# dnrverify
Denarius (DNR) signed message verification

The code was mostly extracted from https://github.com/carsenk/denarius

Digital signing is the core feature of a cryptocurrency. Every spending must be digitally signed and recorded in the blockchain. Only the person with the private key can do the signing. However, anyone with the public key can verify the signature. Since the signing standard is based on the Digital Signature Algorithm (DSA), or more specifically the Elliptic Curve Digital Signature Algorithm (ECDSA) so the same private key can also be used to digitally sign any message outside of the blockchain. Hence, the signed message can also be verified outside of the blockchain. 

This library has been extracted from the Denarius code. A slight modification has been made so that to make the code compact and stand alone. The code reveals the original signed-message verification algorithm used in Denarius.
