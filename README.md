# docDigitalSign

This program is written in C and uses openssl.

Abstract explanation:
---------------------
This program is implemented for digital signing and verifying documents. In this way there is no doubt that the proper author last modified a specific file. The program computes the sha256 hash value of a given document and then uses RSA_sign to encrypt the hash value computed before. In this way this hashed value is now signed. Then that signed value is encoded in base64 format and is written in a file called 'signature_64'. Any modification made at a later stage on file will produce a different hash value so the author has to sign the file every time a new change is made. The program can also verify that a given signature matches a given file signature in order to verify if that file is created(or last edited) by the proper author. For that function the program takes the document and signature(in base 64 format) as arguments and it computes the sha256 hash value of the document, decodes the base64 format signature and decrypts the decoded value. Then the program compares two signatures with RSA_verify to verify that they are the same. In this way we can see if the document is modified by a non authorized.

Installation Instructions:
--------------------------
1)  Clone or download the repository.
2)  Download and install openssl. (Link: https://www.openssl.org/)
3)  Compile and execute.

Compile using:
-------------- 
gcc docsign.c -o docsign -lcrypto -lm

Execute on following  commands:
-------------------------------
- ./docsign : show help for all the available actions to perform.

- ./docsign -createkeys : Create the private and public RSA keys and store them in two files called 'private_key' and 'public_key' in PEM  format.

- ./docsign -s DOCUMENT : Sign the the document named DOCUMENT and store the signature in base64 format in file 'signature_64'.

- ./docsign -v DOCUMENT signature_64 : Verify that DOCUMENT signature matches signature_64.
