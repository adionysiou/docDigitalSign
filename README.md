# docDigitalSign

This program is written in C and uses openssl.

Abstract explanation:
---------------------
This program is implemented for digital signing and verifying documents. In this way there is no doubt that the proper author last modified a specific file. The program computes the sha256 hash value of a given document and then uses RSA_sign to encrypt the hash value computed before. In this way this hashed value is now signed. Then that signed value is encoded in base64 format and is written in a file called 'signature_64'. Any modification made at a later stage on file will produce a different hash value so the author has to sign the file every time a new change is made. The program can also verify that a given signature matches a given file signature in order to verify if that file is created(or last edited) by the proper author. For that function the program takes the document and signature(in base 64 format) as arguments and it computes the sha256 hash value of the document, decodes the base64 format signature and decrypts the decoded value. Then the program compares two signatures with RSA_verify to verify that they are the same. In this way we can see if the document is modified by a non authorized.
Compile using:
-------------- 
gcc docsign.c -o docsign -lcrypto -lm

This is a software written in c that signs a given document. it first hashes the document with sha256 and then uses RSA_sign to "sign" that hash value. The progam also verifies that a given document matches the signature given in a separate file. Also the program is able to create and store RSA private and public keys to files. All this is done with openssl library.
