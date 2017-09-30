# docDigitalSign

This program is written in C and uses openssl.

Getting Started:
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

Available actions to perform:
-------------------------------
- ./docsign : show help for all the available actions to perform.

- ./docsign -createkeys : Create the private and public RSA keys and store them in two files called 'private_key' and 'public_key' in PEM  format.
 
  NOTE: If user does not have RSA keys in PEM format then this command MUST BE EXECUTED FIRST!.

- ./docsign -s DOCUMENT : Sign the the document named DOCUMENT(using RSA private_key file) and store the signature in base64 format in file 'signature_64'.

  NOTE: In order for the program to work properly the 'private_key' file should be in the SAME directory with the program being executed.

- ./docsign -v DOCUMENT signature_64 : Verify that DOCUMENT signature matches signature_64.

  NOTE: In order for the program to work properly the 'public_key' files should be in the SAME directory with the program being executed.

Authors:
--------
Antreas Dionysiou

License:
--------
Please see LICENSE.md file for details

General Notes:
--------------
Please feel free to use our program for signing and verifying your documents as this is an open source software. 
Document and Document1 are sample files for testing purposes.
