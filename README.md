# docDigitalSign
This is a software written in c that signs a given document. it first hashes the document with sha256 and then uses RSA_sign to "sign" that hash value. The progam also verifies that a given document matches the signature given in a separate file. Also the program is able to create and store RSA private and public keys to files. All this is done with openssl library.
