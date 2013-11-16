ESAPI2.0-ciphertext-portable.ser is a test for the backwards compatibility
of ESAPI 2.1.0 and later crypto with ESAPI 2.0 crypto.

That file was created on Windows using the 128-bit session key from
Encryptor.MasterKey and encrypted with AES/CBC/PKCS5Padding so cannot be
decrypted.

The file ESAPI2.1.0-ciphertext-portable-masterkey.ser is a test for the
backwards compatibility of ESAPI 2.1.1 and later crypto. It was created
by the ESAPI 2.1.0 release (the 20130830 crypto version) which was the
version just *before* the KDF was changed to include the KDF version,
KDF PRF, and cipher transformation as part of the KDF context (aka, label)
to derive the encryption and MAC keys. The Encryptor.MasterKey was used for the
encryption key for this to encrypt the plaintext string (w/out quotes):

	"NSA: all your crypto bit are belong to us."
	
This file should be decrypted using the 128-bit AES Encryptor.MasterKey of

	Encryptor.MasterKey=a6H9is3hEVGKB4Jut+lOVA==
