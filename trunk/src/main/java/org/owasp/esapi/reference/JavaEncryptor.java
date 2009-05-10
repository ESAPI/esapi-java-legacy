/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi.reference;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.IntegrityException;

/**
 * Reference implementation of the Encryptor interface. This implementation
 * layers on the JCE provided cryptographic package. Algorithms used are
 * configurable in the ESAPI.properties file.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encryptor
 */
public class JavaEncryptor implements org.owasp.esapi.Encryptor {

    // encryption
    private static SecretKeySpec secretKeySpec = null;
    private static String encryptAlgorithm = "AES";
    private static String encoding = "UTF-8"; 
    private static int keysize = 256; 

    // digital signatures
    private static PrivateKey privateKey = null;
	private static PublicKey publicKey = null;
	private static String signatureAlgorithm = "SHAwithDSA";
    private static String randomAlgorithm = "SHA1PRNG";
	
	// hashing
	private static String hashAlgorithm = "SHA-512";
	
	
    /**
     *
     * @param args
     * @throws java.lang.Exception
     */
    public static void main( String[] args ) throws Exception {
        System.out.println( "Generating a new secret key" );
        KeyGenerator kgen = KeyGenerator.getInstance( encryptAlgorithm );
        kgen.init(keysize);
        SecretKey secretKey = kgen.generateKey();
        byte[] raw = secretKey.getEncoded();
        System.out.println( "\nCopy and paste this into ESAPI.properties\n" );
        System.out.println( ESAPI.encoder().encodeForBase64(raw, false) );
        System.out.println();
    }
	
    
    /**
     *
     */
    public JavaEncryptor() {
		byte[] salt = ESAPI.securityConfiguration().getMasterSalt();
		byte[] skey = ESAPI.securityConfiguration().getMasterKey();

		// setup algorithms
        encryptAlgorithm = ESAPI.securityConfiguration().getEncryptionAlgorithm();
		signatureAlgorithm = ESAPI.securityConfiguration().getDigitalSignatureAlgorithm();
		randomAlgorithm = ESAPI.securityConfiguration().getRandomAlgorithm();
		hashAlgorithm = ESAPI.securityConfiguration().getHashAlgorithm();
		
		try {
            // Set up encryption and decryption
            secretKeySpec = new SecretKeySpec(skey, encryptAlgorithm );
			encoding = ESAPI.securityConfiguration().getCharacterEncoding();

			// Set up signing keypair using the master password and salt
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
			SecureRandom random = SecureRandom.getInstance(randomAlgorithm);
			byte[] seed = hash(new String(skey),new String(salt)).getBytes();
			random.setSeed(seed);
			keyGen.initialize(1024, random);
			KeyPair pair = keyGen.generateKeyPair();
			privateKey = pair.getPrivate();
			publicKey = pair.getPublic();
		} catch (Exception e) {
			// can't throw this exception in initializer, but this will log it
			new EncryptionException("Encryption failure", "Error creating Encryptor", e);
		}
	}

	
	/**
     * {@inheritDoc}
     * 
	 * Hashes the data using the specified algorithm and the Java MessageDigest class. This method
	 * first adds the salt, a separator (":"), and the data, and then rehashes 1024 times to help 
	 * strengthen weak passwords.
	 */
	public String hash(String plaintext, String salt) throws EncryptionException {
		byte[] bytes = null;
		try {
			MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
			digest.reset();
			digest.update(ESAPI.securityConfiguration().getMasterSalt());
			digest.update(salt.getBytes());
			digest.update(plaintext.getBytes());

			// rehash a number of times to help strengthen weak passwords
			bytes = digest.digest();
			for (int i = 0; i < 1024; i++) {
				digest.reset();
				bytes = digest.digest(bytes);
			}
			String encoded = ESAPI.encoder().encodeForBase64(bytes,false);
			return encoded;
		} catch (NoSuchAlgorithmException e) {
			throw new EncryptionException("Internal error", "Can't find hash algorithm " + hashAlgorithm, e);
		}
	}
	
	/**
	* {@inheritDoc}
	*/
	public String encrypt(String plaintext) throws EncryptionException {
		// Note - Cipher is not threadsafe so we create one locally
		try {
			Cipher encrypter = Cipher.getInstance(encryptAlgorithm);
			encrypter.init(Cipher.ENCRYPT_MODE, secretKeySpec);
			byte[] output = plaintext.getBytes(encoding);
			byte[] enc = encrypter.doFinal(output);
			return ESAPI.encoder().encodeForBase64(enc,false);
		} catch (Exception e) {
			throw new EncryptionException("Encryption failure", "Encryption problem: " + e.getMessage(), e);
		}
	}

	/**
	* {@inheritDoc}
	*/
	public String decrypt(String ciphertext) throws EncryptionException {
		// Note - Cipher is not threadsafe so we create one locally
		try {
			Cipher decrypter = Cipher.getInstance(encryptAlgorithm);
			decrypter.init(Cipher.DECRYPT_MODE, secretKeySpec);
			byte[] dec = ESAPI.encoder().decodeFromBase64(ciphertext);
			byte[] output = decrypter.doFinal(dec);
			return new String(output, encoding);
		} catch (Exception e) {
			throw new EncryptionException("Decryption failed", "Decryption problem: " + e.getMessage(), e);
		}
	}

	/**
	* {@inheritDoc}
	*/
	public String sign(String data) throws EncryptionException {
		String signatureAlgorithm="SHAwithDSA";
		try {
			Signature signer = Signature.getInstance(signatureAlgorithm);
			signer.initSign(privateKey);
			signer.update(data.getBytes());
			byte[] bytes = signer.sign();
			return ESAPI.encoder().encodeForBase64(bytes,true);
		} catch (Exception e) {
			throw new EncryptionException("Signature failure", "Can't find signature algorithm " + signatureAlgorithm, e);
		}
	}
		
	/**
	* {@inheritDoc}
	*/
	public boolean verifySignature(String signature, String data) {
		try {
			byte[] bytes = ESAPI.encoder().decodeFromBase64(signature);
			Signature signer = Signature.getInstance(signatureAlgorithm);
			signer.initVerify(publicKey);
			signer.update(data.getBytes());
			return signer.verify(bytes);
		} catch (Exception e) {
			new EncryptionException("Invalid signature", "Problem verifying signature: " + e.getMessage(), e);
			return false;
		}
	}

	/**
	* {@inheritDoc}
     *
     * @param expiration
     * @throws IntegrityException
     */
	public String seal(String data, long expiration) throws IntegrityException {
		try {
			// mix in some random data so even identical data and timestamp produces different seals
			String random = ESAPI.randomizer().getRandomString(10, DefaultEncoder.CHAR_ALPHANUMERICS);
			return this.encrypt(expiration + ":" + random + ":" + data);
		} catch( EncryptionException e ) {
			throw new IntegrityException( e.getUserMessage(), e.getLogMessage(), e );
		}
	}

	/**
	* {@inheritDoc}
	*/
	public String unseal(String seal) throws EncryptionException {
		
		String plaintext = null;
		try {
			plaintext = decrypt(seal);
		} catch (EncryptionException e) {
			throw new EncryptionException("Invalid seal", "Seal did not decrypt properly", e);
		}

		int index = plaintext.indexOf(":");
		if (index == -1) {
			throw new EncryptionException("Invalid seal", "Seal did not contain properly formatted separator");
		}

		String timestring = plaintext.substring(0, index);
		long now = new Date().getTime();
		long expiration = Long.parseLong(timestring);
		if (now > expiration) {
			throw new EncryptionException("Invalid seal", "Seal expiration date has expired");
		}

		index = plaintext.indexOf(":", index+1);
		String sealedValue = plaintext.substring(index + 1);
		return sealedValue;
	}

	
	/**
	* {@inheritDoc}
	*/
	public boolean verifySeal( String seal ) {
		try {
			unseal( seal );
			return true;
		} catch( Exception e ) {
			return false;
		}
	}
	
	/**
	* {@inheritDoc}
	*/
	public long getTimeStamp() {
		return new Date().getTime();
	}

	/**
	* {@inheritDoc}
	*/
	public long getRelativeTimeStamp( long offset ) {
		return new Date().getTime() + offset;
	}

}
