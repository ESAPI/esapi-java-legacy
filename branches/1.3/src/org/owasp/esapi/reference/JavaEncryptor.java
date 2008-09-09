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
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEParameterSpec;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.IntegrityException;

/**
 * Reference implementation of the Encryptor interface. This implementation
 * layers on the JCE provided cryptographic package. Algorithms used are
 * configurable in the ESAPI.properties file.
 * 
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encryptor
 */
public class JavaEncryptor implements org.owasp.esapi.Encryptor {

	/** The private key. */
	PrivateKey privateKey = null;

	/** The public key. */
	PublicKey publicKey = null;

	PBEParameterSpec parameterSpec = null;
	SecretKey secretKey = null;
	String encryptAlgorithm = "PBEWithMD5AndDES";
	String signatureAlgorithm = "SHAwithDSA";
	String hashAlgorithm = "SHA-512";
	String randomAlgorithm = "SHA1PRNG";
	String encoding = "UTF-8"; 
		
	public JavaEncryptor() {
		byte[] salt = ESAPI.securityConfiguration().getMasterSalt();
		char[] pass = ESAPI.securityConfiguration().getMasterPassword();

		// setup algorithms
        encryptAlgorithm = ESAPI.securityConfiguration().getEncryptionAlgorithm();
		signatureAlgorithm = ESAPI.securityConfiguration().getDigitalSignatureAlgorithm();
		randomAlgorithm = ESAPI.securityConfiguration().getRandomAlgorithm();
		hashAlgorithm = ESAPI.securityConfiguration().getHashAlgorithm();
		
		try {
            // Set up encryption and decryption
            parameterSpec = new javax.crypto.spec.PBEParameterSpec(salt, 20);
			SecretKeyFactory kf = SecretKeyFactory.getInstance(encryptAlgorithm);
			secretKey = kf.generateSecret(new javax.crypto.spec.PBEKeySpec(pass));
			encoding = ESAPI.securityConfiguration().getCharacterEncoding();

			// Set up signing keypair using the master password and salt
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
			SecureRandom random = SecureRandom.getInstance(randomAlgorithm);
			byte[] seed = hash(new String(pass),new String(salt)).getBytes();
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
	 * Hashes the data using the specified algorithm and the Java MessageDigest class. This method
	 * first adds the salt, a separator (":"), and the data, and then rehashes 1024 times to help strengthen weak passwords.
	 * 
	 * @see org.owasp.esapi.Encryptor#hash(java.lang.String,java.lang.String)
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

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncryptor#encrypt(java.lang.String)
	 */
	public String encrypt(String plaintext) throws EncryptionException {
		// Note - Cipher is not threadsafe so we create one locally
		try {
			Cipher encrypter = Cipher.getInstance(encryptAlgorithm);
			encrypter.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
			byte[] output = plaintext.getBytes(encoding);
			byte[] enc = encrypter.doFinal(output);
			return ESAPI.encoder().encodeForBase64(enc,false);
		} catch (Exception e) {
			throw new EncryptionException("Decryption failure", "Decryption problem: " + e.getMessage(), e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncryptor#decrypt(java.lang.String)
	 */
	public String decrypt(String ciphertext) throws EncryptionException {
		// Note - Cipher is not threadsafe so we create one locally
		try {
			Cipher decrypter = Cipher.getInstance(encryptAlgorithm);
			decrypter.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
			byte[] dec = ESAPI.encoder().decodeFromBase64(ciphertext);
			byte[] output = decrypter.doFinal(dec);
			return new String(output, encoding);
		} catch (Exception e) {
			throw new EncryptionException("Decryption failed", "Decryption problem: " + e.getMessage(), e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncryptor#sign(java.lang.String)
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
	
	
	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncryptor#verifySignature(java.lang.String,
	 *      java.lang.String)
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

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncryptor#seal(java.lang.String,
	 *      java.lang.String)
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

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncryptor#unseal(java.lang.String)
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

	
	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncryptor#verifySeal(java.lang.String)
	 */
	public boolean verifySeal( String seal ) {
		try {
			unseal( seal );
			return true;
		} catch( Exception e ) {
			return false;
		}
	}
	
	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncryptor#getTimeStamp()
	 */
	public long getTimeStamp() {
		return new Date().getTime();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncryptor#getTimeStamp()
	 */
	public long getRelativeTimeStamp( long offset ) {
		return new Date().getTime() + offset;
	}

}
