/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/esapi.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the LGPL. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;

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

import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.IntegrityException;

/**
 * Reference implementation of the IEncryptor interface. This implementation
 * layers on the JCE provided cryptographic package. Algorithms used are
 * configurable in the ESAPI.properties file.
 * 
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.interfaces.IEncryptor
 */
public class Encryptor implements org.owasp.esapi.interfaces.IEncryptor {

	/** The private key. */
	PrivateKey privateKey = null;

	/** The public key. */
	PublicKey publicKey = null;

	/** The logger. */
	private static final Logger logger = Logger.getLogger("ESAPI", "Encryptor");

	// FIXME: AAA need global scrub of what methods need to log

	/** The instance. */
	private static Encryptor instance = new Encryptor();

	PBEParameterSpec parameterSpec = null;
	SecretKey secretKey = null;
	String encryptAlgorithm = "PBEWithMD5AndDES";
	String signatureAlgorithm = "SHAwithDSA";
	String hashAlgorithm = "SHA-512";
	String randomAlgorithm = "SHA1PRNG";
	String encoding = "UTF-8"; 
		
	/**
	 * Hide the constructor for the Singleton pattern.
	 */
	private Encryptor() {
		
		// FIXME: AAA - need support for key and salt changing. What's best interface?
		byte[] salt = SecurityConfiguration.getInstance().getMasterSalt();
		char[] pass = SecurityConfiguration.getInstance().getMasterPassword();

		// setup algorithms
        encryptAlgorithm = SecurityConfiguration.getInstance().getEncryptionAlgorithm();
		signatureAlgorithm = SecurityConfiguration.getInstance().getDigitalSignatureAlgorithm();
		randomAlgorithm = SecurityConfiguration.getInstance().getRandomAlgorithm();
		hashAlgorithm = SecurityConfiguration.getInstance().getHashAlgorithm();
		
		try {
            // Set up encryption and decryption
            parameterSpec = new javax.crypto.spec.PBEParameterSpec(salt, 20);
			SecretKeyFactory kf = SecretKeyFactory.getInstance(encryptAlgorithm);
			secretKey = kf.generateSecret(new javax.crypto.spec.PBEKeySpec(pass));
			encoding = SecurityConfiguration.getInstance().getCharacterEncoding();

			// Set up signing keypair using the master password and salt
			// FIXME: Enhance - make DSA configurable
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
	 * Gets the single instance of Encryptor.
	 * 
	 * @return single instance of Encryptor
	 */
	public static Encryptor getInstance() {
		return instance;
	}

	/**
	 * Hashes the data using the specified algorithm and the Java MessageDigest class. This method
	 * first adds the salt, then the data, and then rehashes 1024 times to help strengthen weak passwords.
	 * 
	 * @see org.owasp.esapi.interfaces.IEncryptor#hash(java.lang.String,java.lang.String)
	 */
	public String hash(String plaintext, String salt) {
		byte[] bytes = null;
		try {
			MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
			digest.reset();
			digest.update(SecurityConfiguration.getInstance().getMasterSalt());
			digest.update(salt.getBytes());
			digest.update(plaintext.getBytes());

			// rehash a number of times to help strengthen weak passwords
			// FIXME: ENHANCE make iterations configurable
			bytes = digest.digest();
			for (int i = 0; i < 1024; i++) {
				digest.reset();
				bytes = digest.digest(bytes);
			}
			String encoded = Encoder.getInstance().encodeForBase64(bytes,false);
			return encoded;
		} catch (NoSuchAlgorithmException e) {
			logger.logCritical(Logger.SECURITY, "Can't find hash algorithm " + hashAlgorithm, e);
			return null;
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
			return Encoder.getInstance().encodeForBase64(enc,true);
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
			byte[] dec = Encoder.getInstance().decodeFromBase64(ciphertext);
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
			return Encoder.getInstance().encodeForBase64(bytes,true);
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
			byte[] bytes = Encoder.getInstance().decodeFromBase64(signature);
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
			return this.encrypt(expiration + ":" + data);
		} catch( EncryptionException e ) {
			throw new IntegrityException( e.getUserMessage(), e.getLogMessage(), e );
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncryptor#verifySeal(java.lang.String,
	 *      java.lang.String)
	 */
	public boolean verifySeal(String seal, String data) {
		String plaintext = null;
		try {
			plaintext = decrypt(seal);
		} catch (EncryptionException e) {
			new EncryptionException("Invalid seal", "Seal did not decrypt properly", e);
			return false;
		}

		int index = plaintext.indexOf(":");
		if (index == -1) {
			new EncryptionException("Invalid seal", "Seal did not contain properly formatted separator");
			return false;
		}

		String timestring = plaintext.substring(0, index);
		long now = new Date().getTime();
		long expiration = Long.parseLong(timestring);
		if (now > expiration) {
			new EncryptionException("Invalid seal", "Seal expiration date has expired");
			return false;
		}

		String sealedValue = plaintext.substring(index + 1);
		if (!sealedValue.equals(data)) {
			new EncryptionException("Invalid seal", "Seal data does not match");
			return false;
		}
		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IEncryptor#getTimeStamp()
	 */
	public long getTimeStamp() {
		return new Date().getTime();
	}

}
