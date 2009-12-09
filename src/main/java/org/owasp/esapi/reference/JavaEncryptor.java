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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.Map.Entry;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
// import javax.crypto.Mac;			// Uncomment if computeHMAC() is included.
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.owasp.esapi.CipherText;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.EncoderConstants;
import org.owasp.esapi.Logger;
import org.owasp.esapi.PlainText;
import org.owasp.esapi.codecs.Hex;
import org.owasp.esapi.errors.ConfigurationException;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.IntegrityException;
import org.owasp.esapi.util.CipherSpec;
import org.owasp.esapi.util.CryptoHelper;

/**
 * Reference implementation of the {@code Encryptor} interface. This implementation
 * layers on the JCE provided cryptographic package. Algorithms used are
 * configurable in the {@code ESAPI.properties} file.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author kevin.w.wall@gmail.com
 * @since June 1, 2007; some methods since ESAPI Java 2.0
 * @see org.owasp.esapi.Encryptor
 */
public class JavaEncryptor implements org.owasp.esapi.Encryptor {

    // encryption
		// Note: These 'protected' so we can also use them in LegacyJavaEncryptor.
    protected static SecretKeySpec secretKeySpec = null; // Why static? Implies one key?!?
    protected static String encryptAlgorithm = "AES";
    protected static String encoding = "UTF-8"; 
    protected static int encryptionKeyLength = 256;
    
    // digital signatures
    private static PrivateKey privateKey = null;
	private static PublicKey publicKey = null;
	private static String signatureAlgorithm = "SHAwithDSA";
    private static String randomAlgorithm = "SHA1PRNG";
	private static int signatureKeyLength = 1024;
	
	// hashing
	private static String hashAlgorithm = "SHA-512";
	private static int hashIterations = 1024;
	
	// Logging - DISCUSS: This "sticks" us with a specific logger to whatever it was when
	//					  this class is loaded. Is that a big limitation?
	private static Logger logger = ESAPI.getLogger("JavaEncryptor");
	
    /**
     * Generates a new strongly random secret key and salt that can be used in the ESAPI properties file.
     * 
     * @param args Set first argument to "-print" to display available algorithms on standard output.
     * @throws java.lang.Exception	To cover a multitude of sins, mostly in configuring ESAPI.properties.
     */
    public static void main( String[] args ) throws Exception {
		System.out.println( "Generating a new secret master key" );
		
		// print out available ciphers
		if ( args.length == 1 && args[0].equalsIgnoreCase("-print" ) ) {
			System.out.println( "AVAILABLE ALGORITHMS" );

			Provider[] providers = Security.getProviders();
			TreeMap<String, String> tm = new TreeMap<String, String>();
			// DISCUSS: Note: We go through multiple providers, yet nowhere do I
			//			see where we print out the PROVIDER NAME. Not all providers
			//			will implement the same algorithms and some "partner" with
			//			whom we are exchanging different cryptographic messages may
			//			have _different_ providers in their java.security file. So
			//			it would be useful to know the provider name where each
			//			algorithm is implemented. Might be good to prepend the provider
			//			name to the 'key' with something like "providerName: ". Thoughts?
			for (int i = 0; i != providers.length; i++) {
				// DISCUSS: Print security provider name here???
					// Note: For some odd reason, Provider.keySet() returns
					//		 Set<Object> of the property keys (which are Strings)
					//		 contained in this provider, but Set<String> seems
					//		 more appropriate. But that's why we need the cast below.
				Iterator<Object> it = providers[i].keySet().iterator();
				while (it.hasNext()) {
					String key = (String)it.next();
		            String value = providers[i].getProperty( key );
		            tm.put(key, value);
				}
			}

			Set< Entry<String,String> > keyValueSet = tm.entrySet();
			Iterator<Entry<String, String>> it = keyValueSet.iterator();
			while( it.hasNext() ) {
				Map.Entry<String,String> entry = it.next();
				String key = entry.getKey();
				String value = entry.getValue();
	        	System.out.println( "   " + key + " -> "+ value );
			}
		} else {
				// Used to print a similar line to use '-print' even when it was specified.
			System.out.println( "\tuse '-print' to also show available crypto algorithms from all the security providers" );
		}
		
        // setup algorithms -- Each of these have defaults if not set, although
		//					   someone could set them to something invalid. If
		//					   so a suitable exception will be thrown and displayed.
        encryptAlgorithm = ESAPI.securityConfiguration().getEncryptionAlgorithm();
		encryptionKeyLength = ESAPI.securityConfiguration().getEncryptionKeyLength();
		randomAlgorithm = ESAPI.securityConfiguration().getRandomAlgorithm();

		SecureRandom random = SecureRandom.getInstance(randomAlgorithm);
		SecretKey secretKey = CryptoHelper.generateSecretKey(encryptAlgorithm, encryptionKeyLength);
        byte[] raw = secretKey.getEncoded();
        byte[] salt = new byte[20];	// Or 160-bits; big enough for SHA1, but not SHA-256 or SHA-512.
        random.nextBytes( salt );
        String eol = System.getProperty("line.separator", "\n"); // So it works on Windows too.
        System.out.println( eol + "Copy and paste these lines into ESAPI.properties" + eol);
        System.out.println( "#==============================================================");
        System.out.println( "Encryptor.MasterKey=" + ESAPI.encoder().encodeForBase64(raw, false) );
        System.out.println( "Encryptor.MasterSalt=" + ESAPI.encoder().encodeForBase64(salt, false) );
        System.out.println( "#==============================================================" + eol);
    }
	
    
    /**
     * CTOR for {@code JavaEncryptor}.
     * @throws EncryptionException if can't construct this object for some reason.
     * 					Original exception will be attached as the 'cause'.
     */
    public JavaEncryptor() throws EncryptionException {
		byte[] salt = ESAPI.securityConfiguration().getMasterSalt();
		byte[] skey = ESAPI.securityConfiguration().getMasterKey();

		// setup algorithms
        encryptAlgorithm = ESAPI.securityConfiguration().getEncryptionAlgorithm();
		signatureAlgorithm = ESAPI.securityConfiguration().getDigitalSignatureAlgorithm();
		randomAlgorithm = ESAPI.securityConfiguration().getRandomAlgorithm();
		hashAlgorithm = ESAPI.securityConfiguration().getHashAlgorithm();
		hashIterations = ESAPI.securityConfiguration().getHashIterations();
		encoding = ESAPI.securityConfiguration().getCharacterEncoding();
		encryptionKeyLength = ESAPI.securityConfiguration().getEncryptionKeyLength();
        signatureKeyLength = ESAPI.securityConfiguration().getDigitalSignatureKeyLength();
        
		try {
            // Set up encryption and decryption
            secretKeySpec = new SecretKeySpec(skey, encryptAlgorithm );

			// Set up signing key pair using the master password and salt
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(signatureAlgorithm);
			SecureRandom random = SecureRandom.getInstance(randomAlgorithm);
			byte[] seed = hash(new String(skey, encoding),new String(salt, encoding)).getBytes(encoding);
			random.setSeed(seed);
			keyGen.initialize(signatureKeyLength, random);
			KeyPair pair = keyGen.generateKeyPair();
			privateKey = pair.getPrivate();
			publicKey = pair.getPublic();
		} catch (Exception e) {
			throw new EncryptionException("Encryption failure", "Error creating Encryptor", e);
		}
	}

	/**
     * {@inheritDoc}
     * 
	 * Hashes the data with the supplied salt and the number of iterations specified in
	 * the ESAPI SecurityConfiguration.
	 */
	public String hash(String plaintext, String salt) throws EncryptionException {
		return hash( plaintext, salt, hashIterations );
	}
	
	/**
     * {@inheritDoc}
     * 
	 * Hashes the data using the specified algorithm and the Java MessageDigest class. This method
	 * first adds the salt, a separator (":"), and the data, and then rehashes the specified number of iterations
	 * in order to help strengthen weak passwords.
	 */
	public String hash(String plaintext, String salt, int iterations) throws EncryptionException {
		byte[] bytes = null;
		try {
			MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
			digest.reset();
			digest.update(ESAPI.securityConfiguration().getMasterSalt());
			digest.update(salt.getBytes(encoding));
			digest.update(plaintext.getBytes(encoding));

			// rehash a number of times to help strengthen weak passwords
			bytes = digest.digest();
			for (int i = 0; i < iterations; i++) {
				digest.reset();
				bytes = digest.digest(bytes);
			}
			String encoded = ESAPI.encoder().encodeForBase64(bytes,false);
			return encoded;
		} catch (NoSuchAlgorithmException e) {
			throw new EncryptionException("Internal error", "Can't find hash algorithm " + hashAlgorithm, e);
		} catch (UnsupportedEncodingException ex) {
			throw new EncryptionException("Internal error", "Can't find encoding for " + encoding, ex);
		}
	}
	
	/**
	 * Convenience method that encrypts plaintext strings the new way (default
	 * is CBC mode and PKCS5 padding). This encryption method uses the master
	 * encryption key specified by the {@code Encryptor.MasterKey} property
	 * in {@code ESAPI.properties}.
	 * 
	 * @param plaintext	A String to be encrypted
	 * @return	A base64-encoded combination of IV + raw ciphertext
	 * @throws EncryptionException	Thrown when something goes wrong with the
	 * 								encryption.
	 * 
	 * @see org.owasp.esapi.Encryptor#encrypt(PlainText)
	 */
	public String encrypt(String plaintext) throws EncryptionException
	{
		CipherText ct = null;
		ct = encrypt(new PlainText(plaintext) );
		return ct.getEncodedIVCipherText();
	}


	/**
	* {@inheritDoc}
	*/
	 public CipherText encrypt(PlainText plaintext) throws EncryptionException {
		 // Now more of a convenience function for using the master key.
		 return encrypt(secretKeySpec, plaintext);
	 }
	 
	 /**
	  * {@inheritDoc}
	  */
	 public CipherText encrypt(SecretKey key, PlainText plain)
	 			throws EncryptionException
	 {
		 byte[] plaintext = plain.asBytes();
		 boolean overwritePlaintext = ESAPI.securityConfiguration().overwritePlainText();
		 assert key != null : "(Master) encryption key may not be null";
		 
		 boolean success = false;	// Used in 'finally' clause.
		 String xform = null;
		 int keySize = key.getEncoded().length * 8;	// Convert to # bits

		try {
			 xform = ESAPI.securityConfiguration().getCipherTransformation();
			 // Note - Cipher is not thread-safe so we create one locally
			 Cipher encrypter = Cipher.getInstance(xform);
			 String cipherAlg = encrypter.getAlgorithm();
			 int keyLen = ESAPI.securityConfiguration().getEncryptionKeyLength();

			 // DISCUSS: OK, what do we want to do here if keyLen != keySize? If use keyLen, encryption
			 //		     could fail with an exception, but perhaps that's what we want. Or we may just be
			 //			 OK with silently using keySize as long as keySize >= keyLen, which then interprets
			 //			 ESAPI.EncryptionKeyLength as the *minimum* key size, but as long as we have something
			 //			 stronger it's OK to use it. For now, I am just going to log warning if different, but use
			 //			 keySize unless keySize is SMALLER than ESAPI.EncryptionKeyLength, in which case I'm going
			 //			 to log an error.
			 //
			 //			 IMPORTANT NOTE:	When we generate key sizes for both DES and DESede the result of
			 //								SecretKey.getEncoding().length includes the TRUE key size (i.e.,
			 //								*with* the even parity bits) rather than the EFFECTIVE key size
			 //								(which incidentally is what KeyGenerator.init() expects for DES
			 //								and DESede; duh! Nothing like being consistent). This leads to
			 //								the following dilemma:
			 //
			 //													EFFECTIVE Key Size		TRUE Key Size
			 //													(KeyGenerator.init())	(SecretKey.getEncoding().length)
			 //									========================================================================
			 //									For DES:			56 bits					64 bits
			 //									For DESede:			112 bits / 168 bits		192 bits (always)
			 //
			 //								We are trying to automatically determine the key size from SecretKey
			 //								based on 8 * SecretKey.getEncoding().length, but as you can see, the
			 //								2 key 3DES and the 3 key 3DES both use the same key size (192 bits)
			 //								regardless of what is passed to KeyGenerator.init(). There are no advertised
			 //								methods to get the key size specified by the init() method so I'm not sure how
			 //								this is actually working internally. However, it does present a problem if we
			 //								wish to communicate the 3DES key size to a recipient for later decryption as
			 //								they would not be able to distinguish 2 key 3DES from 3 key 3DES.
			 //
			 //								The only workaround I know is to pass the explicit key size down. However, if
			 //								we are going to do that, I'd propose passing in a CipherSpec object so we could
			 //								tell what cipher transformation to use as well instead of just the key size. Then
			 //								we would extract keySize from the CipherSpec object of from the SecretKey object.
			 //
			 if ( keySize != keyLen ) {
				 // DISCUSS: Technically this is not a security "failure" per se, but not really a "success" either.
				 logger.warning(Logger.SECURITY_FAILURE, "Encryption key length mismatch. ESAPI.EncryptionKeyLength is " +
						 keyLen + " bits, but length of actual encryption key is " + keySize +
				 		" bits.  Did you remember to regenerate your master key (if that is what you are using)???");
			 }
			 if ( keySize < keyLen ) {
				 // ESAPI.EncryptionKeyLength defaults to 128, but that means that we could not use DES (as weak as it
				 // is), even for legacy code. Therefore, this has been changed to simple log a warning rather than
				 //	throw the following exception.
				 //				 throw new ConfigurationException("Actual key size of " + keySize + " bits smaller than specified " +
				 //						  "encryption key length (ESAPI.EncryptionKeyLength) of " + keyLen + " bits.");
				 logger.warning(Logger.SECURITY_FAILURE, "Actual key size of " + keySize + " bits SMALLER THAN specified " +
						 "encryption key length (ESAPI.EncryptionKeyLength) of " + keyLen + " bits with cipher algorithm " + cipherAlg);
			 }
			 if ( keySize < 80 ) {		// Most cryptographers today consider 80-bits to be the minimally safe key size.
				 logger.warning(Logger.SECURITY_FAILURE, "Potentially unsecure encryption. Key size not sufficiently long. " +
				 				"Should use appropriate algorithm with key size of at least 80 bits.");
			 }
			 // Check if algorithm mentioned in SecretKey is same as that being used for Cipher object.
			 // They should be the same. If they are different, things could fail. (E.g., DES and DESede
			 // require keys with even parity. Even if key was sufficient size, if it didn't have the correct
			 // parity it could fail.)
			 //
			 String skeyAlg = key.getAlgorithm();
			 if ( !( cipherAlg.startsWith( skeyAlg + "/" ) || cipherAlg.equals( skeyAlg ) ) ) {
				 // DISCUSS: Should we thrown a ConfigurationException here or just log a warning??? I'm game for
				 //			 either, but personally I'd prefer the squeaky wheel to the annoying throwing of
				 //			 a ConfigurationException (which is a RuntimeException). Less likely to upset
				 //			 the development community.
				 logger.warning(Logger.SECURITY_FAILURE, "Encryption mismatch between cipher algorithm (" +
						 cipherAlg + ") and SecretKey algorithm (" + skeyAlg + "). Cipher will use algorithm " + cipherAlg);
			 }

			 byte[] ivBytes = null;
			 CipherSpec cipherSpec = new CipherSpec(encrypter, keySize);	// Could pass the ACTUAL (intended) key size
			 SecretKey encKey = CryptoHelper.computeDerivedKey( key, keySize, "encryption");	// Recommended by David Wagner

			 if ( cipherSpec.requiresIV() ) {
				 String ivType = ESAPI.securityConfiguration().getIVType();
				 IvParameterSpec ivSpec = null;
				 if ( ivType.equalsIgnoreCase("random") ) {
					 ivBytes = ESAPI.randomizer().getRandomBytes(encrypter.getBlockSize());
				 } else if ( ivType.equalsIgnoreCase("fixed") ) {
					 String fixedIVAsHex = ESAPI.securityConfiguration().getFixedIV();
					 ivBytes = Hex.decode(fixedIVAsHex);
					 /* FUTURE		 } else if ( ivType.equalsIgnoreCase("specified")) {
					 		// FUTURE - TODO  - Create instance of specified class to use for IV generation and
					 		//					 use it to create the ivBytes. (The intent is to make sure that
					 		//				     1) IVs are never repeated for cipher modes like OFB and CFB, and
					 		//					 2) to screen for weak IVs for the particular cipher algorithm.
					 		//		In meantime, use 'random' for block cipher in feedback mode. Unlikely they will
					 		//		be repeated unless you are salting SecureRandom with same value each time. Anything
					 		//		monotonically increasing should be suitable, like a counter, but need to remember
					 		//		it across JVM restarts. Was thinking of using System.currentTimeMillis(). While
					 		//		it's not perfect it probably is good enough. Could even all (advanced) developers
					 		//      to define their own class to create a unique IV to allow them some choice, but
					 		//      definitely need to provide a safe, default implementation.
					  */
				 } else {
					 // TODO: Update to add 'specified' once that is supported and added above.
					 throw new ConfigurationException("Property Encryptor.ChooseIVMethod must be set to 'random' or 'fixed'");
				 }
				 ivSpec = new IvParameterSpec(ivBytes);
				 cipherSpec.setIV(ivBytes);
				 encrypter.init(Cipher.ENCRYPT_MODE, encKey, ivSpec);
			 } else {
				 encrypter.init(Cipher.ENCRYPT_MODE, encKey);
			 }
			 logger.debug(Logger.EVENT_SUCCESS, "Encrypting with " + cipherSpec);
			 byte[] raw = encrypter.doFinal(plaintext);
			 
			 // Convert to CipherText and store MAC.
			 CipherText ciphertext = new DefaultCipherText(cipherSpec, raw);
			 SecretKey authKey = CryptoHelper.computeDerivedKey( key, keySize, "authenticity");
			 ciphertext.computeAndStoreMAC(  authKey );

			 logger.debug(Logger.EVENT_SUCCESS, "JavaEncryptor.encrypt(SecretKey,byte[],boolean,boolean) -- success!");
			 success = true;	// W00t!!!
			 return ciphertext;
		} catch (InvalidKeyException ike) {
			 throw new EncryptionException("Encryption failure: Invalid key exception.",
					 "Requested key size: " + keySize + "bits greater than 128 bits. Must install unlimited strength crypto extension from Sun: " +
					 ike.getMessage(), ike);
		 } catch (ConfigurationException cex) {
			 throw new EncryptionException("Encryption failure: Configuration error. Details in log.", "Key size mismatch or unsupported IV method. " +
					 "Check encryption key size vs. ESAPI.EncryptionKeyLength or Encryptor.ChooseIVMethod property.", cex);
		 } catch (InvalidAlgorithmParameterException e) {
			 throw new EncryptionException("Encryption failure (invalid IV)",
					 "Encryption problem: Invalid IV spec: " + e.getMessage(), e);
		 } catch (IllegalBlockSizeException e) {
			 throw new EncryptionException("Encryption failure (no padding used; invalid input size)",
					 "Encryption problem: Invalid input size without padding (" + xform + "). " + e.getMessage(), e);
		 } catch (BadPaddingException e) {
			 throw new EncryptionException("Encryption failure",
					 "[Note: Should NEVER happen in encryption mode.] Encryption problem: " + e.getMessage(), e);
		 } catch (NoSuchAlgorithmException e) {
			 throw new EncryptionException("Encryption failure (unavailable cipher)",
					 "Encryption problem: specified algorithm in cipher xform " + xform + " not available: " + e.getMessage(), e);
		 } catch (NoSuchPaddingException e) {
			 throw new EncryptionException("Encryption failure (unavailable padding scheme)",
					 "Encryption problem: specified padding scheme in cipher xform " + xform + " not available: " + e.getMessage(), e);
		 } finally {
			 // Don't overwrite anything in the case of exceptions because they may wish to retry.
			 if ( success && overwritePlaintext ) {
				 plain.overwrite();		// Note: Same as overwriting 'plaintext' byte array.
		}
	}
	 }

	/**
	  * Convenience method that decrypts previously encrypted plaintext strings
	  * that were encrypted using the new encryption mechanism (with CBC mode and
	  * PKCS5 padding by default).  This decryption method uses the master
	  * encryption key specified by the {@code Encryptor.MasterKey} property
	  * in {@code ESAPI.properties}.
	  * 
	  * @param b64IVCiphertext	A base64-encoded representation of the
	  * 							IV + raw ciphertext string to be decrypted with
	  * 							the default master key.
	  * @return	The plaintext string prior to encryption.
	  * @throws EncryptionException When something fails with the decryption.
	  * 
	  * @see org.owasp.esapi.Encryptor#decrypt(CipherText)
	  */
	 public String decrypt(String b64IVCiphertext) throws EncryptionException
	 {
		 DefaultCipherText ct = null;
		 try {
			 // We assume that the default cipher transform was used to encrypt this.
			 ct = new DefaultCipherText();

			 // Need to base64 decode the IV+ciphertext and extract the IV to set it in DefaultCipherText object.
			 byte[] ivPlusRawCipherText = ESAPI.encoder().decodeFromBase64(b64IVCiphertext);
			 int blockSize = ct.getBlockSize();	// Size in bytes.
			 byte[] iv = new byte[ blockSize ];
			 CryptoHelper.copyByteArray(ivPlusRawCipherText, iv, blockSize);	// Copy the first blockSize bytes into iv array
			 int cipherTextSize = ivPlusRawCipherText.length - blockSize;
			 byte[] rawCipherText = new byte[ cipherTextSize ];
			 System.arraycopy(ivPlusRawCipherText, blockSize, rawCipherText, 0, cipherTextSize);
			 ct.setIVandCiphertext(iv, rawCipherText);

			 // Now the DefaultCipherText object should be prepared to use it to decrypt.
			 PlainText plaintext = decrypt(ct);
			 return plaintext.toString();	// Convert back to a Java String
		 } catch (UnsupportedEncodingException e) {
			 // Should never happen; UTF-8 should be in rt.jar.
			 logger.error(Logger.SECURITY_FAILURE, "UTF-8 encoding not available! Decryption failed.", e);
			 return null;	// CHECKME: Or re-throw or what? Could also use native encoding, but that's
			 // likely to cause unexpected and undesired effects far downstream.
		 } catch (IOException e) {
			 logger.error(Logger.SECURITY_FAILURE, "Base64 decoding of IV+ciphertext failed. Decryption failed.", e);
			 return null;
		 }
	 }

	/**
	* {@inheritDoc}
	*/
	public PlainText decrypt(CipherText ciphertext) throws EncryptionException {
		 // Now more of a convenience function for using the master key.
		 return decrypt(secretKeySpec, ciphertext);
	}

	/**
	 * {@inheritDoc}
	 */
	public PlainText decrypt(SecretKey key, CipherText ciphertext) throws EncryptionException
	{
		SecretKey authKey = null;
		try {
			assert key != null : "Encryption key may not be null";
			assert ciphertext != null : "Ciphertext may not be null";
			logger.debug(Logger.EVENT_SUCCESS, "JavaEncryptor.decrypt(SecretKey,CipherText): " + ciphertext);
			Cipher decrypter = Cipher.getInstance(ciphertext.getCipherTransformation());
			int keySize = key.getEncoded().length * 8;	// Convert to # bits
			// TODO: Calculate avg time this takes and consider caching for very short interval (e.g., 2 or 3 sec tops).
			//		 Otherwise doing lots of encryptions in a loop could take a lot longer.
			SecretKey encKey = CryptoHelper.computeDerivedKey( key, keySize, "encryption");	// Recommended by David Wagner

			if ( ciphertext.requiresIV() ) {
				decrypter.init(Cipher.DECRYPT_MODE, encKey, new IvParameterSpec(ciphertext.getIV()));
			} else {
				decrypter.init(Cipher.DECRYPT_MODE, encKey);
			}
			byte[] output = decrypter.doFinal(ciphertext.getRawCipherText());
				// The decryption was "successful", but there are rare instances (approximately
				// 1 in a 1000 for PKCS5Padding) where the wrong key or IV was used but the ciphertext still
				// decrypts correctly, but simply results in garbage. (The other 999 times out
				// of 1000 it will fail with a BadPaddingException [assuming PKCS#5 padding].)
				// Thus at this point, we check (optionally) validate the MAC. If it returns
				// false, rather than returning the (presumably) garbage plaintext, we return
				// throw an exception. The MAC check (if enabled) allows us to verify the
				// authenticity of what was returned as the raw ciphertext.
				//
				// Note: If it is desired to use the MAC, but it was not computed or stored (as in
				// the case with the String encrypt() / decrypt() methods), we return true when
				// we call CipherText.validateMAC() regardless of the outcome, but we also log the discrepancy.
				// The reasons we do this are:
				//		1) If the String-based encrypt / decrypt methods are used, the CipherText object is
				//		   long gone at the time of the decryption and hence the ability to validate the MAC.
				//		2) If a sender encrypts a message and sends a serialized CipherText message a
				//		   recipient, the sender cannot force the recipient (decryptor) to use a MAC and
				//		   vice-versa.
			authKey = CryptoHelper.computeDerivedKey( key, keySize, "authenticity");
			boolean success = ciphertext.validateMAC( authKey );
			if ( !success ) {
					// Stop the debugger here and peer inside the 'ciphertext' object if you don't believe us.
				throw new EncryptionException("Decryption verification failed.",
									"Decryption returned without throwing but MAC verification " +
						          	"failed, meaning returned plaintext was garbarge or ciphertext not authentic.");
			}
			return new PlainText(output);
		} catch (InvalidKeyException ike) {
			throw new EncryptionException("Decryption failure", "Must install unlimited strength crypto extension from Sun", ike);
		} catch (NoSuchAlgorithmException e) {
			throw new EncryptionException("Decryption failed", "Invalid algorithm for available JCE providers - " +
						ciphertext.getCipherTransformation() + ": " + e.getMessage(), e);
		} catch (NoSuchPaddingException e) {
			throw new EncryptionException("Decryption failed", "Invalid padding scheme (" +
						ciphertext.getPaddingScheme() + ") for cipher transformation " + ciphertext.getCipherTransformation() +
						": " + e.getMessage(), e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new EncryptionException("Decryption failed", "Decryption problem: " + e.getMessage(), e);
		} catch (IllegalBlockSizeException e) {
			throw new EncryptionException("Decryption failed", "Decryption problem: " + e.getMessage(), e);
		} catch (BadPaddingException e) {
			boolean success = ciphertext.validateMAC( authKey );
			if ( success ) {
				throw new EncryptionException("Decryption failed", "Decryption problem: " + e.getMessage(), e);
			} else {
				throw new EncryptionException("Decryption failed",
						"Decryption problem: WARNING: Adversary may have tampered with " +
						"CipherText object orCipherText object mangled in transit: " + e.getMessage(), e);
		}
	}
	}

	/**
	* {@inheritDoc}
	*/
	public String sign(String data) throws EncryptionException {
		try {
			Signature signer = Signature.getInstance(signatureAlgorithm);
			signer.initSign(privateKey);
			signer.update(data.getBytes(encoding));
			byte[] bytes = signer.sign();
			return ESAPI.encoder().encodeForBase64(bytes, false);
		} catch (InvalidKeyException ike) {
			throw new EncryptionException("Encryption failure", "Must install unlimited strength crypto extension from Sun", ike);
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
			signer.update(data.getBytes(encoding));
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
			String random = ESAPI.randomizer().getRandomString(10, EncoderConstants.CHAR_ALPHANUMERICS);
			String plaintext = expiration + ":" + random + ":" + data;
			// add integrity check
			String sig = this.sign( plaintext );
			String ciphertext = this.encrypt( plaintext + ":" + sig );
			return ciphertext;
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

			String[] parts = plaintext.split(":");
			if (parts.length != 4) {
				throw new EncryptionException("Invalid seal", "Seal was not formatted properly");
			}
	
			String timestring = parts[0];
			long now = new Date().getTime();
			long expiration = Long.parseLong(timestring);
			if (now > expiration) {
				throw new EncryptionException("Invalid seal", "Seal expiration date has expired");
			}
			String random = parts[1];
			String data = parts[2];
			String sig = parts[3];
			if (!this.verifySignature(sig, timestring + ":" + random + ":" + data ) ) {
				throw new EncryptionException("Invalid seal", "Seal integrity check failed");
			}	
			return data;
		} catch (EncryptionException e) {
			throw e;
		} catch (Exception e) {
			throw new EncryptionException("Invalid seal", "Invalid seal:" + e.getMessage(), e);
		}
	}

	
	/**
	* {@inheritDoc}
	*/
	public boolean verifySeal( String seal ) {
		try {
			unseal( seal );
			return true;
		} catch( EncryptionException e ) {
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

	// DISCUSS: Why experimental? Would have to be added to Encryptor interface
	//			but only 3 things I saw wrong with this was 1) it used HMacMD5 instead
	//			of HMacSHA1 (see discussion below), 2) that the HMac key is the
	//			same one used for encryption (also see comments), and 3) it caught
	//			overly broad exceptions. Here it is with these specific areas
	//			addressed, bu not unit testing has been done at this point. -kww
   /**
    * Compute an HMAC for a String.  Experimental.
    * @param input	The input for which to compute the HMac.
    */
/********************
	public String computeHMAC( String input ) throws EncryptionException {
		try {
			Mac hmac = Mac.getInstance("HMacSHA1"); // DISCUSS: Changed to HMacSHA1. MD5 *badly* broken
												   //          SHA1 should really be avoided, but using
												   //		   for HMAC-SHA1 is acceptable for now. Plan
												   //		   to migrate to SHA-256 or NIST replacement for
												   //		   SHA1 in not too distant future.
			// DISCUSS: Also not recommended that the HMac key is the same as the one
			//			used for encryption (namely, Encryptor.MasterKey). If anything it
			//			would be better to use Encryptor.MasterSalt for the HMac key, or
			//			perhaps a derived key based on the master salt. (One could use
			//			CryptoHelper.computeDerivedKey().)
			//
			byte[] salt = ESAPI.securityConfiguration().getMasterSalt();
			hmac.init( new SecretKeySpec(salt, "HMacSHA1") );	// Was:	hmac.init(secretKeySpec)	
			byte[] inBytes;
			try {
				inBytes = input.getBytes("UTF-8");
			} catch (UnsupportedEncodingException e) {
				logger.warning(Logger.SECURITY_FAILURE, "computeHMAC(): Can't find UTF-8 encoding; using default encoding", e);
				inBytes = input.getBytes();
			}
			byte[] bytes = hmac.doFinal( inBytes );
			return ESAPI.encoder().encodeForBase64(bytes, false);
		} catch (InvalidKeyException ike) {
			throw new EncryptionException("Encryption failure", "Must install unlimited strength crypto extension from Sun", ike);
	    } catch (NoSuchAlgorithmException e) {
	    	throw new EncryptionException("Could not compute HMAC", "Can't find HMacSHA1 algorithm. " +
	    															"Problem computing HMAC for " + input, e );
	    }
	}
********************/
}
