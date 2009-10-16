package org.owasp.esapi.reference;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.errors.EncryptionException;

/**
 * Crypto functionality from OWSAP ESAPI 1.4 kept <i>temporarily</i> for
 * compatibility reasons. Most of the methods in this class are, or soon will
 * be, deprecated. They are meant only as a transition aid to ESAPI 2.0.
 * The corresponding ESAPI 2.0 methods, which are in the class
 * {@code org.owasp.esapi.reference.JavaEncryptor} provide more secure
 * methods. However, the cryptographic cipher modes used here (ECB) is seriously
 * flawed for most general purpose use and should be avoided whenever possible.
 * <p>
 * Generally, if this class is going to be used, it should be used by setting
 * the property {@code ESAPI.Encryptor} to the value
 * {@code org.owasp.esapi.reference.LegacyJavaEncryptor} in the Java properties
 * file, {@code ESAPI.properties}.
 * </p><p>
 * See the reference
 * <a href="http://www.owasp.org/ESAPI_2.0_ReleaseNotes_CryptoChanges.html">
 * "Why Is OWASP Changing ESAPI Encryption?"</a>
 * for further details.
 * </p>
 * @author kevin.w.wall@gmail.com
 * @see org.owasp.esapi.reference.JavaEncryptor
 * @since 2.0
 */
public final class LegacyJavaEncryptor extends JavaEncryptor {
	
	private static Logger logger = ESAPI.getLogger("LegacyJavaEncryptor");
	private static int encryptCounter = 0;
	private static int decryptCounter = 0;
		// DISCUSS: OK to leave the property for this undocumented?
		//		    The desire is to persuade people to move away from this,
		//			so perhaps the annoyance factor of not being able to
		//			change it will help. For now, just get this from
		//			system properties rather than from ESAPI.properties.
		//			NOTE: The major reason I put it here is so I could more
		//				  easily unit test this. -kevin wall
	private static int logEveryNthUse = 25;
	
	static {
		try {
			logEveryNthUse =
				Integer.parseInt(
				    System.getProperty("ESAPI.Encryptor.legacy.warnEveryNthUse",
				    		           "25")
				);
		} catch(NumberFormatException ex) {
			// Just ignore it and silently set it to 25. If they screw this up
			// they should consider themselves lucky that we don't throw an
			// ExceptionInInitializerError and crash their application.
			logEveryNthUse = 25;	
		}
	}
	
	/**
     * CTOR for {@code LegacyJavaEncryptor}. Simply calls the default constructor
     * of the base class, {@code JavaEncryptor}.
     * 
     * @throws EncryptionException if can't construct this object for some reason.
     * 					Original exception will be attached as the 'cause'.
     */
    public LegacyJavaEncryptor() throws EncryptionException {
    	super();
    }

	/**
	 * Compatibility method with ESAPI 1.4 which encrypts the provided plaintext
	 * using Electronic Code Book (ECB) cipher mode and returns a ciphertext
	 * string.
	 * </p><p>
	 * This method uses the cryptographically weak ECB cipher mode to encrypt,
	 * which for general encryption is not secure and generally should be
	 * avoided. The major weakness of ECB mode is that the encryption of
	 * identical plaintext blocks result in identical ciphertext blocks. This is
	 * a serious weakness especially in the cases where the original plaintext
	 * source is a "low entropy" source such as credit card numbers, bank
	 * account numbers, or social security numbers. Use of ECB mode, when
	 * naively used alone, can result in block replay attacks. Finally, this
	 * method also provides no data integrity or authenticity of the encrypted
	 * data.
	 * </p><p>
	 * This method is provided only for backward compatibility with ESAPI
	 * Java 1.4 code and earlier. You should stop using this method an use
	 * the newer encryption method (see deprecation warning) as soon as possible.
	 * </p><p>
	 * This method will likely be removed in some future ESAPI Java release.
	 * 
	 * @param plaintext
	 *      the plaintext String to encrypt
	 * 
	 * @return 
	 * 		the encrypted, base64-encoded String representation of 'plaintext'
	 * 
	 * @throws EncryptionException
	 *      if the specified encryption algorithm could not be found or another problem exists with 
	 *      the encryption of 'plaintext'
	 * 
	 * @see org.owasp.esapi.reference.JavaEncryptor#encrypt(String)
	 * 
	 * @deprecated As of ESAPI 2.0, replaced by {@link JavaEncryptor#encrypt(String)}
	 */
    @Override
	@Deprecated public String encrypt(String plaintext) throws EncryptionException {
    	logWarning("encrypt", "Deprecated and insecure encrypt() method called" +
    						  "; replace with new JavaEncryptor.encrypt() methods ASAP.");
		try {
			// Note - Cipher is not thread-safe so we create one locally
			Cipher encrypter = Cipher.getInstance(encryptAlgorithm);
			encrypter.init(Cipher.ENCRYPT_MODE, secretKeySpec);
			byte[] output = plaintext.getBytes(encoding);
			byte[] enc = encrypter.doFinal(output);
			return ESAPI.encoder().encodeForBase64(enc,false);
		} catch (InvalidKeyException ike) {
			throw new EncryptionException("Encryption failure", "Key size is: " + encryptionKeyLength +
					    ". Keys longer than 128-bits require Sun's JCE Unlimited Strength Jurisdiction " +
						"Policy files to be downloaded and installed.", ike);
		} catch (Exception e) {
			throw new EncryptionException("Encryption failure", "Encryption problem: " + e.getMessage(), e);
		}
	}

	/**
	 * Decrypts the provided ciphertext string that was encrypted using
	 * Electronic Code Book (ECB) mode using the {@link #encrypt(String)}
	 * method and returns a plaintext string.
	 * </p><p>
	 * This is the decryption method that corresponds to the deprecated
	 * {@link #encrypt(String)} method. It should only be used if you cannot
	 * remove references to this deprecated encryption method. This method
	 * expects ciphertext that was encrypted using the Electronic Code Book
	 * (ECB) cipher mode which in the general case is not secure and should be
	 * avoided. As such, ECB also provides no data integrity or authenticity of
	 * the encrypted data.
	 * </p><p>
	 * This method is provided only for backward compatibility with ESAPI
	 * Java 1.4 code and earlier. You should stop using this method an use
	 * the newer encryption method (see deprecation warning) as soon as possible.
	 * </p><p>
	 * This method will likely be removed in some future ESAPI Java release.
	 * </p><p>
	 * This method is provided only for backward compatibility with ESAPI
	 * Java 1.4 code and earlier. You should stop using these deprecated
	 * encryption / decryption methods an use the newer encryption / 
	 * decryption methods (see deprecation warning) as soon as possible.
	 * </p><p>
	 * This method will likely be removed in some future ESAPI Java release.
	 * 
	 * @param ciphertext
	 *      the ciphertext (encrypted plaintext)
	 * 
	 * @return 
	 * 		the decrypted ciphertext
	 * 
	 * @throws EncryptionException
	 *      if the specified encryption algorithm could not be found or another problem exists with 
	 *      the decryption of 'plaintext'
	 * 
	 * @see org.owasp.esapi.reference.JavaEncryptor#decrypt(String)
	 * 
	 * @deprecated As of ESAPI 2.0, replaced by {@link JavaEncryptor#decrypt(String)}
	 */
    @Override
	@Deprecated public String decrypt(String ciphertext) throws EncryptionException {
    	logWarning("decrypt", "Deprecated decrypt() method called");
		try {
			// Note - Cipher is not thread-safe so we create one locally
			Cipher decrypter = Cipher.getInstance(encryptAlgorithm);
			decrypter.init(Cipher.DECRYPT_MODE, secretKeySpec);
			byte[] dec = ESAPI.encoder().decodeFromBase64(ciphertext);
			byte[] output = decrypter.doFinal(dec);
			return new String(output, encoding);
		} catch (InvalidKeyException ike) {
			throw new EncryptionException("Decryption failure", "Must install unlimited strength crypto extension from Sun", ike);
		} catch (NoSuchAlgorithmException e) {
			throw new EncryptionException("Decryption failed", "Decryption problem - unknown algorithm: " + e.getMessage(), e);
		} catch (NoSuchPaddingException e) {
			// Shouldn't happen; this deprecated method does not use padding.
			throw new EncryptionException("Decryption failed", "Decryption problem - unknown padding: " + e.getMessage(), e);
		} catch (IOException e) {
			throw new EncryptionException("Decryption failed", "Decryption problem: " + e.getMessage(), e);
		} catch (IllegalBlockSizeException e) {
			throw new EncryptionException("Decryption failed", "Decryption problem - invalid block size: " + e.getMessage(), e);
		} catch (BadPaddingException e) {
			// This could happen though, BECAUSE padding is not used.
			throw new EncryptionException("Decryption failed", "Decryption padding problem: " + e.getMessage(), e);
		}
/*		
	 	Shame on you! Don't you read your own advisories! ;-)
	 			See		http://www.owasp.org/index.php/Overly-Broad_Catch_Block
	 	OK for JUnit tests, but not production code.
		} catch (Exception e) {
			throw new EncryptionException("Decryption failed", "Decryption problem: " + e.getMessage(), e);
		}
*/
	}

    /**
     * Log a security warning every Nth time one of the deprecated encrypt or
     * decrypt methods are called. ('N' is hard-coded to be 25 by default, but
     * may be changed via the system property
     * {@code ESAPI.Encryptor.legacy.warnEveryNthUse}.) In other words, we nag
     * them until the give in and change it. ;-)
     * 
     * @param where	The string "encrypt" or "decrypt", corresponding to the
     * 				method that is being logged.
     * @param msg	The message to log.
     */
    private void logWarning(String where, String msg) {
    	int counter = 0;
    	if ( where.equals("encrypt") ) {
    		counter = encryptCounter++;
    		where = "LegacyJavaEncryptor.encrypt(): [count=" + counter +"]";
    	} else if ( where.equals("decrypt") ) {
    		counter = decryptCounter++;
    		where = "LegacyJavaEncryptor.decrypt(): [count=" + counter +"]";
    	} else {
    		where = "LegacyJavaEncryptor: Unknown method: ";
    	}
    	// We log the very first time (note the use of post-increment on the
    	// counters) and then every Nth time thereafter. Logging every single
    	// time is likely to be way too much logging.
    	if ( (counter % logEveryNthUse) == 0 ) {
        	logger.warning(Logger.SECURITY_FAILURE, where + msg);
    	}
    }
}
