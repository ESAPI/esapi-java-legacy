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
 * @author kevin.w.wall@gmail.com
 * @created 2007
 */
package org.owasp.esapi.reference.crypto;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.EncoderConstants;
import org.owasp.esapi.Encryptor;
import org.owasp.esapi.Logger;
import org.owasp.esapi.codecs.Hex;
import org.owasp.esapi.crypto.CipherSpec;
import org.owasp.esapi.crypto.CipherText;
import org.owasp.esapi.crypto.CryptoHelper;
import org.owasp.esapi.crypto.KeyDerivationFunction;
import org.owasp.esapi.crypto.PlainText;
import org.owasp.esapi.crypto.SecurityProviderLoader;
import org.owasp.esapi.errors.ConfigurationException;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.IntegrityException;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;

/**
 * Reference implementation of the {@code Encryptor} interface. This implementation
 * layers on the JCE provided cryptographic package. Algorithms used are
 * configurable in the {@code ESAPI.properties} file. The main property
 * controlling the selection of this class is {@code ESAPI.Encryptor}. Most of
 * the other encryption related properties have property names that start with
 * the string "Encryptor.".
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author kevin.w.wall@gmail.com
 * @author Chris Schmidt (chrisisbeef .at. gmail.com)
 * @since June 1, 2007; some methods since ESAPI Java 2.0
 * @see org.owasp.esapi.Encryptor
 */
public final class JavaEncryptor implements Encryptor {
    private static volatile Encryptor singletonInstance;

    // Note: This double-check pattern only works because singletonInstance
    //       is declared to be volatile.  Usually this method is called
    //       via ESAPI.encryptor() rather than directly.
    public static Encryptor getInstance() throws EncryptionException {
        if ( singletonInstance == null ) {
            synchronized ( JavaEncryptor.class ) {
                if ( singletonInstance == null ) {
                    singletonInstance = new JavaEncryptor();
                }
            }
        }
        return singletonInstance;
    }

    private static boolean initialized = false;
    
    // encryption
    private static SecretKeySpec secretKeySpec = null; // DISCUSS: Why static? Implies one key?!?
    private static String encryptAlgorithm = "AES";
    private static String encoding = "UTF-8"; 
    private static int encryptionKeyLength = 128;
    
    // digital signatures
    private static PrivateKey privateKey = null;
	private static PublicKey publicKey = null;
	private static String signatureAlgorithm = "SHA1withDSA";
    private static String randomAlgorithm = "SHA1PRNG";
	private static int signatureKeyLength = 1024;
	
	// hashing
	private static String hashAlgorithm = "SHA-512";
	private static int hashIterations = 1024;
	
	// Logging - DISCUSS: This "sticks" us with a specific logger to whatever it was when
	//					  this class is first loaded. Is this a big limitation? Since there
	//                    is no method to reset it, we may has well make it 'final' also.
	private static Logger logger = ESAPI.getLogger("JavaEncryptor");
	    // Used to print out warnings about deprecated methods.
	private static int encryptCounter = 0;
	private static int decryptCounter = 0;
        // DISCUSS: OK to not have a property for this to set the frequency?
        //          The desire is to persuade people to move away from these
	    //          two deprecated encrypt(String) / decrypt(String) methods,
        //          so perhaps the annoyance factor of not being able to
        //          change it will help. For now, it is just hard-coded here.
        //          We could be mean and just print a warning *every* time.
	private static final int logEveryNthUse = 25;
	
    // *Only* use this string for user messages for EncryptionException when
    // decryption fails. This is to prevent information leakage that may be
    // valuable in various forms of ciphertext attacks, such as the
	// Padded Oracle attack described by Rizzo and Duong.
    private static final String DECRYPTION_FAILED =
        "Decryption failed; see logs for details.";

    // # of seconds that all failed decryption attempts will take. Used to
    // help prevent side-channel timing attacks.
    private static int N_SECS = 2;

	// Load the preferred JCE provider if one has been specified.
	static {
	    try {
            SecurityProviderLoader.loadESAPIPreferredJCEProvider();
        } catch (NoSuchProviderException ex) {
        	// Note that audit logging is done elsewhere in called method.
            logger.fatal(Logger.SECURITY_FAILURE,
                         "JavaEncryptor failed to load preferred JCE provider.", ex);
            throw new ExceptionInInitializerError(ex);
        }
        setupAlgorithms();
	}
	
    /**
     * Generates a new strongly random secret key and salt that can be
     * copy and pasted in the <b>ESAPI.properties</b> file.
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
	            System.out.println("===== Provider " + i + ":" + providers[i].getName() + " ======");
				Iterator<Object> it = providers[i].keySet().iterator();
				while (it.hasNext()) {
					String key = (String)it.next();
		            String value = providers[i].getProperty( key );
		            tm.put(key, value);
	                System.out.println("\t\t   " + key + " -> "+ value );
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
        System.out.println( eol + "Copy and paste these lines into your ESAPI.properties" + eol);
        System.out.println( "#==============================================================");
        System.out.println( "Encryptor.MasterKey=" + ESAPI.encoder().encodeForBase64(raw, false) );
        System.out.println( "Encryptor.MasterSalt=" + ESAPI.encoder().encodeForBase64(salt, false) );
        System.out.println( "#==============================================================" + eol);
    }
	
    
    /**
     * Private CTOR for {@code JavaEncryptor}, called by {@code getInstance()}.
     * @throws EncryptionException if can't construct this object for some reason.
     * 					Original exception will be attached as the 'cause'.
     */
    private JavaEncryptor() throws EncryptionException {
        byte[] salt = ESAPI.securityConfiguration().getMasterSalt();
        byte[] skey = ESAPI.securityConfiguration().getMasterKey();

        assert salt != null : "Can't obtain master salt, Encryptor.MasterSalt";
        assert salt.length >= 16 : "Encryptor.MasterSalt must be at least 16 bytes. " +
                                   "Length is: " + salt.length + " bytes.";
        assert skey != null : "Can't obtain master key, Encryptor.MasterKey";
        assert skey.length >= 7 : "Encryptor.MasterKey must be at least 7 bytes. " +
                                  "Length is: " + skey.length + " bytes.";
        
        // Set up secretKeySpec for use for symmetric encryption and decryption,
        // and set up the public/private keys for asymmetric encryption /
        // decryption.
        // TODO: Note: If we dump ESAPI 1.4 crypto backward compatibility,
        //       then we probably will ditch the Encryptor.EncryptionAlgorithm
        //       property. If so, encryptAlgorithm should probably use
        //       Encryptor.CipherTransformation and just pull off the cipher
        //       algorithm name so we can use it here.
        synchronized(JavaEncryptor.class) {
            if ( ! initialized ) {
                //
                // For symmetric encryption
                //
                //      NOTE: FindBugs complains about this
                //            (ST_WRITE_TO_STATIC_FROM_INSTANCE_METHOD) but
                //            it should be OK since it is synchronized and only
                //            done once. While we could separate this out and
                //            handle in a static initializer, it just seems to
                //            fit better here.
                secretKeySpec = new SecretKeySpec(skey, encryptAlgorithm );
                
                //
                // For asymmetric encryption (i.e., public/private key)
                //
                try {
                    SecureRandom prng = SecureRandom.getInstance(randomAlgorithm);

                    // Because hash() is not static (but it could be were in not
                    // for the interface method specification in Encryptor), we
                    // cannot do this initialization in a static method or static
                    // initializer.
                    byte[] seed = hash(new String(skey, encoding),new String(salt, encoding)).getBytes(encoding);
                    prng.setSeed(seed);
                    initKeyPair(prng);
                } catch (Exception e) {
                    throw new EncryptionException("Encryption failure", "Error creating Encryptor", e);
                }             
                
                // Mark everything as initialized.
                initialized = true;
            }
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
	@Deprecated public String encrypt(String plaintext) throws EncryptionException
	{
        logWarning("encrypt", "Calling deprecated encrypt() method.");
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
             String[] parts = xform.split("/");
             assert parts.length == 3 : "Malformed cipher transformation: " + xform;
             String cipherMode = parts[1];
             
             // This way we can prevent modes like OFB and CFB where the IV should never
             // be repeated with the same encryption key (at least until we support
             // Encryptor.ChooseIVMethod=specified and allow us to specify some mechanism
             // to ensure the IV will never be repeated (such as a time stamp or other
             // monotonically increasing function).
             // DISCUSS: Should we include the permitted cipher modes in the exception msg?
             if ( ! CryptoHelper.isAllowedCipherMode(cipherMode) ) {
                 throw new EncryptionException("Encryption failure: invalid cipher mode ( " + cipherMode + ") for encryption",
                             "Encryption failure: Cipher transformation " + xform + " specifies invalid " +
                             "cipher mode " + cipherMode);
             }
             
			 // Note - Cipher is not thread-safe so we create one locally
			 //        Also, we need to change this eventually so other algorithms can
			 //        be supported. Eventually, there will be an encrypt() method that
			 //        takes a (new class) CryptoControls, as something like this:
			 //          public CipherText encrypt(CryptoControls ctrl, SecretKey skey, PlainText plaintext)
			 //        and this method will just call that one.
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
			 // DISCUSS: Reconsider these warnings. If thousands of encryptions are done in tight loop, no one needs
			 //          more than 1 warning. Should we do something more intelligent here?
			 if ( keySize < keyLen ) {
				 // ESAPI.EncryptionKeyLength defaults to 128, but that means that we could not use DES (as weak as it
				 // is), even for legacy code. Therefore, this has been changed to simple log a warning rather than
				 //	throw the following exception.
				 //				 throw new ConfigurationException("Actual key size of " + keySize + " bits smaller than specified " +
				 //						  "encryption key length (ESAPI.EncryptionKeyLength) of " + keyLen + " bits.");
				 logger.warning(Logger.SECURITY_FAILURE, "Actual key size of " + keySize + " bits SMALLER THAN specified " +
						 "encryption key length (ESAPI.EncryptionKeyLength) of " + keyLen + " bits with cipher algorithm " + cipherAlg);
			 }
			 if ( keySize < 112 ) {		// NIST Special Pub 800-57 considers 112-bits to be the minimally safe key size from 2010-2030.
				 						// Note that 112 bits 'just happens' to be size of 2-key Triple DES!
				 logger.warning(Logger.SECURITY_FAILURE, "Potentially unsecure encryption. Key size of " + keySize + "bits " +
				                "not sufficiently long for " + cipherAlg + ". Should use appropriate algorithm with key size " +
				                "of *at least* 112 bits except when required by legacy apps. See NIST Special Pub 800-57.");
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
			 
             // Using cipher mode that supports *both* confidentiality *and* authenticity? If so, then
             // use the specified SecretKey as-is rather than computing a derived key from it. We also
             // don't expect a separate MAC in the specified CipherText object so therefore don't try
             // to validate it.
             boolean preferredCipherMode = CryptoHelper.isCombinedCipherMode( cipherMode );
             SecretKey encKey = null;
			 if ( preferredCipherMode ) {
			     encKey = key;
			 } else {
			     encKey = computeDerivedKey(KeyDerivationFunction.kdfVersion, getDefaultPRF(),
			    		 				    key, keySize, "encryption");
			 }
			 
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
                 // Convert to CipherText.
             CipherText ciphertext = new CipherText(cipherSpec, raw);
			 
			 // If we are using a "preferred" cipher mode--i.e., one that supports *both* confidentiality and
			 // authenticity, there is no point to store a separate MAC in the CipherText object. Thus we only
             // do this when we are not using such a cipher mode.
			 if ( !preferredCipherMode ) {
			     // Compute derived key, and then use it to compute and store separate MAC in CipherText object.
			     SecretKey authKey = computeDerivedKey(KeyDerivationFunction.kdfVersion, getDefaultPRF(),
			    		 							   key, keySize, "authenticity");
			     ciphertext.computeAndStoreMAC(  authKey );
			 }
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
			 throw new EncryptionException("Encryption failure (unavailable cipher requested)",
					 "Encryption problem: specified algorithm in cipher xform " + xform + " not available: " + e.getMessage(), e);
		 } catch (NoSuchPaddingException e) {
			 throw new EncryptionException("Encryption failure (unavailable padding scheme requested)",
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
	 @Deprecated public String decrypt(String b64IVCiphertext) throws EncryptionException
	 {
	     logWarning("decrypt", "Calling deprecated decrypt() method.");
		 CipherText ct = null;
		 try {
			 // We assume that the default cipher transform was used to encrypt this.
			 ct = new CipherText();

			 // Need to base64 decode the IV+ciphertext and extract the IV to set it in CipherText object.
			 byte[] ivPlusRawCipherText = ESAPI.encoder().decodeFromBase64(b64IVCiphertext);
			 int blockSize = ct.getBlockSize();	// Size in bytes.
			 byte[] iv = new byte[ blockSize ];
			 CryptoHelper.copyByteArray(ivPlusRawCipherText, iv, blockSize);	// Copy the first blockSize bytes into iv array
			 int cipherTextSize = ivPlusRawCipherText.length - blockSize;
			 byte[] rawCipherText = new byte[ cipherTextSize ];
			 System.arraycopy(ivPlusRawCipherText, blockSize, rawCipherText, 0, cipherTextSize);
			 ct.setIVandCiphertext(iv, rawCipherText);

			 // Now the CipherText object should be prepared to use it to decrypt.
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
	public PlainText decrypt(SecretKey key, CipherText ciphertext)
	    throws EncryptionException, IllegalArgumentException
	{
	    long start = System.nanoTime();  // Current time in nanosecs; used to prevent timing attacks
	    if ( key == null ) {
	        throw new IllegalArgumentException("SecretKey arg may not be null");
	    }
	    if ( ciphertext == null ) {
	        throw new IllegalArgumentException("Ciphertext may arg not be null");
	    }

	    if ( ! CryptoHelper.isAllowedCipherMode(ciphertext.getCipherMode()) ) {
	        // This really should be an illegal argument exception, but it could
	        // mean that a partner encrypted something using a cipher mode that
	        // you do not accept, so it's a bit more complex than that. Also
	        // throwing an IllegalArgumentException doesn't allow us to provide
	        // the two separate error messages or automatically log it.
	        throw new EncryptionException(DECRYPTION_FAILED,
	                "Invalid cipher mode " + ciphertext.getCipherMode() +
	        " not permitted for decryption or encryption operations.");
	    }
	    logger.debug(Logger.EVENT_SUCCESS,
	            "Args valid for JavaEncryptor.decrypt(SecretKey,CipherText): " +
	            ciphertext);

	    PlainText plaintext = null;
	    boolean caughtException = false;
	    int progressMark = 0;
	    try {
	        // First we validate the MAC.
	        boolean valid = CryptoHelper.isCipherTextMACvalid(key, ciphertext);
	        if ( !valid ) {
	            try {
	                // This is going to fail, but we want the same processing
	                // to occur as much as possible so as to prevent timing
	                // attacks. We _could_ just be satisfied by the additional
	                // sleep in the 'finally' clause, but an attacker on the
	                // same server who can run something like 'ps' can tell
	                // CPU time versus when the process is sleeping. Hence we
	                // try to make this as close as possible. Since we know
	                // it is going to fail, we ignore the result and ignore
	                // the (expected) exception.
	                handleDecryption(key, ciphertext); // Ignore return (should fail).
	            } catch(Exception ex) {
	                ;   // Ignore
	            }
	            throw new EncryptionException(DECRYPTION_FAILED,
	                    "Decryption failed because MAC invalid for " +
	                    ciphertext);
	        }
	        progressMark++;
	        // The decryption only counts if the MAC was valid.
	        plaintext = handleDecryption(key, ciphertext);
	        progressMark++;
	    } catch(EncryptionException ex) {
	        caughtException = true;
	        String logMsg = null;
	        switch( progressMark ) {
	        case 1:
	            logMsg = "Decryption failed because MAC invalid. See logged exception for details.";
	            break;
	        case 2:
	            logMsg = "Decryption failed because handleDecryption() failed. See logged exception for details.";
	            break;
	        default:
	            logMsg = "Programming error: unexpected progress mark == " + progressMark;
	        break;
	        }
	        logger.error(Logger.SECURITY_FAILURE, logMsg);
	        throw ex;           // Re-throw
	    }
	    finally {
	        if ( caughtException ) {
	            // The rest of this code is to try to account for any minute differences
	            // in the time it might take for the various reasons that decryption fails
	            // in order to prevent any other possible timing attacks. Perhaps it is
	            // going overboard. If nothing else, if N_SECS is large enough, it might
	            // deter attempted repeated attacks by making them take much longer.
	            long now = System.nanoTime();
	            long elapsed = now - start;
	            final long NANOSECS_IN_SEC = 1000000000L; // nanosec is 10**-9 sec
	            long nSecs = N_SECS * NANOSECS_IN_SEC;  // N seconds in nano seconds
	            if ( elapsed < nSecs ) {
	                // Want to sleep so total time taken is N seconds.
	                long extraSleep = nSecs - elapsed;

	                // 'extraSleep' is in nanoseconds. Need to convert to a millisec
	                // part and nanosec part. Nanosec is 10**-9, millsec is
	                // 10**-3, so divide by (10**-9 / 10**-3), or 10**6 to
	                // convert to from nanoseconds to milliseconds.
	                long millis = extraSleep / 1000000L;
	                long nanos  = (extraSleep - (millis * 1000000L));
	                assert nanos >= 0 && nanos <= Integer.MAX_VALUE :
                            "Nanosecs out of bounds; nanos = " + nanos;
	                try {
	                    Thread.sleep(millis, (int)nanos);
	                } catch(InterruptedException ex) {
	                    ;   // Ignore
	                }
	            } // Else ... time already exceeds N_SECS sec, so do not sleep.
	        }
	    }
	    return plaintext;
	}

    // Handle the actual decryption portion. At this point it is assumed that
    // any MAC has already been validated. (But see "DISCUSS" issue, below.)
    private PlainText handleDecryption(SecretKey key, CipherText ciphertext)
        throws EncryptionException
    {
        int keySize = 0;
        try {
            Cipher decrypter = Cipher.getInstance(ciphertext.getCipherTransformation());
            keySize = key.getEncoded().length * 8;  // Convert to # bits

            // Using cipher mode that supports *both* confidentiality *and* authenticity? If so, then
            // use the specified SecretKey as-is rather than computing a derived key from it. We also
            // don't expect a separate MAC in the specified CipherText object so therefore don't try
            // to validate it.
            boolean preferredCipherMode = CryptoHelper.isCombinedCipherMode( ciphertext.getCipherMode() );
            SecretKey encKey = null;
            if ( preferredCipherMode ) {
                encKey = key;
            } else {
                // TODO: PERFORMANCE: Calculate avg time this takes and consider caching for very short interval
                //       (e.g., 2 to 5 sec tops). Otherwise doing lots of encryptions in a loop could take a LOT longer.
                //       But remember Jon Bentley's "Rule #1 on performance: First make it right, then make it fast."
            	//		 This would be a security trade-off as it would leave keys in memory a bit longer, so it
            	//		 should probably be off by default and controlled via a property.
                encKey = computeDerivedKey( ciphertext.getKDFVersion(), ciphertext.getKDF_PRF(),
                		                    key, keySize, "encryption");
            }
            if ( ciphertext.requiresIV() ) {
                decrypter.init(Cipher.DECRYPT_MODE, encKey, new IvParameterSpec(ciphertext.getIV()));
            } else {
                decrypter.init(Cipher.DECRYPT_MODE, encKey);
            }
            byte[] output = decrypter.doFinal(ciphertext.getRawCipherText());
            return new PlainText(output);

        } catch (InvalidKeyException ike) {
            throw new EncryptionException(DECRYPTION_FAILED, "Must install JCE Unlimited Strength Jurisdiction Policy Files from Sun", ike);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException(DECRYPTION_FAILED, "Invalid algorithm for available JCE providers - " +
                    ciphertext.getCipherTransformation() + ": " + e.getMessage(), e);
        } catch (NoSuchPaddingException e) {
            throw new EncryptionException(DECRYPTION_FAILED, "Invalid padding scheme (" +
                    ciphertext.getPaddingScheme() + ") for cipher transformation " + ciphertext.getCipherTransformation() +
                    ": " + e.getMessage(), e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new EncryptionException(DECRYPTION_FAILED, "Decryption problem: " + e.getMessage(), e);
        } catch (IllegalBlockSizeException e) {
            throw new EncryptionException(DECRYPTION_FAILED, "Decryption problem: " + e.getMessage(), e);
        } catch (BadPaddingException e) {
            //DISCUSS: This needs fixed. Already validated MAC in CryptoHelper.isCipherTextMACvalid() above.
            //So only way we could get a padding exception is if invalid padding were used originally by
            //the party doing the encryption. (This might happen with a buggy padding scheme for instance.)
            //It *seems* harmless though, so will leave it for now, and technically, we need to either catch it
            //or declare it in a throws class. Clearly we don't want to do the later. This should be discussed
            //during a code inspection.
            SecretKey authKey;
            try {
                authKey = computeDerivedKey( ciphertext.getKDFVersion(), ciphertext.getKDF_PRF(),
                		                     key, keySize, "authenticity");
            } catch (Exception e1) {
                throw new EncryptionException(DECRYPTION_FAILED,
                        "Decryption problem -- failed to compute derived key for authenticity: " + e1.getMessage(), e1);
            }
            boolean success = ciphertext.validateMAC( authKey );
            if ( success ) {
                throw new EncryptionException(DECRYPTION_FAILED, "Decryption problem: " + e.getMessage(), e);
            } else {
                throw new EncryptionException(DECRYPTION_FAILED,
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
		    // NOTE: EncryptionException constructed *only* for side-effect of causing logging.
		    // FindBugs complains about this and since it examines byte-code, there's no way to
		    // shut it up.
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
	    if ( data == null ) {
	        throw new IllegalArgumentException("Data to be sealed may not be null.");
	    }
	    
		try {
		    String b64data = null;
            try {
                b64data = ESAPI.encoder().encodeForBase64(data.getBytes("UTF-8"), false);
            } catch (UnsupportedEncodingException e) {
                ; // Ignore; should never happen since UTF-8 built into rt.jar
            }
			// mix in some random data so even identical data and timestamp produces different seals
			String nonce = ESAPI.randomizer().getRandomString(10, EncoderConstants.CHAR_ALPHANUMERICS);
			String plaintext = expiration + ":" + nonce + ":" + b64data;
			// add integrity check; signature is already base64 encoded.
			String sig = this.sign( plaintext );
			CipherText ciphertext = this.encrypt( new PlainText(plaintext + ":" + sig) );
			String sealedData = ESAPI.encoder().encodeForBase64(ciphertext.asPortableSerializedByteArray(), false);
			return sealedData;
		} catch( EncryptionException e ) {
			throw new IntegrityException( e.getUserMessage(), e.getLogMessage(), e );
		}
	}

	/**
	* {@inheritDoc}
	*/
	public String unseal(String seal) throws EncryptionException {
		PlainText plaintext = null;
		try {
		    byte[] encryptedBytes = ESAPI.encoder().decodeFromBase64(seal);
		    CipherText cipherText = null;
		    try {
		        cipherText = CipherText.fromPortableSerializedBytes(encryptedBytes);
		    } catch( AssertionError e) {
	            // Some of the tests in EncryptorTest.testVerifySeal() are examples of
		        // this if assertions are enabled.
		        throw new EncryptionException("Invalid seal",
	                                          "Seal passed garbarge data resulting in AssertionError: " + e);
	        }
			plaintext = this.decrypt(cipherText);

			String[] parts = plaintext.toString().split(":");
			if (parts.length != 4) {
				throw new EncryptionException("Invalid seal", "Seal was not formatted properly.");
			}
	
			String timestring = parts[0];
			long now = new Date().getTime();
			long expiration = Long.parseLong(timestring);
			if (now > expiration) {
				throw new EncryptionException("Invalid seal", "Seal expiration date of " + new Date(expiration) + " has past.");
			}
			String nonce = parts[1];
			String b64data = parts[2];
			String sig = parts[3];
			if (!this.verifySignature(sig, timestring + ":" + nonce + ":" + b64data ) ) {
				throw new EncryptionException("Invalid seal", "Seal integrity check failed");
			}	
			return new String(ESAPI.encoder().decodeFromBase64(b64data), "UTF-8");
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
	//			addressed, but no unit testing has been done at this point. -kww
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
			//			KeyDerivationFunction.computeDerivedKey().)
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

    /**
     * Log a security warning every Nth time one of the deprecated encrypt or
     * decrypt methods are called. ('N' is hard-coded to be 25 by default, but
     * may be changed via the system property
     * {@code ESAPI.Encryptor.warnEveryNthUse}.) In other words, we nag
     * them until the give in and change it. ;-)
     * 
     * @param where The string "encrypt" or "decrypt", corresponding to the
     *              method that is being logged.
     * @param msg   The message to log.
     */
    private void logWarning(String where, String msg) {
        int counter = 0;
        if ( where.equals("encrypt") ) {
            counter = encryptCounter++;
            where = "JavaEncryptor.encrypt(): [count=" + counter +"]";
        } else if ( where.equals("decrypt") ) {
            counter = decryptCounter++;
            where = "JavaEncryptor.decrypt(): [count=" + counter +"]";
        } else {
            where = "JavaEncryptor: Unknown method: ";
        }
        // We log the very first time (note the use of post-increment on the
        // counters) and then every Nth time thereafter. Logging every single
        // time is likely to be way too much logging.
        if ( (counter % logEveryNthUse) == 0 ) {
            logger.warning(Logger.SECURITY_FAILURE, where + msg);
        }
    }
    
    private KeyDerivationFunction.PRF_ALGORITHMS getPRF(String name) {    	
		String prfName = null;
		if ( name == null ) {
			prfName = ESAPI.securityConfiguration().getKDFPseudoRandomFunction();
		} else {
			prfName = name;
		}
		KeyDerivationFunction.PRF_ALGORITHMS prf = KeyDerivationFunction.convertNameToPRF(prfName);
		return prf;
    }
    
    private KeyDerivationFunction.PRF_ALGORITHMS getDefaultPRF() {
		String prfName = ESAPI.securityConfiguration().getKDFPseudoRandomFunction();
		return getPRF(prfName);
    }
    
    // Private interface to call ESAPI's KDF to get key for encryption or authenticity.
    private SecretKey computeDerivedKey(int kdfVersion, KeyDerivationFunction.PRF_ALGORITHMS prf,
    									SecretKey kdk, int keySize, String purpose)
    	throws NoSuchAlgorithmException, InvalidKeyException, EncryptionException
    {
    	// These really should be turned into actual runtime checks and an
    	// IllegalArgumentException should be thrown if they are violated.
    	// But this should be OK since this is a private method. Also, this method will
    	// be called quite often so assertions are a big win as they can be disabled or
    	// enabled at will.
    	assert prf != null : "Pseudo Random Function for KDF cannot be null";
    	assert kdk != null : "Key derivation key cannot be null.";
    	// We would choose a larger minimum key size, but we want to be
    	// able to accept DES for legacy encryption needs. NIST says 112-bits is min. If less than that,
    	// we print warning.
    	assert keySize >= 56 : "Key has size of " + keySize + ", which is less than minimum of 56-bits.";
    	assert (keySize % 8) == 0 : "Key size (" + keySize + ") must be a even multiple of 8-bits.";
    	assert purpose != null : "Purpose cannot be null. Should be 'encryption' or 'authenticity'.";
    	assert purpose.equals("encryption") || purpose.equals("authenticity") :
    		"Purpose must be \"encryption\" or \"authenticity\".";

    	KeyDerivationFunction kdf = new KeyDerivationFunction(prf);
    	if ( kdfVersion != 0 ) {
    		kdf.setVersion(kdfVersion);
    	}
    	return kdf.computeDerivedKey(kdk, keySize, purpose);
    }

    // Get all the algorithms we will be using from ESAPI.properties.
    private static void setupAlgorithms() {
        // setup algorithms
        encryptAlgorithm = ESAPI.securityConfiguration().getEncryptionAlgorithm();
        signatureAlgorithm = ESAPI.securityConfiguration().getDigitalSignatureAlgorithm();
        randomAlgorithm = ESAPI.securityConfiguration().getRandomAlgorithm();
        hashAlgorithm = ESAPI.securityConfiguration().getHashAlgorithm();
        hashIterations = ESAPI.securityConfiguration().getHashIterations();
        encoding = ESAPI.securityConfiguration().getCharacterEncoding();
        encryptionKeyLength = ESAPI.securityConfiguration().getEncryptionKeyLength();
        signatureKeyLength = ESAPI.securityConfiguration().getDigitalSignatureKeyLength();
    }
    
    // Set up signing key pair using the master password and salt. Called (once)
    // from the JavaEncryptor CTOR.
    private static void initKeyPair(SecureRandom prng) throws NoSuchAlgorithmException {
        String sigAlg = signatureAlgorithm.toLowerCase();
        if ( sigAlg.endsWith("withdsa") ) {
            //
            // Admittedly, this is a kludge. However for Sun JCE, even though
            // "SHA1withDSA" is a valid signature algorithm name, if one calls
            //      KeyPairGenerator kpg = KeyPairGenerator.getInstance("SHA1withDSA");
            // that will throw a NoSuchAlgorithmException with an exception
            // message of "SHA1withDSA KeyPairGenerator not available". Since
            // SHA1withDSA and DSA keys should be identical, we use "DSA"
            // in the case that SHA1withDSA or SHAwithDSA was specified. This is
            // all just to make these 2 work as expected. Sigh. (Note:
            // this was tested with JDK 1.6.0_21, but likely fails with earlier
            // versions of the JDK as well.)
            //
            sigAlg = "DSA";
        } else if ( sigAlg.endsWith("withrsa") ) {
            // Ditto for RSA.
            sigAlg = "RSA";
        }
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(sigAlg);
        keyGen.initialize(signatureKeyLength, prng);
        KeyPair pair = keyGen.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();
    }
}
