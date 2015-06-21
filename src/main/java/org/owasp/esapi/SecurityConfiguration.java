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
 * @author Mike Fauzy <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;

import org.owasp.esapi.configuration.EsapiPropertyLoader;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.regex.Pattern;

/**
 * The {@code SecurityConfiguration} interface stores all configuration information
 * that directs the behavior of the ESAPI implementation.
 * <br><br>
 * Protection of this configuration information is critical to the secure
 * operation of the application using the ESAPI. You should use operating system
 * access controls to limit access to wherever the configuration information is
 * stored.
 * <br><br>
 * Please note that adding another layer of encryption does not make the
 * attackers job much more difficult. Somewhere there must be a master "secret"
 * that is stored unencrypted on the application platform (unless you are
 * willing to prompt for some passphrase when you application starts or insert
 * a USB thumb drive or an HSM card, etc., in which case this master "secret"
 * it would only be in memory). Creating another layer of indirection provides
 * additional obfuscation, but doesn't provide any real additional security.
 * It's up to the reference implementation to decide whether this file should
 * be encrypted or not.
 * <br><br>
 * The ESAPI reference implementation (DefaultSecurityConfiguration.java) does
 * <i>not</i> encrypt its properties file.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface SecurityConfiguration extends EsapiPropertyLoader {

	/**
	 * Gets the application name, used for logging
	 * 
	 * @return the name of the current application
	 */
	@Deprecated
	public String getApplicationName();
	
	/**
	 * Returns the fully qualified classname of the ESAPI Logging implementation.
	 */
	@Deprecated
	public String getLogImplementation();
	
	/**
	 * Returns the fully qualified classname of the ESAPI Authentication implementation.
	 */
	@Deprecated
	public String getAuthenticationImplementation();
	
	/**
	 * Returns the fully qualified classname of the ESAPI Encoder implementation.
	 */
	@Deprecated
	public String getEncoderImplementation();
	
	/**
	 * Returns the fully qualified classname of the ESAPI Access Control implementation.
	 */
	@Deprecated
	public String getAccessControlImplementation();
	
	/**
	 * Returns the fully qualified classname of the ESAPI Intrusion Detection implementation.
	 */
	@Deprecated
	public String getIntrusionDetectionImplementation();
	
	/**
	 * Returns the fully qualified classname of the ESAPI Randomizer implementation.
	 */
	@Deprecated
	public String getRandomizerImplementation();
	
	/**
	 * Returns the fully qualified classname of the ESAPI Encryption implementation.
	 */
	@Deprecated
	public String getEncryptionImplementation();
	
	/**
	 * Returns the fully qualified classname of the ESAPI Validation implementation.
	 */
	@Deprecated
	public String getValidationImplementation();
	
	/**
	 * Returns the validation pattern for a particular type
	 * @param typeName
	 * @return the validation pattern
	 */
	@Deprecated
    public Pattern getValidationPattern( String typeName );
    
    /**
     * Determines whether ESAPI will accept "lenient" dates when attempt
     * to parse dates. Controlled by ESAPI property
     * {@code Validator.AcceptLenientDates}, which defaults to {@code false}
     * if unset.
     * 
     * @return True if lenient dates are accepted; false otherwise.
     * @see java.text.DateFormat#setLenient(boolean)
     */
	@Deprecated
    public boolean getLenientDatesAccepted();
	
	/**
	 * Returns the fully qualified classname of the ESAPI OS Execution implementation.
	 */
	@Deprecated
	public String getExecutorImplementation();
	
	/**
	 * Returns the fully qualified classname of the ESAPI HTTPUtilities implementation.
	 */
	@Deprecated
	public String getHTTPUtilitiesImplementation();
	
	/**
	 * Gets the master key. This password is used to encrypt/decrypt other files or types
	 * of data that need to be protected by your application.
	 * 
	 * @return the current master key
	 */
	@Deprecated
	public byte[] getMasterKey();

	/**
     * Retrieves the upload directory as specified in the ESAPI.properties file.
     * @return the upload directory
     */
	@Deprecated
    public File getUploadDirectory();
	
    /**
     * Retrieves the temp directory to use when uploading files, as specified in ESAPI.properties.
     * @return the temp directory
     */
	@Deprecated
    public File getUploadTempDirectory();

	/**
	 * Gets the key length to use in cryptographic operations declared in the ESAPI properties file.
	 * 
	 * @return the key length.
	 */
	@Deprecated
    public int getEncryptionKeyLength();
    
	/**
	 * Gets the master salt that is used to salt stored password hashes and any other location 
	 * where a salt is needed.
	 * 
	 * @return the current master salt
	 */
	@Deprecated
	public byte[] getMasterSalt();

	/**
	 * Gets the allowed executables to run with the Executor.
	 * 
	 * @return a list of the current allowed file extensions
	 */
	@Deprecated
	public List<String> getAllowedExecutables();

	/**
	 * Gets the allowed file extensions for files that are uploaded to this application.
	 * 
	 * @return a list of the current allowed file extensions
	 */
	@Deprecated
	public List<String> getAllowedFileExtensions();

	/**
	 * Gets the maximum allowed file upload size.
	 * 
	 * @return the current allowed file upload size
	 */
	@Deprecated
	public int getAllowedFileUploadSize();

	/**
	 * Gets the name of the password parameter used during user authentication.
	 * 
	 * @return the name of the password parameter
	 */
	@Deprecated
	public String getPasswordParameterName();

	/**
	 * Gets the name of the username parameter used during user authentication.
	 * 
	 * @return the name of the username parameter
	 */
	@Deprecated
	public String getUsernameParameterName();

	/**
	 * Gets the encryption algorithm used by ESAPI to protect data. This is
	 * mostly used for compatibility with ESAPI 1.4; ESAPI 2.0 prefers to
	 * use "cipher transformation" since it supports multiple cipher modes
	 * and padding schemes.
	 * 
	 * @return the current encryption algorithm
	 */
	@Deprecated
	public String getEncryptionAlgorithm();

	/**
	 * Retrieve the <i>cipher transformation</i>. In general, the cipher transformation
	 * is a specification of cipher algorithm, cipher mode, and padding scheme
	 * and in general, is a {@code String} that takes the following form:
	 * <pre>
	 * 		<i>cipher_alg</i>/<i>cipher_mode[bits]</i>/<i>padding_scheme</i>
	 * </pre>
	 * where <i>cipher_alg</i> is the JCE cipher algorithm (e.g., "DESede"),
	 * <i>cipher_mode</i> is the cipher mode (e.g., "CBC", "CFB", "CTR", etc.),
	 * and <i>padding_scheme</i> is the cipher padding scheme (e.g., "NONE" for
	 * no padding, "PKCS5Padding" for PKCS#5 padding, etc.) and where
	 * <i>[bits]</i> is an optional bit size that applies to certain cipher
	 * modes such as {@code CFB} and {@code OFB}. Using modes such as CFB and
	 * OFB, block ciphers can encrypt data in units smaller than the cipher's
	 * actual block size. When requesting such a mode, you may optionally
	 * specify the number of bits to be processed at a time. This generally must
	 * be an integral multiple of 8-bits so that it can specify a whole number
	 * of octets. 
	 * </p><p>
	 * Examples are:
	 * <pre>
	 * 		"AES/ECB/NoPadding"		// Default for ESAPI Java 1.4 (insecure)
	 * 		"AES/CBC/PKCS5Padding"	// Default for ESAPI Java 2.0
	 * 		"DESede/OFB32/PKCS5Padding"
	 * </pre>
	 * <b>NOTE:</b> Occasionally, in cryptographic literature, you may also
	 * see the key size (in bits) specified after the cipher algorithm in the
	 * cipher transformation. Generally, this is done to account for cipher
	 * algorithms that have variable key sizes. The Blowfish cipher for example
	 * supports key sizes from 32 to 448 bits. So for Blowfish, you might see
	 * a cipher transformation something like this:
	 * <pre>
	 * 		"Blowfish-192/CFB8/PKCS5Padding"
	 * </pre>
	 * in the cryptographic literature. It should be noted that the Java
	 * Cryptography Extensions (JCE) do not generally support this (at least
	 * not the reference JCE implementation of "SunJCE"), and therefore it
	 * should be avoided.
	 * @return	The cipher transformation.
	 */
	@Deprecated
    public String getCipherTransformation();
    
    /**
     * Set the cipher transformation. This allows a different cipher transformation
     * to be used without changing the {@code ESAPI.properties} file. For instance
     * you may normally want to use AES/CBC/PKCS5Padding, but have some legacy
     * encryption where you have ciphertext that was encrypted using 3DES.
     * 
     * @param cipherXform	The new cipher transformation. See
     * 						{@link #getCipherTransformation} for format. If
     * 						{@code null} is passed as the parameter, the cipher
     * 						transformation will be set to the the default taken
     * 						from the property {@code Encryptor.CipherTransformation}
     * 						in the {@code ESAPI.properties} file. <b>BEWARE:</b>
     * 						there is <b>NO</b> sanity checking here (other than
     * 						the empty string, and then, only if Java assertions are
     * 						enabled), so if you set this wrong, you will not get
     * 						any errors until you later try to use it to encrypt
     * 						or decrypt data.
     * @return	The previous cipher transformation is returned for convenience,
     * 			with the assumption that you may wish to restore it once you have
     * 			completed the encryption / decryption with the new cipher
     * 			transformation.
     * @deprecated To be replaced by new class in ESAPI 2.1, but here if you need it
     *          until then. Details of replacement forthcoming to ESAPI-Dev list.
     */
    @Deprecated
    public String setCipherTransformation(String cipherXform);

    /**
     * Retrieve the <i>preferred</i> JCE provider for ESAPI and your application.
     * ESAPI 2.0 now allows setting the property
     * {@code Encryptor.PreferredJCEProvider} in the
     * {@code ESAPI.properties} file, which will cause the specified JCE
     * provider to be automatically and dynamically loaded (assuming that
     * {@code SecurityManager} permissions allow) as the Ii>preferred</i>
     * JCE provider. (Note this only happens if the JCE provider is not already
     * loaded.) This method returns the property {@code Encryptor.PreferredJCEProvider}.
     * </p<p>
     * By default, this {@code Encryptor.PreferredJCEProvider} property is set
     * to an empty string, which means that the preferred JCE provider is not
     * changed.
     * @return The property {@code Encryptor.PreferredJCEProvider} is returned.
     * @see org.owasp.esapi.crypto.SecurityProviderLoader
     */
	@Deprecated
    public String getPreferredJCEProvider();
    
// TODO - DISCUSS: Where should this web page (below) go? Maybe with the Javadoc? But where?
//				   Think it makes more sense as part of the release notes, but OTOH, I
//				   really don't want to rewrite this as a Wiki page either.
    /**
     * Determines whether the {@code CipherText} should be used with a Message
     * Authentication Code (MAC). Generally this makes for a more robust cryptographic
     * scheme, but there are some minor performance implications. Controlled by
     * the ESAPI property <i>Encryptor.CipherText.useMAC</i>.
     * </p><p>
     * For further details, see the "Advanced Usage" section of
     * <a href="http://www.owasp.org/ESAPI_2.0_ReleaseNotes_CryptoChanges.html">
     * "Why Is OWASP Changing ESAPI Encryption?"</a>.
     * </p>
     * @return	{@code true} if a you want a MAC to be used, otherwise {@code false}.
     */
	@Deprecated
    public boolean useMACforCipherText();

    /**
     * Indicates whether the {@code PlainText} objects may be overwritten after
     * they have been encrypted. Generally this is a good idea, especially if
     * your VM is shared by multiple applications (e.g., multiple applications
     * running in the same J2EE container) or if there is a possibility that
     * your VM may leave a core dump (say because it is running non-native
     * Java code.
     * <p>
     * Controlled by the property {@code Encryptor.PlainText.overwrite} in
     * the {@code ESAPI.properties} file.
     * </p>
     * @return	True if it is OK to overwrite the {@code PlainText} objects
     *			after encrypting, false otherwise.
     */
	@Deprecated
    public boolean overwritePlainText();
    
    /**
     * Get a string indicating how to compute an Initialization Vector (IV).
     * Currently supported modes are "random" to generate a random IV or
     * "fixed" to use a fixed (static) IV. If a "fixed" IV is chosen, then the
     * the value of this fixed IV must be specified as the property
     * {@code Encryptor.fixedIV} and be of the appropriate length.
     * 
     * @return A string specifying the IV type. Should be "random" or "fixed".
     * 
     * @see #getFixedIV()
     */
	@Deprecated
    public String getIVType();
    
    /**
     * If a "fixed" (i.e., static) Initialization Vector (IV) is to be used,
     * this will return the IV value as a hex-encoded string.
     * @return The fixed IV as a hex-encoded string.
     */
	@Deprecated
    public String getFixedIV();
    
    /**
     * Return a {@code List} of strings of combined cipher modes that support
     * <b>both</b> confidentiality and authenticity. These would be preferred
     * cipher modes to use if your JCE provider supports them. If such a
     * cipher mode is used, no explicit <i>separate</i> MAC is calculated as part of
     * the {@code CipherText} object upon encryption nor is any attempt made
     * to verify the same on decryption.
     * </p><p>
     * The list is taken from the comma-separated list of cipher modes specified
     * by the ESAPI property
     * {@code Encryptor.cipher_modes.combined_modes}.
     * 
     * @return The parsed list of comma-separated cipher modes if the property
     * was specified in {@code ESAPI.properties}; otherwise the empty list is
     * returned.
     */
	@Deprecated
    public List<String> getCombinedCipherModes();

    /**
     * Return {@code List} of strings of additional cipher modes that are
     * permitted (i.e., in <i>addition<i> to those returned by
     * {@link #getCombinedCipherModes()}) to be used for encryption and
     * decryption operations.
     * </p><p>
     * The list is taken from the comma-separated list of cipher modes specified
     * by the ESAPI property
     * {@code Encryptor.cipher_modes.additional_allowed}.
     * 
     * @return The parsed list of comma-separated cipher modes if the property
     * was specified in {@code ESAPI.properties}; otherwise the empty list is
     * returned.
     *
     * @see #getCombinedCipherModes()
     */
	@Deprecated
    public List<String> getAdditionalAllowedCipherModes();

	/**
	 * Gets the hashing algorithm used by ESAPI to hash data.
	 * 
	 * @return the current hashing algorithm
	 */
	@Deprecated
	public String getHashAlgorithm();

	/**
	 * Gets the hash iterations used by ESAPI to hash data.
	 * 
	 * @return the current hashing algorithm
	 */
	@Deprecated
	public int getHashIterations();

	/**
	 * Retrieve the Pseudo Random Function (PRF) used by the ESAPI
	 * Key Derivation Function (KDF).
	 * 
	 * @return	The KDF PRF algorithm name.
	 */
	@Deprecated
	public String getKDFPseudoRandomFunction();
	
	/**
	 * Gets the character encoding scheme supported by this application. This is used to set the
	 * character encoding scheme on requests and responses when setCharacterEncoding() is called
	 * on SafeRequests and SafeResponses. This scheme is also used for encoding/decoding URLs 
	 * and any other place where the current encoding scheme needs to be known.
	 * <br><br>
	 * Note: This does not get the configured response content type. That is accessed by calling 
	 * getResponseContentType().
	 * 
	 * @return the current character encoding scheme
	 */
	@Deprecated
	public String getCharacterEncoding();

	/**
	 * Return true if multiple encoding is allowed
	 *
	 * @return whether multiple encoding is allowed when canonicalizing data
	 */
	@Deprecated
	public boolean getAllowMultipleEncoding();

	/**
	 * Return true if mixed encoding is allowed
	 *
	 * @return whether mixed encoding is allowed when canonicalizing data
	 */
	@Deprecated
	public boolean getAllowMixedEncoding();

	/**
	 * Returns the List of Codecs to use when canonicalizing data
	 * 
	 * @return the codec list
	 */
	@Deprecated
	public List<String> getDefaultCanonicalizationCodecs();

	/**
	 * Gets the digital signature algorithm used by ESAPI to generate and verify signatures.
	 * 
	 * @return the current digital signature algorithm
	 */
	@Deprecated
	public String getDigitalSignatureAlgorithm();

	/**
	 * Gets the digital signature key length used by ESAPI to generate and verify signatures.
	 * 
	 * @return the current digital signature key length
	 */
	@Deprecated
	public int getDigitalSignatureKeyLength();
		   
	/**
	 * Gets the random number generation algorithm used to generate random numbers where needed.
	 * 
	 * @return the current random number generation algorithm
	 */
	@Deprecated
	public String getRandomAlgorithm();

	/**
	 * Gets the number of login attempts allowed before the user's account is locked. If this 
	 * many failures are detected within the alloted time period, the user's account will be locked.
	 * 
	 * @return the number of failed login attempts that cause an account to be locked
	 */
	@Deprecated
	public int getAllowedLoginAttempts();

	/**
	 * Gets the maximum number of old password hashes that should be retained. These hashes can 
	 * be used to ensure that the user doesn't reuse the specified number of previous passwords
	 * when they change their password.
	 * 
	 * @return the number of old hashed passwords to retain
	 */
	@Deprecated
	public int getMaxOldPasswordHashes();

	/**
	 * Allows for complete disabling of all intrusion detection mechanisms
	 * 
	 * @return true if intrusion detection should be disabled
	 */
	@Deprecated
	public boolean getDisableIntrusionDetection();
	
	/**
	 * Gets the intrusion detection quota for the specified event.
	 * 
	 * @param eventName the name of the event whose quota is desired
	 * 
	 * @return the Quota that has been configured for the specified type of event
	 */
	@Deprecated
	public Threshold getQuota(String eventName);

	/**
	 * Gets a file from the resource directory
     *
     * @param filename The file name resource.
     * @return A {@code File} object representing the specified file name or null if not found.
     */
	@Deprecated
    public File getResourceFile( String filename );
    
	/**
	 * Forces new cookies to have HttpOnly flag set.
     */
	@Deprecated
    public boolean getForceHttpOnlySession() ;

	/**
	 * Forces session cookies to have Secure flag set.
     */
	@Deprecated
    public boolean getForceSecureSession() ;

	/**
	 * Forces new cookies to have HttpOnly flag set.
     */
	@Deprecated
    public boolean getForceHttpOnlyCookies() ;

	/**
	 * Forces new cookies to have Secure flag set.
     */
	@Deprecated
    public boolean getForceSecureCookies() ;

	/**
	 * Returns the maximum allowable HTTP header size.
	 */
	@Deprecated
	public int getMaxHttpHeaderSize() ;

	/**
	 * Gets an InputStream to a file in the resource directory
     *
     * @param filename A file name in the resource directory.
     * @return An {@code InputStream} to the specified file name in the resource directory.
     * @throws IOException If the specified file name cannot be found or opened for reading.
     */
	@Deprecated
    public InputStream getResourceStream( String filename ) throws IOException;

    	
	/**
	 * Sets the ESAPI resource directory.
	 * 
	 * @param dir The location of the resource directory.
	 */
	@Deprecated
	public void setResourceDirectory(String dir);
	
	/**
	 * Gets the content type for responses used when setSafeContentType() is called.
	 * <br><br>
	 * Note: This does not get the configured character encoding scheme. That is accessed by calling 
	 * getCharacterEncoding().
	 * 
	 * @return The current content-type set for responses.
	 */
	@Deprecated
	public String getResponseContentType();

	/**
	 * This method returns the configured name of the session identifier, 
	 * likely "JSESSIONID" though this can be overridden.
	 * 
	 * @return The name of the session identifier, like "JSESSIONID"
	 */
	@Deprecated
	public String getHttpSessionIdName();
	
	/**
	 * Gets the length of the time to live window for remember me tokens (in milliseconds).
	 * 
	 * @return The time to live length for generated remember me tokens.
	 */
	@Deprecated
	public long getRememberTokenDuration();

	
	/**
	 * Gets the idle timeout length for sessions (in milliseconds). This is the amount of time that a session
	 * can live before it expires due to lack of activity. Applications or frameworks could provide a reauthenticate
	 * function that enables a session to continue after reauthentication.
	 * 
	 * @return The session idle timeout length.
	 */
	@Deprecated
	public int getSessionIdleTimeoutLength();
	
	/**
	 * Gets the absolute timeout length for sessions (in milliseconds). This is the amount of time that a session
	 * can live before it expires regardless of the amount of user activity. Applications or frameworks could 
	 * provide a reauthenticate function that enables a session to continue after reauthentication.
	 * 
	 * @return The session absolute timeout length.
	 */
	@Deprecated
	public int getSessionAbsoluteTimeoutLength();
	
	
	/**
	 * Returns whether HTML entity encoding should be applied to log entries.
	 * 
	 * @return True if log entries are to be HTML Entity encoded. False otherwise.
	 */
	@Deprecated
	public boolean getLogEncodingRequired();
	
	/**
	 * Returns whether ESAPI should log the application name. This might be clutter in some
	 * single-server/single-app environments.
	 * 
	 * @return True if ESAPI should log the application name, False otherwise
	 */
	@Deprecated
	public boolean getLogApplicationName();

	/**
	 * Returns whether ESAPI should log the server IP. This might be clutter in some
	 * single-server environments.
	 * 
	 * @return True if ESAPI should log the server IP and port, False otherwise
	 */
	@Deprecated
	public boolean getLogServerIP();

	/**
	 * Returns the current log level.
	 * @return	An integer representing the current log level.
	 */
	@Deprecated
    public int getLogLevel();
	
    /**
     * Get the name of the log file specified in the ESAPI configuration properties file. Return a default value 
     * if it is not specified.
     * 
     * @return the log file name defined in the properties file.
     */
	@Deprecated
    public String getLogFileName();

    /**
     * Get the maximum size of a single log file from the ESAPI configuration properties file. Return a default value 
     * if it is not specified. Once the log hits this file size, it will roll over into a new log.
     * 
     * @return the maximum size of a single log file (in bytes).
     */
	@Deprecated
    public int getMaxLogFileSize();

	/**
	 * Models a simple threshold as a count and an interval, along with a set of actions to take if 
	 * the threshold is exceeded. These thresholds are used to define when the accumulation of a particular event
	 * has met a set number within the specified time period. Once a threshold value has been met, various
	 * actions can be taken at that point.
	 */
	public static class Threshold {
		
		/** The name of this threshold. */
		public String name = null;
		
		/** The count at which this threshold is triggered. */
		public int count = 0;
		
		/** 
		 * The time frame within which 'count' number of actions has to be detected in order to
		 * trigger this threshold.
		 */
		public long interval = 0;
		
		/**
		 * The list of actions to take if the threshold is met. It is expected that this is a list of Strings, but 
		 * your implementation could have this be a list of any type of 'actions' you wish to define. 
		 */
		public List<String> actions = null;

		/**
		 * Constructs a threshold that is composed of its name, its threshold count, the time window for
		 * the threshold, and the actions to take if the threshold is triggered.
		 * 
		 * @param name The name of this threshold.
		 * @param count The count at which this threshold is triggered.
		 * @param interval The time frame within which 'count' number of actions has to be detected in order to
		 * trigger this threshold.
		 * @param actions The list of actions to take if the threshold is met.
		 */
		public Threshold(String name, int count, long interval, List<String> actions) {
			this.name = name;
			this.count = count;
			this.interval = interval;
			this.actions = actions;
		}
	}

	/**
	 * Returns the default working directory for executing native processes with Runtime.exec().
	 */
	public File getWorkingDirectory();
}
