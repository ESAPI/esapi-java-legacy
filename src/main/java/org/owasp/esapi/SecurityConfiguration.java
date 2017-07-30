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
	 * Returns the validation pattern for a particular type
	 * @param typeName
	 * @return the validation pattern
	 */
    public Pattern getValidationPattern( String typeName );
    
	/**
     * Retrieves the upload directory as specified in the ESAPI.properties file.
     * @return the upload directory
     */
    public File getUploadDirectory();
	
    /**
     * Retrieves the temp directory to use when uploading files, as specified in ESAPI.properties.
     * @return the temp directory
     */
    public File getUploadTempDirectory();

	/**
	 * Gets the allowed executables to run with the Executor.
	 * 
	 * @return a list of the current allowed file extensions
	 */
	public List<String> getAllowedExecutables();

	/**
	 * Gets the allowed file extensions for files that are uploaded to this application.
	 * 
	 * @return a list of the current allowed file extensions
	 */
	public List<String> getAllowedFileExtensions();
    
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
     *          until then. Details of replacement forthcoming to ESAPI-Dev
     *          list. Most likely to be replaced by a new public CTOR for
     *          JavaEncryptor that takes a list of properties to override.
     */
    @Deprecated
    public String setCipherTransformation(String cipherXform);
	
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
    public List<String> getAdditionalAllowedCipherModes();

	/**
	 * Returns the List of Codecs to use when canonicalizing data
	 * 
	 * @return the codec list
	 */
	public List<String> getDefaultCanonicalizationCodecs();

	/**
	 * Gets the digital signature algorithm used by ESAPI to generate and verify signatures.
	 * 
	 * @return the current digital signature algorithm
     * @deprecated Use SecurityConfiguration.getStringProp("appropriate_esapi_prop_name") instead.
	 */
	/**
	 * Gets the intrusion detection quota for the specified event.
	 * 
	 * @param eventName the name of the event whose quota is desired
	 * 
	 * @return the Quota that has been configured for the specified type of event
	 */
	public Threshold getQuota(String eventName);

	/**
	 * Gets a file from the resource directory
     *
     * @param filename The file name resource.
     * @return A {@code File} object representing the specified file name or null if not found.
     */
    public File getResourceFile( String filename );
    
	/**
	 * Gets an InputStream to a file in the resource directory
     *
     * @param filename A file name in the resource directory.
     * @return An {@code InputStream} to the specified file name in the resource directory.
     * @throws IOException If the specified file name cannot be found or opened for reading.
     */
    public InputStream getResourceStream( String filename ) throws IOException;

    	
	/**
	 * Sets the ESAPI resource directory.
	 * 
	 * @param dir The location of the resource directory.
	 */
	public void setResourceDirectory(String dir);
	
	/**
	 * Gets the length of the time to live window for remember me tokens (in milliseconds).
	 * 
	 * @return The time to live length for generated "remember me" tokens.
	 */
    // OPEN ISSUE: Can we replace w/ SecurityConfiguration.getIntProp("appropriate_esapi_prop_name") instead?
	public long getRememberTokenDuration();

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
