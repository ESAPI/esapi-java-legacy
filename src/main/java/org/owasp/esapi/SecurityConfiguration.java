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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

/**
 * The SecurityConfiguration interface stores all configuration information
 * that directs the behavior of the ESAPI implementation.
 * <br><br>
 * Protection of this configuration information is critical to the secure
 * operation of the application using the ESAPI. You should use operating system
 * access controls to limit access to wherever the configuration information is
 * stored.
 * <br><br>
 * Please note that adding another layer of encryption does not make the
 * attackers job much more difficult. Somewhere there must be a master "secret"
 * that is stored unencrypted on the application platform. Creating another
 * layer of indirection doesn't provide any real additional security. Its up to the
 * reference implementation to decide whether this file should be encrypted or not.
 * The ESAPI reference implementation (DefaultSecurityConfiguration.java) does not encrypt
 * its properties file.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface SecurityConfiguration {

	/**
	 * Gets the application name, used for logging
	 * 
	 * @return the name of the current application
	 */
	public String getApplicationName();
	
	/**
	 * Returns the fully qualified classname of the ESAPI Logging implementation.
	 */
	public String getLogImplementation();
	
	/**
	 * Returns the fully qualified classname of the ESAPI Authentication implementation.
	 */
	public String getAuthenticationImplementation();
	
	/**
	 * Returns the fully qualified classname of the ESAPI Encoder implementation.
	 */
	public String getEncoderImplementation();
	
	/**
	 * Returns the fully qualified classname of the ESAPI Access Control implementation.
	 */
	public String getAccessControlImplementation();
	
	/**
	 * Returns the fully qualified classname of the ESAPI Intrusion Detection implementation.
	 */
	public String getIntrusionDetectionImplementation();
	
	/**
	 * Returns the fully qualified classname of the ESAPI Randomizer implementation.
	 */
	public String getRandomizerImplementation();
	
	/**
	 * Returns the fully qualified classname of the ESAPI Encryption implementation.
	 */
	public String getEncryptionImplementation();
	
	/**
	 * Returns the fully qualified classname of the ESAPI Validation implementation.
	 */
	public String getValidationImplementation();
	
	/**
	 * Returns the fully qualified classname of the ESAPI OS Execution implementation.
	 */
	public String getExecutorImplementation();
	
	/**
	 * Returns the fully qualified classname of the ESAPI HTTPUtilities implementation.
	 */
	public String getHTTPUtilitiesImplementation();
	
	/**
	 * Gets the master key. This password is used to encrypt/decrypt other files or types
	 * of data that need to be protected by your application.
	 * 
	 * @return the current master key
	 */
	public byte[] getMasterKey();

	/**
	 * Gets the keystore used to hold any encryption keys used by your application.
	 * 
	 * @return the current keystore
	 */
	public File getKeystore();

	/**
	 * Gets the master salt that is used to salt stored password hashes and any other location 
	 * where a salt is needed.
	 * 
	 * @return the current master salt
	 */
	public byte[] getMasterSalt();

	/**
	 * Gets the allowed file extensions for files that are uploaded to this application.
	 * 
	 * @return a list of the current allowed file extensions
	 */
	@SuppressWarnings("unchecked")
	public List getAllowedFileExtensions();

	/**
	 * Gets the maximum allowed file upload size.
	 * 
	 * @return the current allowed file upload size
	 */
	public int getAllowedFileUploadSize();

	/**
	 * Gets the name of the password parameter used during user authentication.
	 * 
	 * @return the name of the password parameter
	 */
	public String getPasswordParameterName();

	/**
	 * Gets the name of the username parameter used during user authentication.
	 * 
	 * @return the name of the username parameter
	 */
	public String getUsernameParameterName();

	/**
	 * Gets the encryption algorithm used by ESAPI to protect data.
	 * 
	 * @return the current encryption algorithm
	 */
	public String getEncryptionAlgorithm();

	/**
	 * Gets the hashing algorithm used by ESAPI to hash data.
	 * 
	 * @return the current hashing algorithm
	 */
	public String getHashAlgorithm();

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
	public String getCharacterEncoding();

	/**
	 * Gets the digital signature algorithm used by ESAPI to generate and verify signatures.
	 * 
	 * @return the current digital signature algorithm
	 */
	public String getDigitalSignatureAlgorithm();

	/**
	 * Gets the random number generation algorithm used to generate random numbers where needed.
	 * 
	 * @return the current random number generation algorithm
	 */
	public String getRandomAlgorithm();

	/**
	 * Gets the number of login attempts allowed before the user's account is locked. If this 
	 * many failures are detected within the alloted time period, the user's account will be locked.
	 * 
	 * @return the number of failed login attempts that cause an account to be locked
	 */
	public int getAllowedLoginAttempts();

	/**
	 * Gets the maximum number of old password hashes that should be retained. These hashes can 
	 * be used to ensure that the user doesn't reuse the specified number of previous passwords
	 * when they change their password.
	 * 
	 * @return the number of old hashed passwords to retain
	 */
	public int getMaxOldPasswordHashes();

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
     * @param filename
     * @return
     */
    public File getResourceFile( String filename );
    
	/**
	 * Forces new cookie headers with HttpOnly on first and second responses
	 * in public HttpSession org.owasp.esapi.filters.SafeRequest.getSession() and 
	 * org.owasp.esapi.filters.getSession(boolean create) 
     *
     * @param force whether to override JSESSIONID cookie
     */
    public boolean getForceHTTPOnly() ;

	/**
	 * Gets an InputStream to a file in the resource directory
     *
     * @param filename
     * @return
     * @throws IOException
     */
    public InputStream getResourceStream( String filename ) throws IOException;

    	
	/**
	 * Sets the ESAPI resource directory.
	 * 
	 * @param dir The location of the resource directory.
	 */
	public void setResourceDirectory(String dir);
	
	/**
	 * Gets the content type for responses used when setSafeContentType() is called.
	 * <br><br>
	 * Note: This does not get the configured character encoding scheme. That is accessed by calling 
	 * getCharacterEncoding().
	 * 
	 * @return The current content-type set for responses.
	 */
	public String getResponseContentType();

	/**
	 * Gets the length of the time to live window for remember me tokens (in milliseconds).
	 * 
	 * @return The time to live length for generated remember me tokens.
	 */
	public long getRememberTokenDuration();

	
	/**
	 * Gets the idle timeout length for sessions (in milliseconds). This is the amount of time that a session
	 * can live before it expires due to lack of activity. Applications or frameworks could provide a reauthenticate
	 * function that enables a session to continue after reauthentication.
	 * 
	 * @return The session idle timeout length.
	 */
	public int getSessionIdleTimeoutLength();
	
	/**
	 * Gets the absolute timeout length for sessions (in milliseconds). This is the amount of time that a session
	 * can live before it expires regardless of the amount of user activity. Applications or frameworks could 
	 * provide a reauthenticate function that enables a session to continue after reauthentication.
	 * 
	 * @return The session absolute timeout length.
	 */
	public int getSessionAbsoluteTimeoutLength();
	
	
	/**
	 * Returns whether HTML entity encoding should be applied to log entries.
	 * 
	 * @return True if log entries are to be HTML Entity encoded. False otherwise.
	 */
	public boolean getLogEncodingRequired();

    /**
     * Get the name of the log file specified in the ESAPI configuration properties file. Return a default value 
     * if it is not specified.
     * 
     * @return the log file name defined in the properties file.
     */
    public String getLogFileName();

    /**
     * Get the maximum size of a single log file from the ESAPI configuration properties file. Return a default value 
     * if it is not specified. Once the log hits this file size, it will roll over into a new log.
     * 
     * @return the maximum size of a single log file (in bytes).
     */
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
		
		/** The list of actions to take if the threshold is met. It is expected that this is a list of Strings, but 
		 * your implementation could have this be a list of any type of 'actions' you wish to define. 
		 */
		@SuppressWarnings("unchecked")
		public List actions = null;

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
		@SuppressWarnings("unchecked")
		public Threshold(String name, int count, long interval, List actions) {
			this.name = name;
			this.count = count;
			this.interval = interval;
			this.actions = actions;
		}
	}
}