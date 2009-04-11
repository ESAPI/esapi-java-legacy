/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2008 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Mike Fauzy <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Rogan Dawes <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2008
 */
package org.owasp.esapi;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.reference.DefaultExecutor;
import org.owasp.esapi.reference.DefaultHTTPUtilities;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;
import org.owasp.esapi.reference.DefaultValidator;
import org.owasp.esapi.reference.accesscontrol.DefaultAccessController;
import org.owasp.esapi.reference.accesscontrol.policyloader.ACRPolicyFileLoader;
import org.owasp.esapi.reference.accesscontrol.policyloader.PolicyDTO;

/**
 * ESAPI locator class is provided to make it easy to gain access to the current ESAPI classes in use.
 * Use the set methods to override the reference implementations with instances of any custom ESAPI implementations.
 */
public class ESAPI {

	private static Authenticator authenticator = null;

	private static Encoder encoder = null;
	
	private static LogFactory logFactory = null;
	
	private static AccessController accessController = null;
	
	private static IntrusionDetector intrusionDetector = null;
	
	private static Randomizer randomizer = null;

	private static Encryptor encryptor = null;

	private static Executor executor = null;
	
	private static Validator validator = null;

	private static HTTPUtilities httpUtilities = null;
	
	private static Logger defaultLogger = null;

	private static SecurityConfiguration securityConfiguration = new DefaultSecurityConfiguration();

	/**
	 * prevent instantiation of this class
	 */
	private ESAPI() {
	}

	/**
	 * Get the current HTTP Servlet Request being processed.
	 * @return the current HTTP Servlet Request.
	 */
	public static HttpServletRequest currentRequest() {
		return httpUtilities().getCurrentRequest();
	}
	
	/**
	 * Get the current HTTP Servlet Response being generated.
	 * @return the current HTTP Servlet Response.
	 */
	public static HttpServletResponse currentResponse() {
		return httpUtilities().getCurrentResponse();
	}
	
	/**
	 * @return the current ESAPI AccessController object being used to maintain the access control rules for this application. 
	 */
	@SuppressWarnings("unchecked")
	public static AccessController accessController() {
		if (accessController == null) {
			String accessControllerName = securityConfiguration().getAccessControlImplementation();
		    try {
		        Class theClass  = Class.forName(accessControllerName);
		        accessController = (AccessController)theClass.newInstance();
		    } catch ( ClassNotFoundException ex ) {
				System.out.println( ex + " AccessController class (" + accessControllerName + ") must be in class path.");
		    } catch( InstantiationException ex ) {
		        System.out.println( ex + " AccessController class (" + accessControllerName + ") must be concrete.");
		    } catch( IllegalAccessException ex ) {
		        System.out.println( ex + " AccessController class (" + accessControllerName + ") must have a no-arg constructor.");
		    }
		} 
		return accessController;
	}

	/**
	 * Change the current ESAPI AccessController to the AccessController provided. 
	 * @param accessController
	 *            the AccessController to set to be the current ESAPI AccessController. 
	 */
	public static void setAccessController(AccessController accessController) {
		ESAPI.accessController = accessController;
	}

	/**
	 * @return the current ESAPI Authenticator object being used to authenticate users for this application. 
	 */
	@SuppressWarnings("unchecked")
	public static Authenticator authenticator() {
		if (authenticator == null) {
			String authenticatorName = securityConfiguration().getAuthenticationImplementation();
		    try {
		        Class theClass  = Class.forName(authenticatorName);
		        authenticator = (Authenticator)theClass.newInstance();
		        
		    } catch ( ClassNotFoundException ex ) {
				System.out.println( ex + " Authenticator class (" + authenticatorName + ") must be in class path.");
		    } catch( InstantiationException ex ) {
		        System.out.println( ex + " Authenticator class (" + authenticatorName + ") must be concrete.");
		    } catch( IllegalAccessException ex ) {
		        System.out.println( ex + " Authenticator class (" + authenticatorName + ") must have a no-arg constructor.");
		    }
		} 
		return authenticator;
	}

	/**
	 * Change the current ESAPI Authenticator to the Authenticator provided. 
	 * @param authenticator
	 *            the Authenticator to set to be the current ESAPI Authenticator. 
	 */
	public static void setAuthenticator(Authenticator authenticator) {
		ESAPI.authenticator = authenticator;
	}

	/**
	 * @return the current ESAPI Encoder object being used to encode and decode data for this application. 
	 */
	@SuppressWarnings("unchecked")
	public static Encoder encoder() {
		if (encoder == null) {
			String encoderName = securityConfiguration().getEncoderImplementation();
		    try {
		        Class theClass  = Class.forName(encoderName);
		        encoder = (Encoder)theClass.newInstance();
		        
		    } catch ( ClassNotFoundException ex ) {
				System.out.println( ex + " Encoder class (" + encoderName + ") must be in class path.");
		    } catch( InstantiationException ex ) {
		        System.out.println( ex + " Encoder class (" + encoderName + ") must be concrete.");
		    } catch( IllegalAccessException ex ) {
		        System.out.println( ex + " Encoder class (" + encoderName + ") must have a no-arg constructor.");
		    }
		} 
		return encoder;
	}

	/**
	 * Change the current ESAPI Encoder to the Encoder provided. 
	 * @param encoder
	 *            the Encoder to set to be the current ESAPI Encoder. 
	 */
	public static void setEncoder(Encoder encoder) {
		ESAPI.encoder = encoder;
	}

	/**
	 * @return the current ESAPI Encryptor object being used to encrypt and decrypt data for this application. 
	 */
	@SuppressWarnings("unchecked")
	public static Encryptor encryptor() {
		if (encryptor == null) {
			String encryptorName = securityConfiguration().getEncryptionImplementation();
		    try {
		        Class theClass  = Class.forName(encryptorName);
		        encryptor = (Encryptor)theClass.newInstance();
		        
		    } catch ( ClassNotFoundException ex ) {
				System.out.println( ex + " Encryptor class (" + encryptorName + ") must be in class path.");
		    } catch( InstantiationException ex ) {
		        System.out.println( ex + " Encryptor class (" + encryptorName + ") must be concrete.");
		    } catch( IllegalAccessException ex ) {
		        System.out.println( ex + " Encryptor class (" + encryptorName + ") must have a no-arg constructor.");
		    }
		} 
		return encryptor;
	}

	/**
	 * Change the current ESAPI Encryptor to the Encryptor provided. 
	 * @param encryptor
	 *            the Encryptor to set to be the current ESAPI Encryptor. 
	 */
	public static void setEncryptor(Encryptor encryptor) {
		ESAPI.encryptor = encryptor;
	}

	/**
	 * @return the current ESAPI Executor object being used to safely execute OS commands for this application. 
	 */
	public static Executor executor() {
		if (executor == null) {
			String executorName = securityConfiguration().getExecutorImplementation();
		    try {
		        Class theClass  = Class.forName(executorName);
		        executor = (Executor)theClass.newInstance();
		        
		    } catch ( ClassNotFoundException ex ) {
				System.out.println( ex + " Executor class (" + executorName + ") must be in class path.");
		    } catch( InstantiationException ex ) {
		        System.out.println( ex + " Executor class (" + executorName + ") must be concrete.");
		    } catch( IllegalAccessException ex ) {
		        System.out.println( ex + " Executor class (" + executorName + ") must have a no-arg constructor.");
		    }
		} 
		return executor;
	}

	/**
	 * Change the current ESAPI Executor to the Executor provided. 
	 * @param executor
	 *            the Executor to set to be the current ESAPI Executor. 
	 */
	public static void setExecutor(Executor executor) {
		ESAPI.executor = executor;
	}

	/**
	 * @return the current ESAPI HTTPUtilities object being used to safely access HTTP requests and responses 
	 * for this application. 
	 */
	public static HTTPUtilities httpUtilities() {
		if (httpUtilities == null) {
			String httpUtilitiesName = securityConfiguration().getHTTPUtilitiesImplementation();
		    try {
		        Class theClass  = Class.forName(httpUtilitiesName);
		        httpUtilities = (HTTPUtilities)theClass.newInstance();
		        
		    } catch ( ClassNotFoundException ex ) {
				System.out.println( ex + " HTTPUtilities class (" + httpUtilitiesName + ") must be in class path.");
		    } catch( InstantiationException ex ) {
		        System.out.println( ex + " HTTPUtilities class (" + httpUtilitiesName + ") must be concrete.");
		    } catch( IllegalAccessException ex ) {
		        System.out.println( ex + " HTTPUtilities class (" + httpUtilitiesName + ") must have a no-arg constructor.");
		    }
		} 
		return httpUtilities;
	}

	/**
	 * Change the current ESAPI HTTPUtilities object to the HTTPUtilities object provided. 
	 * @param httpUtilities
	 *            the HTTPUtilities object to set to be the current ESAPI HTTPUtilities object. 
	 */
	public static void setHttpUtilities(HTTPUtilities httpUtilities) {
		ESAPI.httpUtilities = httpUtilities;
	}

	/**
	 * @return the current ESAPI IntrusionDetector being used to monitor for intrusions in this application. 
	 */
	@SuppressWarnings("unchecked")
	public static IntrusionDetector intrusionDetector() {
		if (intrusionDetector == null) {
			String intrusionDetectorName = securityConfiguration().getIntrusionDetectionImplementation();
		    try {
		        Class theClass  = Class.forName(intrusionDetectorName);
		        intrusionDetector = (IntrusionDetector)theClass.newInstance();
		        
		    } catch ( ClassNotFoundException ex ) {
				System.out.println( ex + " IntrusionDetector class (" + intrusionDetectorName + ") must be in class path.");
		    } catch( InstantiationException ex ) {
		        System.out.println( ex + " IntrusionDetector class (" + intrusionDetectorName + ") must be concrete.");
		    } catch( IllegalAccessException ex ) {
		        System.out.println( ex + " IntrusionDetector class (" + intrusionDetectorName + ") must have a no-arg constructor.");
		    }
		} 
		return intrusionDetector;
	}

	/**
	 * Change the current ESAPI IntrusionDetector to the IntrusionDetector provided. 
	 * @param intrusionDetector
	 *            the IntrusionDetector to set to be the current ESAPI IntrusionDetector. 
	 */
	public static void setIntrusionDetector(IntrusionDetector intrusionDetector) {
		ESAPI.intrusionDetector = intrusionDetector;
	}

	/**
	 * Get the current LogFactory being used by ESAPI. If there isn't one yet, it will create one, and then 
	 * return this same LogFactory from then on.
	 * @return The current LogFactory being used by ESAPI.
	 */
	@SuppressWarnings("unchecked")
	private static LogFactory logFactory() {
		if (logFactory == null) {
			String logFactoryName = securityConfiguration().getLogImplementation();
		    try {
		        Class theClass  = Class.forName(logFactoryName);
		        logFactory = (LogFactory)theClass.newInstance();
		        logFactory.setApplicationName( securityConfiguration().getApplicationName() );
		        
		    } catch ( ClassNotFoundException ex ) {
				System.out.println( ex + " LogFactory class (" + logFactoryName + ") must be in class path.");
		    } catch( InstantiationException ex ) {
		        System.out.println( ex + " LogFactory class (" + logFactoryName + ") must be concrete.");
		    } catch( IllegalAccessException ex ) {
		        System.out.println( ex + " LogFactory class (" + logFactoryName + ") must have a no-arg constructor.");
		    }
		} 
		return logFactory;
	}
	
	/**
	 * @param clazz The class to associate the logger with.
	 * @return The current Logger associated with the specified class.
	 */
	@SuppressWarnings("unchecked")
	public static Logger getLogger(Class clazz) {
		return logFactory().getLogger(clazz);
	}
	
	/**
	 * @param moduleName The module to associate the logger with.
	 * @return The current Logger associated with the specified module.
	 */
	public static Logger getLogger(String moduleName) {
		return logFactory().getLogger(moduleName);
	}
	
	/**
	 * @return The default Logger.
	 */
	public static Logger log() {
		if (defaultLogger == null)
			defaultLogger = logFactory().getLogger("DefaultLogger");
		return defaultLogger;
	}
	
	/**
	 * Change the current ESAPI LogFactory to the LogFactory provided. 
	 * @param factory
	 *            the LogFactory to set to be the current ESAPI LogFactory. 
	 */
	 public static void setLogFactory(LogFactory factory) {
		 ESAPI.logFactory = factory;
	 }
	
	/**
	 * @return the current ESAPI Randomizer being used to generate random numbers in this application. 
	 */
	@SuppressWarnings("unchecked")
	public static Randomizer randomizer() {
		if (randomizer == null) {
			String randomizerName = securityConfiguration().getRandomizerImplementation();
		    try {
		        Class theClass = Class.forName(randomizerName);
		        randomizer = (Randomizer)theClass.newInstance();
		        
		    } catch ( ClassNotFoundException ex ) {
				System.out.println( ex + " Randomizer class (" + randomizerName + ") must be in class path.");
		    } catch( InstantiationException ex ) {
		        System.out.println( ex + " Randomizer class (" + randomizerName + ") must be concrete.");
		    } catch( IllegalAccessException ex ) {
		        System.out.println( ex + " Randomizer class (" + randomizerName + ") must have a no-arg constructor.");
		    }
		} 
		return randomizer;
	}

	/**
	 * Change the current ESAPI Randomizer to the Randomizer provided. 
	 * @param randomizer
	 *            the Randomizer to set to be the current ESAPI Randomizer. 
	 */
	public static void setRandomizer(Randomizer randomizer) {
		ESAPI.randomizer = randomizer;
	}

	/**
	 * @return the current ESAPI SecurityConfiguration being used to manage the security configuration for 
	 * ESAPI for this application. 
	 */
	public static SecurityConfiguration securityConfiguration() {
		if (ESAPI.securityConfiguration == null)
			ESAPI.securityConfiguration = new DefaultSecurityConfiguration();
		return ESAPI.securityConfiguration;
	}

	/**
	 * Change the current ESAPI SecurityConfiguration to the SecurityConfiguration provided. 
	 * @param securityConfiguration
	 *            the SecurityConfiguration to set to be the current ESAPI SecurityConfiguration. 
	 */
	public static void setSecurityConfiguration(
			SecurityConfiguration securityConfiguration) {
		ESAPI.securityConfiguration = securityConfiguration;
	}

	/**
	 * @return the current ESAPI Validator being used to validate data in this application. 
	 */
	public static Validator validator() {
		if (validator == null) {
			String validatorName = securityConfiguration().getValidationImplementation();
		    try {
		        Class theClass = Class.forName(validatorName);
		        validator = (Validator)theClass.newInstance();
		        
		    } catch ( ClassNotFoundException ex ) {
				System.out.println( ex + " Validator class (" + validatorName + ") must be in class path.");
		    } catch( InstantiationException ex ) {
		        System.out.println( ex + " Validator class (" + validatorName + ") must be concrete.");
		    } catch( IllegalAccessException ex ) {
		        System.out.println( ex + " Validator class (" + validatorName + ") must have a no-arg constructor.");
		    }
		} 
		return validator;
	}

	/**
	 * Change the current ESAPI Validator to the Validator provided. 
	 * @param validator
	 *            the Validator to set to be the current ESAPI Validator. 
	 */
	public static void setValidator(Validator validator) {
		ESAPI.validator = validator;
	}

}
