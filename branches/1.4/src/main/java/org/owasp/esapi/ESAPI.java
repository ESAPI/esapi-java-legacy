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
 * @author Rogan Dawes <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2008
 */
package org.owasp.esapi;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.reference.DefaultEncoder;
import org.owasp.esapi.reference.DefaultExecutor;
import org.owasp.esapi.reference.DefaultHTTPUtilities;
import org.owasp.esapi.reference.DefaultIntrusionDetector;
import org.owasp.esapi.reference.DefaultRandomizer;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;
import org.owasp.esapi.reference.DefaultValidator;
import org.owasp.esapi.reference.FileBasedAccessController;
import org.owasp.esapi.reference.FileBasedAuthenticator;
import org.owasp.esapi.reference.JavaEncryptor;
import org.owasp.esapi.reference.JavaLogFactory;

/**
 * ESAPI locator class is provided to make it easy to gain access to the current ESAPI classes in use.
 * Use the set methods to override the reference implementations with instances of any custom ESAPI implementations.
 */
public class ESAPI {

	private static AccessController accessController = null;

	private static Authenticator authenticator = null;

	private static Encoder encoder = null;

	private static Encryptor encryptor = null;

	private static Executor executor = null;

	private static HTTPUtilities httpUtilities = null;

	private static IntrusionDetector intrusionDetector = null;

	private static LogFactory logFactory = null;
	
	private static Logger defaultLogger = null;

	private static Randomizer randomizer = null;

	private static SecurityConfiguration securityConfiguration = null;

	private static Validator validator = null;

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
	public static AccessController accessController() {
		if (ESAPI.accessController == null)
			ESAPI.accessController = new FileBasedAccessController();
		return ESAPI.accessController;
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
	public static Authenticator authenticator() {
		if (ESAPI.authenticator == null)
			ESAPI.authenticator = new FileBasedAuthenticator();
		return ESAPI.authenticator;
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
	public static Encoder encoder() {
		if (ESAPI.encoder == null)
			ESAPI.encoder = new DefaultEncoder();
		return ESAPI.encoder;
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
	public static Encryptor encryptor() {
		if (ESAPI.encryptor == null)
			ESAPI.encryptor = new JavaEncryptor();
		return ESAPI.encryptor;
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
		if (ESAPI.executor == null)
			ESAPI.executor = new DefaultExecutor();
		return ESAPI.executor;
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
		if (ESAPI.httpUtilities == null)
			ESAPI.httpUtilities = new DefaultHTTPUtilities();
		return ESAPI.httpUtilities;
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
	public static IntrusionDetector intrusionDetector() {
		if (ESAPI.intrusionDetector == null)
			ESAPI.intrusionDetector = new DefaultIntrusionDetector();
		return ESAPI.intrusionDetector;
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
	private static LogFactory logFactory() {
		if (logFactory == null)
			logFactory = new JavaLogFactory(securityConfiguration().getApplicationName());
		return logFactory;
	}
	
	/**
	 * @param clazz The class to associate the logger with.
	 * @return The current Logger associated with the specified class.
	 */
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
	public static Randomizer randomizer() {
		if (ESAPI.randomizer == null)
			ESAPI.randomizer = new DefaultRandomizer();
		return ESAPI.randomizer;
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
		if (ESAPI.validator == null)
			ESAPI.validator = new DefaultValidator();
		return ESAPI.validator;
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
