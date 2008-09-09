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
 * ESAPI locator class to make it easy to get a concrete implementation of the
 * various ESAPI classes. Use the setters to override the reference implementations
 * with instances of any custom ESAPI implementations.
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

	public static HttpServletRequest currentRequest() {
		return httpUtilities().getCurrentRequest();
	}
	
	public static HttpServletResponse currentResponse() {
		return httpUtilities().getCurrentResponse();
	}
	
	/**
	 * @return the accessController
	 */
	public static AccessController accessController() {
		if (ESAPI.accessController == null)
			ESAPI.accessController = new FileBasedAccessController();
		return ESAPI.accessController;
	}

	/**
	 * @param accessController
	 *            the accessController to set
	 */
	public static void setAccessController(AccessController accessController) {
		ESAPI.accessController = accessController;
	}

	/**
	 * @return the authenticator
	 */
	public static Authenticator authenticator() {
		if (ESAPI.authenticator == null)
			ESAPI.authenticator = new FileBasedAuthenticator();
		return ESAPI.authenticator;
	}

	/**
	 * @param authenticator
	 *            the authenticator to set
	 */
	public static void setAuthenticator(Authenticator authenticator) {
		ESAPI.authenticator = authenticator;
	}

	/**
	 * @return the encoder
	 */
	public static Encoder encoder() {
		if (ESAPI.encoder == null)
			ESAPI.encoder = new DefaultEncoder();
		return ESAPI.encoder;
	}

	/**
	 * @param encoder
	 *            the encoder to set
	 */
	public static void setEncoder(Encoder encoder) {
		ESAPI.encoder = encoder;
	}

	/**
	 * @return the encryptor
	 */
	public static Encryptor encryptor() {
		if (ESAPI.encryptor == null)
			ESAPI.encryptor = new JavaEncryptor();
		return ESAPI.encryptor;
	}

	/**
	 * @param encryptor
	 *            the encryptor to set
	 */
	public static void setEncryptor(Encryptor encryptor) {
		ESAPI.encryptor = encryptor;
	}

	/**
	 * @return the executor
	 */
	public static Executor executor() {
		if (ESAPI.executor == null)
			ESAPI.executor = new DefaultExecutor();
		return ESAPI.executor;
	}

	/**
	 * @param executor
	 *            the executor to set
	 */
	public static void setExecutor(Executor executor) {
		ESAPI.executor = executor;
	}

	/**
	 * @return the httpUtilities
	 */
	public static HTTPUtilities httpUtilities() {
		if (ESAPI.httpUtilities == null)
			ESAPI.httpUtilities = new DefaultHTTPUtilities();
		return ESAPI.httpUtilities;
	}

	/**
	 * @param httpUtilities
	 *            the httpUtilities to set
	 */
	public static void setHttpUtilities(HTTPUtilities httpUtilities) {
		ESAPI.httpUtilities = httpUtilities;
	}

	/**
	 * @return the intrusionDetector
	 */
	public static IntrusionDetector intrusionDetector() {
		if (ESAPI.intrusionDetector == null)
			ESAPI.intrusionDetector = new DefaultIntrusionDetector();
		return ESAPI.intrusionDetector;
	}

	/**
	 * @param intrusionDetector
	 *            the intrusionDetector to set
	 */
	public static void setIntrusionDetector(IntrusionDetector intrusionDetector) {
		ESAPI.intrusionDetector = intrusionDetector;
	}

	private static LogFactory logFactory() {
		if (logFactory == null)
			logFactory = new JavaLogFactory(securityConfiguration().getApplicationName());
		return logFactory;
	}
	
	/**
	 * 
	 */
	public static Logger getLogger(Class clazz) {
		return logFactory().getLogger(clazz);
	}
	
	/**
	 * 
	 */
	public static Logger getLogger(String name) {
		return logFactory().getLogger(name);
	}
	
	public static Logger log() {
		if (defaultLogger == null)
			defaultLogger = logFactory().getLogger("");
		return defaultLogger;
	}
	
	 /**
	 * @param factory the log factory to set
	 */
	 public static void setLogFactory(LogFactory factory) {
		 ESAPI.logFactory = factory;
	 }
	
	/**
	 * @return the randomizer
	 */
	public static Randomizer randomizer() {
		if (ESAPI.randomizer == null)
			ESAPI.randomizer = new DefaultRandomizer();
		return ESAPI.randomizer;
	}

	/**
	 * @param randomizer
	 *            the randomizer to set
	 */
	public static void setRandomizer(Randomizer randomizer) {
		ESAPI.randomizer = randomizer;
	}

	/**
	 * @return the securityConfiguration
	 */
	public static SecurityConfiguration securityConfiguration() {
		if (ESAPI.securityConfiguration == null)
			ESAPI.securityConfiguration = new DefaultSecurityConfiguration();
		return ESAPI.securityConfiguration;
	}

	/**
	 * @param securityConfiguration
	 *            the securityConfiguration to set
	 */
	public static void setSecurityConfiguration(
			SecurityConfiguration securityConfiguration) {
		ESAPI.securityConfiguration = securityConfiguration;
	}

	/**
	 * @return the validator
	 */
	public static Validator validator() {
		if (ESAPI.validator == null)
			ESAPI.validator = new DefaultValidator();
		return ESAPI.validator;
	}

	/**
	 * @param validator
	 *            the validator to set
	 */
	public static void setValidator(Validator validator) {
		ESAPI.validator = validator;
	}

}
