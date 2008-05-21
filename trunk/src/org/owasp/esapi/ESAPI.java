/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/esapi.
 *
 * Copyright (c) 2008 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the LGPL. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Rogan Dawes <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2008
 */
package org.owasp.esapi;

import org.owasp.esapi.reference.AccessController;
import org.owasp.esapi.reference.Authenticator;
import org.owasp.esapi.reference.Encoder;
import org.owasp.esapi.reference.Encryptor;
import org.owasp.esapi.reference.Executor;
import org.owasp.esapi.reference.HTTPUtilities;
import org.owasp.esapi.reference.IntrusionDetector;
import org.owasp.esapi.reference.JavaLogFactory;
import org.owasp.esapi.reference.Randomizer;
import org.owasp.esapi.reference.SecurityConfiguration;
import org.owasp.esapi.reference.Validator;

/**
 * ESAPI locator class to make it easy to get a concrete implementation of the
 * various ESAPI classes. Use the setters to override the reference implemnentations
 * with instances of any custom ESAPI implementations.
 */
public class ESAPI {

	private static IAccessController accessController = null;

	private static IAuthenticator authenticator = null;

	private static IEncoder encoder = null;

	private static IEncryptor encryptor = null;

	private static IExecutor executor = null;

	private static IHTTPUtilities httpUtilities = null;

	private static IIntrusionDetector intrusionDetector = null;

	private static ILogFactory logFactory = null;
	
	private static ILogger defaultLogger = null;

	private static IRandomizer randomizer = null;

	private static ISecurityConfiguration securityConfiguration = null;

	private static IValidator validator = null;

	/**
	 * prevent instantiation of this class
	 */
	private ESAPI() {
	}

	/**
	 * @return the accessController
	 */
	public static IAccessController accessController() {
		if (ESAPI.accessController == null)
			ESAPI.accessController = new AccessController();
		return ESAPI.accessController;
	}

	/**
	 * @param accessController
	 *            the accessController to set
	 */
	public static void setAccessController(IAccessController accessController) {
		ESAPI.accessController = accessController;
	}

	/**
	 * @return the authenticator
	 */
	public static IAuthenticator authenticator() {
		if (ESAPI.authenticator == null)
			ESAPI.authenticator = new Authenticator();
		return ESAPI.authenticator;
	}

	/**
	 * @param authenticator
	 *            the authenticator to set
	 */
	public static void setAuthenticator(IAuthenticator authenticator) {
		ESAPI.authenticator = authenticator;
	}

	/**
	 * @return the encoder
	 */
	public static IEncoder encoder() {
		if (ESAPI.encoder == null)
			ESAPI.encoder = new Encoder();
		return ESAPI.encoder;
	}

	/**
	 * @param encoder
	 *            the encoder to set
	 */
	public static void setEncoder(IEncoder encoder) {
		ESAPI.encoder = encoder;
	}

	/**
	 * @return the encryptor
	 */
	public static IEncryptor encryptor() {
		if (ESAPI.encryptor == null)
			ESAPI.encryptor = new Encryptor();
		return ESAPI.encryptor;
	}

	/**
	 * @param encryptor
	 *            the encryptor to set
	 */
	public static void setEncryptor(IEncryptor encryptor) {
		ESAPI.encryptor = encryptor;
	}

	/**
	 * @return the executor
	 */
	public static IExecutor executor() {
		if (ESAPI.executor == null)
			ESAPI.executor = new Executor();
		return ESAPI.executor;
	}

	/**
	 * @param executor
	 *            the executor to set
	 */
	public static void setExecutor(IExecutor executor) {
		ESAPI.executor = executor;
	}

	/**
	 * @return the httpUtilities
	 */
	public static IHTTPUtilities httpUtilities() {
		if (ESAPI.httpUtilities == null)
			ESAPI.httpUtilities = new HTTPUtilities();
		return ESAPI.httpUtilities;
	}

	/**
	 * @param httpUtilities
	 *            the httpUtilities to set
	 */
	public static void setHttpUtilities(IHTTPUtilities httpUtilities) {
		ESAPI.httpUtilities = httpUtilities;
	}

	/**
	 * @return the intrusionDetector
	 */
	public static IIntrusionDetector intrusionDetector() {
		if (ESAPI.intrusionDetector == null)
			ESAPI.intrusionDetector = new IntrusionDetector();
		return ESAPI.intrusionDetector;
	}

	/**
	 * @param intrusionDetector
	 *            the intrusionDetector to set
	 */
	public static void setIntrusionDetector(IIntrusionDetector intrusionDetector) {
		ESAPI.intrusionDetector = intrusionDetector;
	}

	private static ILogFactory logFactory() {
		if (logFactory == null)
			logFactory = new JavaLogFactory(securityConfiguration().getApplicationName());
		return logFactory;
	}
	
	/**
	 * 
	 */
	public static ILogger getLogger(Class clazz) {
		return logFactory().getLogger(clazz);
	}
	
	/**
	 * 
	 */
	public static ILogger getLogger(String name) {
		return logFactory().getLogger(name);
	}
	
	public static ILogger log() {
		if (defaultLogger == null)
			defaultLogger = logFactory().getLogger("");
		return defaultLogger;
	}
	
	 /**
	 * @param factory the log factory to set
	 */
	 public static void setLogger(ILogFactory factory) {
		 ESAPI.logFactory = factory;
	 }
	
	/**
	 * @return the randomizer
	 */
	public static IRandomizer randomizer() {
		if (ESAPI.randomizer == null)
			ESAPI.randomizer = new Randomizer();
		return ESAPI.randomizer;
	}

	/**
	 * @param randomizer
	 *            the randomizer to set
	 */
	public static void setRandomizer(IRandomizer randomizer) {
		ESAPI.randomizer = randomizer;
	}

	/**
	 * @return the securityConfiguration
	 */
	public static ISecurityConfiguration securityConfiguration() {
		if (ESAPI.securityConfiguration == null)
			ESAPI.securityConfiguration = new SecurityConfiguration();
		return ESAPI.securityConfiguration;
	}

	/**
	 * @param securityConfiguration
	 *            the securityConfiguration to set
	 */
	public static void setSecurityConfiguration(
			ISecurityConfiguration securityConfiguration) {
		ESAPI.securityConfiguration = securityConfiguration;
	}

	/**
	 * @return the validator
	 */
	public static IValidator validator() {
		if (ESAPI.validator == null)
			ESAPI.validator = new Validator();
		return ESAPI.validator;
	}

	/**
	 * @param validator
	 *            the validator to set
	 */
	public static void setValidator(IValidator validator) {
		ESAPI.validator = validator;
	}

}
