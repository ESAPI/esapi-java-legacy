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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.reference.DefaultSecurityConfiguration;
import org.owasp.esapi.util.*;

// DISCUSS: Many of these 'setter' methods seem like they should require proper access control
//		    checks. By default, permissions could be granted to everyone, but if we have something
//			to check these (e.g., when a SecurityManager is used) for proper Permissions, we should
//			able to accomplish this w/out too much difficulty. Overkill? Perhaps...it depends on
//			your threat model. I'm more thinking preventing stupidity than maliciousness though.
//			A developer may try to get around something by sub-classing something and perhaps intend
//			it is only done for a moment, and then change it back to what it was, but has an exception
//			and there is no 'finally' block or whatever to restore the original setting and then
//			you are running with some potentially weaker version in your whole J2EE container the
//			rest of the time. If we require special permissions to do this, then at deployment
//			we could set it up so that appropriate Permissions need to be granted BEFORE allow
//			things like Authenticator, Encryptor, IntrusionDetector, etc. to be changed. (Presumably
//			a DIFFERENT party other than developers would be responsible for granting these Permissions.)
//			So for example, if someone needed to call setEncryptor() method, they might need to be
//			granted CryptoAllPermissions in order to do so, etc. And if these permissions were carefully
//			controlled, that would ensure some sort of review. To do this, we'd only make these restrictions
//			when a SecurityManager was being used; it would not mandate the use of a SecurityManager so
//			that without a security manager, everyone is allowed permissions.
//
//			Which brings me to the SECOND thing... IMHO, these 'setters' should NOT be of type 'void',
//			but be of whatever type that they are setting so that they can set the new value and return
//			the PREVIOUS value so that things can be restored as they were. The only way to do this
//			now is the somewhat clumsy:
//
//						// Note: There are some thread-safety issues here as well, but that's not what
//						//       I'm trying to illustrate here.
//					Authenticator savedAuthenticator = ESAPI.authenticator();
//					ESAPI.setAuthenticator( new MySpecialAuthenticator() );
//					... use MySpecialAuthenticator for awhile for some special cases ...
//						// Sometime later ...
//					ESAPI.setAuthenticator( savedAuthenticator ); // Restore what we were using
//
//			Is there any reason NOT to have these 'setters' return something useful? Their return
//			values can always be ignored if you are not interested in it.
/**
 * ESAPI locator class is provided to make it easy to gain access to the current ESAPI classes in use.
 * Use the set methods to override the reference implementations with instances of any custom ESAPI implementations.
 */
public final class ESAPI {

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
    /**
	 * Clears the current User, HttpRequest, and HttpResponse associated with the current thread. This method
	 * MUST be called as some containers do not properly clear threadlocal variables when the execution of
	 * a thread is complete. The suggested approach is to put this call in a finally block inside a filter.
	 * <pre>
		public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException {
			try {
				HttpServletRequest request = (HttpServletRequest) req;
				HttpServletResponse response = (HttpServletResponse) resp;
				ESAPI.httpUtilities().setCurrentHTTP(request, response);
				ESAPI.authenticator().login();
				chain.doFilter(request, response);
			} catch (Exception e) {
				logger.error( Logger.SECURITY_FAILURE, "Error in ESAPI security filter: " + e.getMessage(), e );
			} finally {
				// VERY IMPORTANT
				// clear out ThreadLocal variables
				ESAPI.clearCurrent();
			}
		}
	 * </pre>
	 * The advantages of having identity everywhere are worth the risk here.
	 */
	public static void clearCurrent() {
		authenticator().clearCurrent();
		httpUtilities().clearCurrent();
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
		if (accessController == null) {
			String accessControllerName = securityConfiguration().getAccessControlImplementation();
			accessController =  (new ObjFactory<AccessController>()).make(accessControllerName, "AccessController");
		    }
		return accessController;
	}

	/**
	 * Change the current ESAPI AccessController to the AccessController provided. 
	 * @param controller
	 *            the AccessController to set to be the current ESAPI AccessController. 
	 */
	public static void setAccessController(AccessController controller) {
		ESAPI.accessController = controller;
	}

	/**
	 * @return the current ESAPI Authenticator object being used to authenticate users for this application. 
	 */
	public static Authenticator authenticator() {
		if (authenticator == null) {
			String authenticatorName = securityConfiguration().getAuthenticationImplementation();
			authenticator =  (new ObjFactory<Authenticator>()).make(authenticatorName, "Authenticator");
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
	public static Encoder encoder() {
		if (encoder == null) {
			String encoderName = securityConfiguration().getEncoderImplementation();
			encoder =  (new ObjFactory<Encoder>()).make(encoderName, "Encoder");
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
	public static Encryptor encryptor() {
		if (encryptor == null) {
			String encryptorName = securityConfiguration().getEncryptionImplementation();
			encryptor =  (new ObjFactory<Encryptor>()).make(encryptorName, "Encryptor");
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
			executor =  (new ObjFactory<Executor>()).make(executorName, "Executor");
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
			httpUtilities =  (new ObjFactory<HTTPUtilities>()).make(httpUtilitiesName, "HTTPUtilities");
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
	public static IntrusionDetector intrusionDetector() {
		if (intrusionDetector == null) {
			String intrusionDetectorName = securityConfiguration().getIntrusionDetectionImplementation();
			intrusionDetector =  (new ObjFactory<IntrusionDetector>()).make(intrusionDetectorName, "IntrusionDetector");
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
	private static LogFactory logFactory() {
		if (logFactory == null) {
			String logFactoryName = securityConfiguration().getLogImplementation();
			logFactory =  (new ObjFactory<LogFactory>()).make(logFactoryName, "LogFactory");
		} 
		return logFactory;
	}
	
	/**
	 * @param clazz The class to associate the logger with.
	 * @return The current Logger associated with the specified class.
	 */
	@SuppressWarnings("unchecked")		// Because Eclipse wants Class<T> instead.
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
		if (randomizer == null) {
			String randomizerName = securityConfiguration().getRandomizerImplementation();
			randomizer =  (new ObjFactory<Randomizer>()).make(randomizerName, "Randomizer");
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
	 * CHECKME: Why not return the previous value here? Also, doesn't it make sense to check for null in all setters?
	 * @param securityConfiguration
	 *            the SecurityConfiguration to set to be the current ESAPI SecurityConfiguration. 
	 */
	public static void setSecurityConfiguration(
			SecurityConfiguration securityConfiguration) {
		// CHECMKE: Or perhaps use assertions? They can be disabled, but IMO, better than not checking for null at all.
		//			Whatever approach is taken, it should be used consistently throughout.
		if ( securityConfiguration != null ) {
		ESAPI.securityConfiguration = securityConfiguration;
		} else {
			// CHECKME: Alternately we could throw NullPointerException with meaningful message here.
			System.out.println("ESAPI.setSecurityConfiguration(): null passed in. Security configuration unchanged.");
	}
	}

	/**
	 * @return the current ESAPI Validator being used to validate data in this application. 
	 */
	public static Validator validator() {
		if (validator == null) {
			String validatorName = securityConfiguration().getValidationImplementation();
			validator =  (new ObjFactory<Validator>()).make(validatorName, "Validator");
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
