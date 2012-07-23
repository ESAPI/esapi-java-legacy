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

import org.owasp.esapi.util.ObjFactory;

/**
 * ESAPI locator class is provided to make it easy to gain access to the current ESAPI classes in use.
 * Use the set methods to override the reference implementations with instances of any custom ESAPI implementations.
 */
public final class ESAPI {
	private static String securityConfigurationImplName = System.getProperty("org.owasp.esapi.SecurityConfiguration", "org.owasp.esapi.reference.DefaultSecurityConfiguration");

	/**
	 * prevent instantiation of this class
	 */
	private ESAPI() {
	}
	
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
        return ObjFactory.make( securityConfiguration().getAccessControlImplementation(), "AccessController" );
	}

	/**
	 * @return the current ESAPI Authenticator object being used to authenticate users for this application. 
	 */
	public static Authenticator authenticator() {
        return ObjFactory.make( securityConfiguration().getAuthenticationImplementation(), "Authenticator" );
	}

	/**
	 * @return the current ESAPI Encoder object being used to encode and decode data for this application. 
	 */
	public static Encoder encoder() {
        return ObjFactory.make( securityConfiguration().getEncoderImplementation(), "Encoder" );
	}

	/**
	 * @return the current ESAPI Encryptor object being used to encrypt and decrypt data for this application. 
	 */
	public static Encryptor encryptor() {
        return ObjFactory.make( securityConfiguration().getEncryptionImplementation(), "Encryptor" );
	}

	/**
	 * @return the current ESAPI Executor object being used to safely execute OS commands for this application. 
	 */
	public static Executor executor() {
        return ObjFactory.make( securityConfiguration().getExecutorImplementation(), "Executor" );
	}

	/**
	 * @return the current ESAPI HTTPUtilities object being used to safely access HTTP requests and responses 
	 * for this application. 
	 */
	public static HTTPUtilities httpUtilities() {
        return ObjFactory.make( securityConfiguration().getHTTPUtilitiesImplementation(), "HTTPUtilities" );
	}

	/**
	 * @return the current ESAPI IntrusionDetector being used to monitor for intrusions in this application. 
	 */
	public static IntrusionDetector intrusionDetector() {
        return ObjFactory.make( securityConfiguration().getIntrusionDetectionImplementation(), "IntrusionDetector" );
	}

	/**
	 * Get the current LogFactory being used by ESAPI. If there isn't one yet, it will create one, and then 
	 * return this same LogFactory from then on.
	 * @return The current LogFactory being used by ESAPI.
	 */
	private static LogFactory logFactory() {
        return ObjFactory.make( securityConfiguration().getLogImplementation(), "LogFactory" );
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
        return logFactory().getLogger("DefaultLogger");
    }
	
	/**
	 * @return the current ESAPI Randomizer being used to generate random numbers in this application. 
	 */
	public static Randomizer randomizer() {
        return ObjFactory.make( securityConfiguration().getRandomizerImplementation(), "Randomizer" );
	}

    private static volatile SecurityConfiguration overrideConfig = null;

	/**
	 * @return the current ESAPI SecurityConfiguration being used to manage the security configuration for 
	 * ESAPI for this application. 
	 */
	public static SecurityConfiguration securityConfiguration() {
		// copy the volatile into a non-volatile to prevent TOCTTOU race condition
		SecurityConfiguration override = overrideConfig;
		if ( override != null ) {
			return override;
        }

        return ObjFactory.make( securityConfigurationImplName, "SecurityConfiguration" );
	}

	/**
	 * @return the current ESAPI Validator being used to validate data in this application. 
	 */
	public static Validator validator() {
        return ObjFactory.make( securityConfiguration().getValidationImplementation(), "Validator" );
	}

    // TODO: This should probably use the SecurityManager or some value within the current
    // securityConfiguration to determine if this method is allowed to be called. This could
    // allow for unit tests internal to ESAPI to modify the configuration for the purpose of
    // testing stuff, and allow developers to allow this in development environments but make
    // it so the securityConfiguration implementation *cannot* be modified in production environments.
    //
    // The purpose of this method is to replace the functionality provided by the setSecurityConfiguration
    // method that is no longer on this class, and allow the context configuration of the ESAPI
    // to be modified at Runtime.
    public static String initialize( String impl ) {
        String oldImpl = securityConfigurationImplName;
        securityConfigurationImplName = impl;
        return oldImpl;
    }

    /**
     * Overrides the current security configuration with a new implementation. This is meant
     * to be used as a temporary means to alter the behavior of the ESAPI and should *NEVER*
     * be used in a production environment as it will affect the behavior and configuration of
     * the ESAPI *GLOBALLY*.
     *
     * To clear an overridden Configuration, simple call this method with null for the config
     * parameter.
     *
     * @param config
     * @return
     */
    public static void override( SecurityConfiguration config ) {
        overrideConfig = config;
    }
}
