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

import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.util.ObjFactory;
import org.owasp.esapi.errors.ConfigurationException;

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
     * The ESAPI {@code Encoder} is primarily used to provide <i>output</i> encoding to
     * prevent Cross-Site Scripting (XSS).
     * @return the current ESAPI {@code Encoder} object being used to encode and decode data for this application.
     */
    public static Encoder encoder() {
        return ObjFactory.make( securityConfiguration().getEncoderImplementation(), "Encoder" );
    }

    /**
     * ESAPI {@code Encryptor} provides a set of methods for performing common encryption, random number, and
     * hashing operations.
     * @return the current ESAPI {@code Encryptor} object being used to encrypt and decrypt data for this application.
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
     * @param config The new security configuration.
     */
    public static void override( SecurityConfiguration config ) {
        overrideConfig = config;
    }

    // KWW - OPEN ISSUE: I don't like placing this here, but it's convenient and I
    //       don't really know a better place for it and would rather not create
    //       a whole new utility class just to use it.
    /**
     * Determine if a given fully qualified (ESAPI) method name has been explicitly
     * enabled in the <b>ESAPI.properties</b>'s file via the property name
     * <b>ESAPI.dangerouslyAllowUnsafeMethods.methodNames</b>. Note that there
     * is no real reason for an ESAPI client to use this, It is intended for
     * interal use,
     * </p><p>
     * The reason this method exists is because certain (other) ESAPI method names
     * are considered "unsafe" and therefore should be used with extra caution.
     * These "unsafe" methods may include methods that are:
     * <ul>
     * <li>Deprecated and thus no longer suggested for long term use.</li>
     * <li>Methods where the programming contract is not in itself sufficient to ensure safety alone
     * and developers are expected to take addional actions on their own to secure their application.</li>
     * <li>Methods that are using some unpatched transitive dependency that we haven't firmly
     * established grounds for it not being exploitable in the manner that ESAPI uses it.</li>
     * <li>Methods whose reference implementations are not scalable to the enterprise level.</li>
     * </ul>
     * <i>Public</i> methods that are not in that list for the above ESAPI property
     * are generally are considered enabled and okay to use unless their Javadoc
     * indicates otherwise.
     * </p><p>
     * Note that this method is intended primarilly for internal ESAPI use and if we were
     * using Java Modules (in JDK 9 and later), this method would not be exported.
     * </p><p>
     * For further details, please see the ESAPI GitHub wiki article,
     * <a href="https://github.com/ESAPI/esapi-java-legacy/wiki/Reducing-the-ESAPI-Library's-Attack-Surface">"Reducing the ESAPI Library's Attack Surface"</a>.
     * @param fullyQualifiedMethodName A fully qualified ESAPI class name (so, should start
     *              "org.owasp.esapi.") followed by the method name (but without
     *              parenthesis or any parameter signature information.
     * @return {@code true} if the parameter {@code fullyQualifiedMethodName} is in the comma-separated
     *         list of values in the ESAPI property <b>ESAPI.dangerouslyAllowUnsafeMethods.methodNames</b>,
     *         otherwise {@code false} is returned.
     */
    public static boolean isMethodExplicityEnabled(String fullyQualifiedMethodName) {
        if ( fullyQualifiedMethodName == null || fullyQualifiedMethodName.trim().isEmpty() ) {
            throw new IllegalArgumentException("Program error: fullyQualifiedMethodName parameter cannot be null or empty");
        }
        String desiredMethodName = fullyQualifiedMethodName.trim();
            // This regex is too liberal to be anything more than just a trivial
            // sanity test to protect against typos.
        if ( !desiredMethodName.matches("^org\\.owasp\\.esapi\\.(\\p{Alnum}|\\.)*$") ) {
            throw new IllegalArgumentException("Program error: fullyQualifiedMethodName must start with " +
                                               "'org.owasp.esapi.' and be a valid method name.");
        }

        String enabledMethods = null;
        try {
            // Need to do this w/in a try/catch because if the property is not
            // found, getStringProp will throw a ConfigurationException rather
            // than returning a null.
            enabledMethods = securityConfiguration().getStringProp("ESAPI.dangerouslyAllowUnsafeMethods.methodNames");
        } catch( ConfigurationException cex ) {
            return false;   // Property not found at all.
        }


        // Split it up by ',' and then filter it by finding the first on that
        // matches the desired method name passed in as the method parameter.
        // If no matches, return the empty string.
        String result = Arrays.stream( enabledMethods.trim().split(",") )
                                  .filter(methodName -> methodName.trim().equals( desiredMethodName ) )
                                  .findFirst()
                                  .orElse("");
        return !result.isEmpty();
    }
}
