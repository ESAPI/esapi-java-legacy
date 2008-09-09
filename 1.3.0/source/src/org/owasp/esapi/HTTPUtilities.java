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
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.EnterpriseSecurityException;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.filters.SafeRequest;
import org.owasp.esapi.filters.SafeResponse;


/**
 * The HTTPUtilities interface is a collection of methods that provide additional security related to HTTP requests,
 * responses, sessions, cookies, headers, and logging.
 * <P>
 * <img src="doc-files/HTTPUtilities.jpg" height="600">
 * <P>
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface HTTPUtilities {

    /** Key for remember token cookie */
    public final static String REMEMBER_TOKEN_COOKIE_NAME = "ESAPIRememberToken";

	/**
	 * Ensures that the current request uses SSL and POST to protect any sensitive parameters
	 * in the querystring from being sniffed or logged. For example, this method should
	 * be called from any method that uses sensitive data from a web form.
	 * 
	 * This method uses {@link HTTPUtilities#getCurrentRequest()} to obtain the current {@link HttpServletRequest} object 
	 * 
	 * @throws AccessControlException if security constraints are not met
	 */
	void assertSecureRequest( HttpServletRequest request ) throws AccessControlException;

    
    /**
     * Adds the current user's CSRF token (see User.getCSRFToken()) to the URL for purposes of preventing CSRF attacks.
     * This method should be used on all URLs to be put into all links and forms the application generates.
     * 
     * @param href 
     * 		the URL to which the CSRF token will be appended
     * 
     * @return the updated URL with the CSRF token parameter added
     */
    String addCSRFToken(String href);
    
    /**
     * Get the first cookie with the matching name.
     * @param name
     * @return
     */
	Cookie getCookie(HttpServletRequest request, String name);
    
    /**
     * Returns the current user's CSRF token. If there is no current user then return null.
     * 
     * @return the current users CSRF token
     */
    String getCSRFToken();


    /**
     * Invalidate the old session after copying all of its contents to a newly created session with a new session id.
     * Note that this is different from logging out and creating a new session identifier that does not contain the
     * existing session contents. Care should be taken to use this only when the existing session does not contain
     * hazardous contents.
	 * 
	 * This method uses {@link HTTPUtilities#getCurrentRequest()} to obtain the current {@link HttpSession} object 
     * 
     * @return the new HttpSession with a changed id
     * @throws EnterpriseSecurityException the enterprise security exception
     */
    HttpSession changeSessionIdentifier( HttpServletRequest request ) throws AuthenticationException;

    
	/**
     * Checks the CSRF token in the URL (see User.getCSRFToken()) against the user's CSRF token and
	 * throws an IntrusionException if it is missing.
     * 
	 * @throws IntrusionException if CSRF token is missing or incorrect
	 */
    void verifyCSRFToken(HttpServletRequest request) throws IntrusionException;
    
    
    /**
	 * Decrypts an encrypted hidden field value and returns the cleartext. If the field does not decrypt properly,
	 * an IntrusionException is thrown to indicate tampering.
	 * 
	 * @param encrypted 
	 * 		hidden field value to decrypt
	 * 
	 * @return decrypted hidden field value stored as a String
	 */
	String decryptHiddenField(String encrypted);

	/**
	 * Set a cookie containing the current User's remember me token for automatic authentication. The use of remember me tokens
	 * is generally not recommended, but this method will help do it as safely as possible. The user interface should strongly warn
	 * the user that this should only be enabled on computers where no other users will have access.  
	 * 
	 * The username can be retrieved with: User username = ESAPI.authenticator().getCurrentUser(); 
	 * 
	 * @param password 
	 * 		the user's password
	 * @param maxAge 
	 * 		the length of time that the token should be valid for in relative seconds
	 * @param domain 
	 * 		the domain to restrict the token to or null
	 * @param path 
	 * 		the path to restrict the token to or null
	 * 
	 * @return encrypted "Remember Me" token stored as a String
	 */
	String setRememberToken(HttpServletRequest request,HttpServletResponse response, String password, int maxAge, String domain, String path);

    /**
     * Encrypts a hidden field value for use in HTML.
     * 
     * @param value 
     * 		the cleartext value of the hidden field
     * 
     * @return the encrypted value of the hidden field
     * 
     * @throws EncryptionException 
     */
	String encryptHiddenField(String value) throws EncryptionException;

	/**
	 * Takes a querystring (i.e. everything after the ? in the URL) and returns an encrypted string containing the parameters.
	 * 
	 * @param query 
	 * 		the querystring to encrypt
	 * 
	 * @return encrypted querystring stored as a String
	 * 
	 * @throws EncryptionException
	 */
	String encryptQueryString(String query) throws EncryptionException;
	
	/**
	 * Takes an encrypted querystring and returns a Map containing the original parameters.
	 * 
	 * @param encrypted 
	 * 		the encrypted querystring to decrypt
	 * 
	 * @return a Map object containing the decrypted querystring
	 * 
	 * @throws EncryptionException
	 */
	Map decryptQueryString(String encrypted) throws EncryptionException;

	
    /**
     * Extract uploaded files from a multipart HTTP requests. Implementations must check the content to ensure that it
     * is safe before making a permanent copy on the local filesystem. Checks should include length and content checks,
     * possibly virus checking, and path and name checks. Refer to the file checking methods in Validator for more
     * information.
	 * 
	 * This method uses {@link HTTPUtilities#getCurrentRequest()} to obtain the {@link HttpServletRequest} object
     * 
     * @param tempDir 
     * 		the temporary directory
     * @param finalDir 
     * 		the final directory
     * 
     * @return List of new File objects from upload
     * 
     * @throws ValidationException 
     * 		if the file fails validation
     */
    List getSafeFileUploads(HttpServletRequest request, File tempDir, File finalDir) throws ValidationException;

    /**
     * Retrieves a map of data from a cookie encrypted with encryptStateInCookie().
     * 
	 * @return a map containing the decrypted cookie state value
	 * 
	 * @throws EncryptionException
     */
    Map decryptStateFromCookie(HttpServletRequest request) throws EncryptionException ;

    /**
     * Kill all cookies received in the last request from the browser. Note that new cookies set by the application in
     * this response may not be killed by this method.
     */
    void killAllCookies(HttpServletRequest request, HttpServletResponse response);
    
    /**
     * Kills the specified cookie by setting a new cookie that expires immediately. Note that this
     * method does not delete new cookies that are being set by the application for this response. 
     */
    void killCookie(HttpServletRequest request, HttpServletResponse response, String name);

    /**
     * Stores a Map of data in an encrypted cookie. Generally the session is a better
     * place to store state information, as it does not expose it to the user at all.
     * If there is a requirement not to use sessions, or the data should be stored
     * across sessions (for a long time), the use of encrypted cookies is an effective
     * way to prevent the exposure.
     */
    void encryptStateInCookie(HttpServletResponse response, Map cleartext) throws EncryptionException;

    
    /**
     * This method perform a forward to any resource located inside the WEB-INF directory. Forwarding to
     * publicly accessible resources can be dangerous, as the request will have already passed the URL
     * based access control check. This method ensures that you can only forward to non-publicly
     * accessible resources.
	 * 
     * @param context 
     * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param location 
     * 		the URL to forward to
     * 
     * @throws AccessControlException
     * @throws ServletException
     * @throws IOException
     */
	void safeSendForward(HttpServletRequest request, HttpServletResponse response, String context, String location) throws AccessControlException,ServletException,IOException;
	

    /**
     * Sets the content type on each HTTP response, to help protect against cross-site scripting attacks and other types
     * of injection into HTML documents.
     */
    void safeSetContentType(HttpServletResponse response);

    
    /**
     * Set headers to protect sensitive information against being cached in the browser. Developers should make this
     * call for any HTTP responses that contain any sensitive data that should not be cached within the browser or any
     * intermediate proxies or caches. Implementations should set headers for the expected browsers. The safest approach
     * is to set all relevant headers to their most restrictive setting. These include:
     * 
     * <PRE>
     * 
     * Cache-Control: no-store<BR>
     * Cache-Control: no-cache<BR>
     * Cache-Control: must-revalidate<BR>
     * Expires: -1<BR>
     * 
     * </PRE>
     * 
     * Note that the header "pragma: no-cache" is only useful in HTTP requests, not HTTP responses. So even though there
     * are many articles recommending the use of this header, it is not helpful for preventing browser caching. For more
     * information, please refer to the relevant standards:
     * <UL>
     * <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html">HTTP/1.1 Cache-Control "no-cache"</a>
     * <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9.1">HTTP/1.1 Cache-Control "no-store"</a>
     * <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9.2">HTTP/1.0 Pragma "no-cache"</a>
     * <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.32">HTTP/1.0 Expires</a>
     * <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.21">IE6 Caching Issues</a>
     * <LI><a href="http://support.microsoft.com/kb/937479">Firefox browser.cache.disk_cache_ssl</a>
     * <LI><a href="http://www.mozilla.org/quality/networking/docs/netprefs.html">Mozilla</a>
     * </UL>
     * 
	 * This method uses {@link HTTPUtilities#getCurrentResponse()} to obtain the {@link HttpServletResponse} object
	 * 
     */
    void setNoCacheHeaders(HttpServletResponse response);

    /**
     * Stores the current HttpRequest and HttpResponse so that they may be readily accessed throughout
     * ESAPI (and elsewhere)
     * 
     * @param request 
     * 		the current request
     * @param response 
     * 		the current response
     */
    void setCurrentHTTP(HttpServletRequest request, HttpServletResponse response);
    
    /**
     * Retrieves the current HttpServletRequest
     * 
     * @return the current request
     */
    SafeRequest getCurrentRequest();
    
    /**
     * Retrieves the current HttpServletResponse
     * 
     * @return the current response
     */
    SafeResponse getCurrentResponse();
    
    /**
     * Format the Source IP address, URL, URL parameters, and all form
     * parameters into a string suitable for the log file. Be careful not
     * to log sensitive information, and consider masking with the
     * logHTTPRequest( List parameterNamesToObfuscate ) method.
	 * 
	 * @param logger the logger to write the request to
     */
    void logHTTPRequest(HttpServletRequest request, Logger logger);

    /**
     * Format the Source IP address, URL, URL parameters, and all form
     * parameters into a string suitable for the log file. The list of parameters to
     * obfuscate should be specified in order to prevent sensitive information
     * from being logged. If a null list is provided, then all parameters will
     * be logged. If HTTP request logging is done in a central place, the
     * parameterNamesToObfuscate could be made a configuration parameter. We
     * include it here in case different parts of the application need to obfuscate
     * different parameters.
     * 
	 * This method uses {@link HTTPUtilities#getCurrentResponse()} to obtain the {@link HttpServletResponse} object
	 * 
	 * @param logger 
	 * 		the logger to write the request to
     * @param parameterNamesToObfuscate
     * 		the sensitive parameters
     */
    void logHTTPRequest(HttpServletRequest request, Logger logger, List parameterNamesToObfuscate);

}
