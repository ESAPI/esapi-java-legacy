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

import org.owasp.esapi.errors.*;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;


/**
 * The HTTPUtilities interface is a collection of methods that provide additional security related to HTTP requests,
 * responses, sessions, cookies, headers, and logging.
 * <p/>
 * <img src="doc-files/HTTPUtilities.jpg">
 * <p/>
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface HTTPUtilities
{

    final static String REMEMBER_TOKEN_COOKIE_NAME = "rtoken";
    final static int MAX_COOKIE_LEN = 4096;            // From RFC 2109
	final static int MAX_COOKIE_PAIRS = 20;			// From RFC 2109
	final static String CSRF_TOKEN_NAME = "ctoken";
	final static String ESAPI_STATE = "estate";

	final static int PARAMETER = 0;
	final static int HEADER = 1;
	final static int COOKIE = 2;


	/**
     * Calls addCookie with the *current* request.
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
     */
    void addCookie(Cookie cookie);

	/**
     * Add a cookie to the response after ensuring that there are no encoded or
     * illegal characters in the name and name and value. This method also sets
     * the secure and HttpOnly flags on the cookie.
     *
     * @param cookie
     */
    void addCookie(HttpServletResponse response, Cookie cookie);

	/**
     * Adds the current user's CSRF token (see User.getCSRFToken()) to the URL for purposes of preventing CSRF attacks.
     * This method should be used on all URLs to be put into all links and forms the application generates.
     *
     * @param href the URL to which the CSRF token will be appended
     * @return the updated URL with the CSRF token parameter added
     */
    String addCSRFToken(String href);

    /**
     * Calls addHeader with the *current* request.
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
     */
    void addHeader(String name, String value);

    /**
     * Add a header to the response after ensuring that there are no encoded or
     * illegal characters in the name and name and value. This implementation
     * follows the following recommendation: "A recipient MAY replace any linear
     * white space with a single SP before interpreting the field value or
     * forwarding the message downstream."
     * http://www.w3.org/Protocols/rfc2616/rfc2616-sec2.html#sec2.2
     *
     * @param name
     * @param value
     */
    void addHeader(HttpServletResponse response, String name, String value);

	/**
     * Calls assertSecureRequest with the *current* request.
	 */
	void assertSecureRequest() throws AccessControlException;

	/**
	 * Ensures that the request uses SSL and POST to protect any sensitive parameters
	 * in the querystring from being sniffed, logged, bookmarked, included in referer header, etc...
	 * This method should be called for any request that contains sensitive data from a web form.
     *
     * @param request
     * @throws AccessControlException if security constraints are not met
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
	 */
    void assertSecureRequest(HttpServletRequest request) throws AccessControlException;

	/**
     * Calls changeSessionIdentifier with the *current* request.
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
     */
	HttpSession changeSessionIdentifier() throws AuthenticationException;

	/**
     * Invalidate the existing session after copying all of its contents to a newly created session with a new session id.
     * Note that this is different from logging out and creating a new session identifier that does not contain the
     * existing session contents. Care should be taken to use this only when the existing session does not contain
     * hazardous contents.
     *
     * @param request
     * @return the new HttpSession with a changed id
     * @throws AuthenticationException the exception
     */
    HttpSession changeSessionIdentifier(HttpServletRequest request) throws AuthenticationException;

    /**
	 * Clears the current HttpRequest and HttpResponse associated with the current thread.
     *
	 * @see ESAPI#clearCurrent()
	 */
    void clearCurrent();

    /**
	 * Decrypts an encrypted hidden field value and returns the cleartext. If the field does not decrypt properly,
	 * an IntrusionException is thrown to indicate tampering.
     *
	 * @param encrypted hidden field value to decrypt
	 * @return decrypted hidden field value stored as a String
	 */
	String decryptHiddenField(String encrypted);

    /**
	 * Takes an encrypted querystring and returns a Map containing the original parameters.
     *
	 * @param encrypted the encrypted querystring to decrypt
	 * @return a Map object containing the decrypted querystring
	 * @throws EncryptionException
	 */
    Map<String, String> decryptQueryString(String encrypted) throws EncryptionException;

    /**
     * Calls decryptStateFromCookie with the *current* request.
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
     */
    Map<String, String> decryptStateFromCookie() throws EncryptionException;

    /**
     * Retrieves a map of data from a cookie encrypted with encryptStateInCookie().
     *
     * @param request
     * @return a map containing the decrypted cookie state value
	 * @throws EncryptionException
     */
    Map<String, String> decryptStateFromCookie(HttpServletRequest request) throws EncryptionException;

    /**
     * Encrypts a hidden field value for use in HTML.
     *
     * @param value the cleartext value of the hidden field
     * @return the encrypted value of the hidden field
     * @throws EncryptionException
     */
	String encryptHiddenField(String value) throws EncryptionException;

	/**
	 * Takes a querystring (everything after the question mark in the URL) and returns an encrypted string containing the parameters.
     *
	 * @param query the querystring to encrypt
	 * @return encrypted querystring stored as a String
	 * @throws EncryptionException
	 */
	String encryptQueryString(String query) throws EncryptionException;

	/**
	 * Calls encryptStateInCookie with the *current* response.
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
	 */
    void encryptStateInCookie(Map<String, String> cleartext) throws EncryptionException;

    /**
     * Stores a Map of data in an encrypted cookie. Generally the session is a better
     * place to store state information, as it does not expose it to the user at all.
     * If there is a requirement not to use sessions, or the data should be stored
     * across sessions (for a long time), the use of encrypted cookies is an effective
     * way to prevent the exposure.
     *
     * @param response
     * @param cleartext
     * @throws EncryptionException
     */
    void encryptStateInCookie(HttpServletResponse response, Map<String, String> cleartext) throws EncryptionException;

    /**
	 * Calls getCookie with the *current* response.
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
	 */
	String getCookie(String name) throws ValidationException;

	/**
     * A safer replacement for getCookies() in HttpServletRequest that returns the canonicalized
     * value of the named cookie after "global" validation against the
     * general type defined in ESAPI.properties. This should not be considered a replacement for
     * more specific validation.
     *
     * @param request
     * @param name
     * @return the requested cookie value
     */
	String getCookie(HttpServletRequest request, String name) throws ValidationException;

    /**
     * Returns the current user's CSRF token. If there is no current user then return null.
     *
     * @return the current users CSRF token
     */
    String getCSRFToken();

	/**
     * Retrieves the current HttpServletRequest
     *
     * @return the current request
     */
    HttpServletRequest getCurrentRequest();

	/**
     * Retrieves the current HttpServletResponse
     *
     * @return the current response
     */
    HttpServletResponse getCurrentResponse();

	/**
	 * Calls getFileUploads with the *current* request, default upload directory, and default allowed file extensions
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
	 */
	List getFileUploads() throws ValidationException;

    /**
	 * Call getFileUploads with the specified request, default upload directory, and default allowed file extensions
	 */
	List getFileUploads(HttpServletRequest request) throws ValidationException;

    /**
	 * Call getFileUploads with the specified request, specified upload directory, and default allowed file extensions
	 */
    List getFileUploads(HttpServletRequest request, File finalDir) throws ValidationException;


    /**
     * Extract uploaded files from a multipart HTTP requests. Implementations must check the content to ensure that it
     * is safe before making a permanent copy on the local filesystem. Checks should include length and content checks,
     * possibly virus checking, and path and name checks. Refer to the file checking methods in Validator for more
     * information.
     * <p/>
	 * This method uses {@link HTTPUtilities#getCurrentRequest()} to obtain the {@link HttpServletRequest} object
     *
     * @param request
     * @return List of new File objects from upload
     * @throws ValidationException if the file fails validation
     */
    List getFileUploads(HttpServletRequest request, File destinationDir, List allowedExtensions) throws ValidationException;


	/**
	 * Calls getHeader with the *current* request.
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
	 */
	String getHeader(String name) throws ValidationException;

    /**
     * A safer replacement for getHeader() in HttpServletRequest that returns the canonicalized
     * value of the named header after "global" validation against the
     * general type defined in ESAPI.properties. This should not be considered a replacement for
     * more specific validation.
     *
     * @param request
     * @param name
     * @return the requested header value
     */
	String getHeader(HttpServletRequest request, String name) throws ValidationException;

	/**
	 * Calls getParameter with the *current* request.
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
	 */
	String getParameter(String name) throws ValidationException;

    /**
     * A safer replacement for getParameter() in HttpServletRequest that returns the canonicalized
     * value of the named parameter after "global" validation against the
     * general type defined in ESAPI.properties. This should not be considered a replacement for
     * more specific validation.
     *
     * @param request
     * @param name
     * @return the requested parameter value
     */
    String getParameter(HttpServletRequest request, String name) throws ValidationException;

	/**
	 * Calls killAllCookies with the *current* request and response.
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
	 */
	void killAllCookies();

    /**
     * Kill all cookies received in the last request from the browser. Note that new cookies set by the application in
     * this response may not be killed by this method.
     *
     * @param request
     * @param response
     */
    void killAllCookies(HttpServletRequest request, HttpServletResponse response);

	/**
	 * Calls killCookie with the *current* request and response.
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
	 */
	void killCookie(String name);

    /**
     * Kills the specified cookie by setting a new cookie that expires immediately. Note that this
     * method does not delete new cookies that are being set by the application for this response.
     *
     * @param request
     * @param name
     * @param response
     */
    void killCookie(HttpServletRequest request, HttpServletResponse response, String name);

	/**
	 * Calls logHTTPRequest with the *current* request and logger.
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
	 */
	void logHTTPRequest();

    /**
     * Format the Source IP address, URL, URL parameters, and all form
     * parameters into a string suitable for the log file. Be careful not
     * to log sensitive information, and consider masking with the
     * logHTTPRequest( List parameterNamesToObfuscate ) method.
     *
     * @param request
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
     * @param request
     * @param logger the logger to write the request to
     * @param parameterNamesToObfuscate the sensitive parameters
     */
    void logHTTPRequest(HttpServletRequest request, Logger logger, List parameterNamesToObfuscate);

	/**
	 * Calls sendForward with the *current* request and response.
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
	 */
    void sendForward(String location) throws AccessControlException, ServletException, IOException;

    /**
     * This method performs a forward to any resource located inside the WEB-INF directory. Forwarding to
     * publicly accessible resources can be dangerous, as the request will have already passed the URL
     * based access control check. This method ensures that you can only forward to non-publicly
     * accessible resources.
     *
     * @param request
     * @param response
     * @param location the URL to forward to, including parameters
     * @throws AccessControlException
     * @throws ServletException
     * @throws IOException
     */
    void sendForward(HttpServletRequest request, HttpServletResponse response, String location) throws AccessControlException, ServletException, IOException;


	/**
	 * Calls sendRedirect with the *current* response.
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
	 */
    void sendRedirect(String location) throws AccessControlException, IOException;


    /**
     * This method performs a forward to any resource located inside the WEB-INF directory. Forwarding to
     * publicly accessible resources can be dangerous, as the request will have already passed the URL
     * based access control check. This method ensures that you can only forward to non-publicly
     * accessible resources.
     *
     * @param response
     * @param location the URL to forward to, including parameters
     * @throws AccessControlException
     * @throws ServletException
     * @throws IOException
     */
    void sendRedirect(HttpServletResponse response, String location) throws AccessControlException, IOException;

	/**
	 * Calls setContentType with the *current* request and response.
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
	 */
    void setContentType();

     /**
	 * Set the content type character encoding header on every HttpServletResponse in order to limit
	 * the ways in which the input data can be represented. This prevents
	 * malicious users from using encoding and multi-byte escape sequences to
	 * bypass input validation routines.
     * <p/>
	 * Implementations of this method should set the content type header to a safe value for your environment.
     * The default is text/html; charset=UTF-8 character encoding, which is the default in early
	 * versions of HTML and HTTP. See RFC 2047 (http://ds.internic.net/rfc/rfc2045.txt) for more
	 * information about character encoding and MIME.
     * <p/>
	 * The DefaultHTTPUtilities reference implementation sets the content type as specified.
     *
     * @param response The servlet response to set the content type for.
     */
    void setContentType(HttpServletResponse response);

    /**
     * Stores the current HttpRequest and HttpResponse so that they may be readily accessed throughout
     * ESAPI (and elsewhere)
     *
     * @param request  the current request
     * @param response the current response
     */
    void setCurrentHTTP(HttpServletRequest request, HttpServletResponse response);


	/**
	 * Calls setHeader with the *current* response.
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
	 */
    void setHeader(String name, String value);

    /**
     * Add a header to the response after ensuring that there are no encoded or
     * illegal characters in the name and value. "A recipient MAY replace any
     * linear white space with a single SP before interpreting the field value
     * or forwarding the message downstream."
     * http://www.w3.org/Protocols/rfc2616/rfc2616-sec2.html#sec2.2
     *
     * @param name
     * @param value
     */
    void setHeader(HttpServletResponse response, String name, String value);


	/**
	 * Calls setNoCacheHeaders with the *current* response.
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
	 */
    void setNoCacheHeaders();


    /**
     * Set headers to protect sensitive information against being cached in the browser. Developers should make this
     * call for any HTTP responses that contain any sensitive data that should not be cached within the browser or any
     * intermediate proxies or caches. Implementations should set headers for the expected browsers. The safest approach
     * is to set all relevant headers to their most restrictive setting. These include:
     * <p/>
     * <PRE>
     * Cache-Control: no-store<BR>
     * Cache-Control: no-cache<BR>
     * Cache-Control: must-revalidate<BR>
     * Expires: -1<BR>
     * </PRE>
     * <p/>
     * Note that the header "pragma: no-cache" is intended only for use in HTTP requests, not HTTP responses. However, Microsoft has chosen to
     * directly violate the standards, so we need to include that header here. For more information, please refer to the relevant standards:
     * <UL>
     * <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html">HTTP/1.1 Cache-Control "no-cache"</a>
     * <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9.1">HTTP/1.1 Cache-Control "no-store"</a>
     * <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9.2">HTTP/1.0 Pragma "no-cache"</a>
     * <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.32">HTTP/1.0 Expires</a>
     * <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.21">IE6 Caching Issues</a>
     * <LI><a href="http://support.microsoft.com/kb/937479">Firefox browser.cache.disk_cache_ssl</a>
     * <LI><a href="http://support.microsoft.com/kb/234067">Microsoft directly violates specification for pragma: no-cache</a>
     * <LI><a href="http://www.mozilla.org/quality/networking/docs/netprefs.html">Mozilla</a>
     * </UL>
     *
     * @param response
     */
    void setNoCacheHeaders(HttpServletResponse response);

	/**
	 * Calls setNoCacheHeaders with the *current* response.
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
	 */
    String setRememberToken(String password, int maxAge, String domain, String path);


    /**
	 * Set a cookie containing the current User's remember me token for automatic authentication. The use of remember me tokens
	 * is generally not recommended, but this method will help do it as safely as possible. The user interface should strongly warn
     * the user that this should only be enabled on computers where no other users will have access.
     * <p/>
     * Implementations should save the user's remember me data in an encrypted cookie and send it to the user.
     * Any old remember me cookie should be destroyed first. Setting this cookie should keep the user
	 * logged in until the maxAge passes, the password is changed, or the cookie is deleted.
	 * If the cookie exists for the current user, it should automatically be used by ESAPI to
     * log the user in, if the data is valid and not expired.
     * <p/>
	 * The ESAPI reference implementation, DefaultHTTPUtilities.setRememberToken() implements all these suggestions.
     * <p/>
     * The username can be retrieved with: User username = ESAPI.authenticator().getCurrentUser();
     *
     * @param request
     * @param password the user's password
     * @param response
     * @param maxAge the length of time that the token should be valid for in relative seconds
	 * @param domain the domain to restrict the token to or null
	 * @param path the path to restrict the token to or null
	 * @return encrypted "Remember Me" token stored as a String
	 */
    String setRememberToken(HttpServletRequest request, HttpServletResponse response, String password, int maxAge, String domain, String path);


	/**
	 * Calls verifyCSRFToken with the *current* request.
     *
	 * @see {@link HTTPUtilities#setCurrentHTTP(HttpServletRequest, HttpServletResponse)}
	 */
    void verifyCSRFToken();

    /**
     * Checks the CSRF token in the URL (see User.getCSRFToken()) against the user's CSRF token and
	 * throws an IntrusionException if it is missing.
     *
     * @param request
     * @throws IntrusionException if CSRF token is missing or incorrect
	 */
    void verifyCSRFToken(HttpServletRequest request) throws IntrusionException;

   /**
    * Gets a typed attribute from the session associated with the calling thread. If the
    * object referenced by the passed in key is not of the implied type, a ClassCastException
    * will be thrown to the calling code.
    *
    * @param    key
    *           The key that references the session attribute
    * @param    <T>
    *           The implied type of object expected.
    * @return
    *           The requested object.
    * @see      #getSessionAttribute(javax.servlet.http.HttpSession, String)
    */
    <T> T getSessionAttribute( String key );

    /**
     * Gets a typed attribute from the passed in session. This method has the same
     * responsibility as {link #getSessionAttribute(String} however only it references
     * the passed in session and thus performs slightly better since it does not need
     * to return to the Thread to get the {@link HttpSession} associated with the current
     * thread.
     *
     * @param session
     *          The session to retrieve the attribute from
     * @param key
     *          The key that references the requested object
     * @param <T>
     *          The implied type of object expected
     * @return  The requested object
     */
    <T> T getSessionAttribute( HttpSession session, String key );

    /**
     * Gets a typed attribute from the {@link HttpServletRequest} associated
     * with the caller thread. If the attribute on the request is not of the implied
     * type, a ClassCastException will be thrown back to the caller.
     *
     * @param key The key that references the request attribute.
     * @param <T> The implied type of the object expected
     * @return The requested object
     */
    <T> T getRequestAttribute( String key );

    /**
     * Gets a typed attribute from the {@link HttpServletRequest} associated
     * with the passed in request. If the attribute on the request is not of the implied
     * type, a ClassCastException will be thrown back to the caller.
     *
     * @param request The request to retrieve the attribute from
     * @param key The key that references the request attribute.
     * @param <T> The implied type of the object expected
     * @return The requested object
     */
    <T> T getRequestAttribute( HttpServletRequest request, String key );
}
