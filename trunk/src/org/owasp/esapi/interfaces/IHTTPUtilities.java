/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/esapi.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the LGPL. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi.interfaces;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.EnterpriseSecurityException;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;

/**
 * The IHTTPUtilities interface is a collection of methods that provide additional security related to HTTP requests,
 * responses, sessions, cookies, headers, and logging.
 * <P>
 * <img src="doc-files/HTTPUtilities.jpg" height="600">
 * <P>
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface IHTTPUtilities {

    /**
     * Adds the current user's CSRF token (see User.getCSRFToken()) to the URL for purposes of preventing CSRF attacks.
     * This method should be used on all URLs to be put into all links and forms the application generates.
     * 
     * @param url
     * @return the updated href with the CSRF token parameter
     */
    String addCSRFToken(String href);

    /**
     * Adds a cookie to the specified HttpServletResponse and adds the Http-Only flag.
     * 
     * @param name the name
     * @param value the value
     * @param domain the domain
     * @param path the path
     * @param response the response
     * @param maxAge the max age
     */
    void safeAddCookie(String name, String value, int maxAge, String domain, String path);
    
    /**
     * Adds a header to an HttpServletResponse after checking for special characters (such as CRLF injection) that could enable 
     * attacks like response splitting and other header-based attacks that nobody has thought of yet. 
     * 
     * @param name the name
     * @param value the value
     * @param response the response
     */
    void safeAddHeader(String name, String value) throws ValidationException;

    /**
     * Sets a header in an HttpServletResponse after checking for special characters (such as CRLF injection) that could enable 
     * attacks like response splitting and other header-based attacks that nobody has thought of yet. 
     * 
     * @param name the name
     * @param value the value
     * @param response the response
     */
    void safeSetHeader(String name, String value) throws ValidationException;

    /**
     * Invalidate the old session after copying all of its contents to a newly created session with a new session id.
     * Note that this is different from logging out and creating a new session identifier that does not contain the
     * existing session contents. Care should be taken to use this only when the existing session does not contain
     * hazardous contents.
     * 
     * @param request the request
     * @return the http session
     * @throws EnterpriseSecurityException the enterprise security exception
     */
    HttpSession changeSessionIdentifier() throws AuthenticationException;
	
	/**
     * Checks the CSRF token in the URL (see User.getCSRFToken()) against the user's CSRF token and
	 * throws an IntrusionException if it is missing.
	 * 
	 * @param request
	 * @throws IntrusionException
	 */
    void verifyCSRFToken() throws IntrusionException;
    
    /**
	 * Decrypts an encrypted hidden field value and returns the cleartest. If the field does not decrypt properly,
	 * an IntrusionException is thrown to indicate tampering.
	 * @param encrypted
	 * @return
	 */
	public String decryptHiddenField(String encrypted);
    
    /**
     * Encrypts a hidden field value for use in HTML.
     * @param value
     * @return
     * @throws EncryptionException
     */
	public String encryptHiddenField(String value) throws EncryptionException;


	/**
	 * Takes a querystring (i.e. everything after the ? in the URL) and returns an encrypted string containing the parameters.
	 * @param href
	 * @return
	 */
	public String encryptQueryString(String query) throws EncryptionException;
	
	/**
	 * Takes an encrypted querystring and returns a Map containing the original parameters.
	 * @param encrypted
	 * @return
	 */
	public Map decryptQueryString(String encrypted) throws EncryptionException;
	
    /**
     * Extract uploaded files from a multipart HTTP requests. Implementations must check the content to ensure that it
     * is safe before making a permanent copy on the local filesystem. Checks should include length and content checks,
     * possibly virus checking, and path and name checks. Refer to the file checking methods in IValidator for more
     * information.
     * 
     * @param request the request
     * @param tempDir the temp dir
     * @param finalDir the final dir
     * @return List of new File objects from upload
     * @throws ValidationException the validation exception
     */
    List getSafeFileUploads(File tempDir, File finalDir) throws ValidationException;

    /**
     * Retrieves a map of data from the encrypted cookie. 
     */
    Map decryptStateFromCookie() throws EncryptionException ;

    /**
     * Returns true if the request and response are using an SSL-enabled connection. This check should be made on
     * every request from the login page through the logout confirmation page. Essentially, any page that uses the
     * Authenticator.login() call should call this. Implementers should consider calling this method directly in
     * their Authenticator.login() method. If this method returns true for a page that requires SSL, there must be a
     * misconfiguration, an AuthenticationException is warranted. 
     * 
     * @param request
     * @return
     */
    boolean isSecureChannel();

    /**
     * Kill all cookies received in the last request from the browser. Note that new cookies set by the application in
     * this response may not be killed by this method.
     * 
     * @param request the request
     * @param response the response
     */
    void killAllCookies();
    
    /**
     * Kills the specified cookie by setting a new cookie that expires immediately.
     * 
     * @param name the cookie name
     */
    void killCookie(String name);

    /**
     * Stores a Map of data in an encrypted cookie.
     */
    void encryptStateInCookie(Map cleartext) throws EncryptionException;

    
    /**
     * This method generates a redirect response that can only be used to redirect the browser to safe locations.
     * Importantly, redirect requests can be modified by attackers, so do not rely information contained within redirect
     * requests, and do not include sensitive information in a redirect.
     * 
     * @param location the URL to redirect to
     * @param response the current HttpServletResponse
     * @throws IOException Signals that an I/O exception has occurred.
     */
    void safeSendRedirect(String context, String location) throws IOException;

    /**
     * This method perform a forward to any resource located inside the WEB-INF directory. Forwarding to
     * publically accessible resources can be dangerous, as the request will have already passed the URL
     * based access control check. This method ensures that you can only forward to non-publically
     * accessible resources.
     *  
     * @param context
     * @param location
     * @throws AccessControlException
     * @throws ServletException
     * @throws IOException
     */
	void safeSendForward(String context, String location) throws AccessControlException,ServletException,IOException;
	

    /**
     * Sets the content type on each HTTP response, to help protect against cross-site scripting attacks and other types
     * of injection into HTML documents.
     * 
     * @param response
     */
    void safeSetContentType();

    
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
     * @param response the current HttpServletResponse
     */
    void setNoCacheHeaders();

    /**
     * Stores the current HttpRequest and HttpResponse so that they may be readily accessed throughout
     * ESAPI (and elsewhere)
     * 
     * @param request the current request
     * @param response the current response
     */
    void setCurrentHTTP(HttpServletRequest request, HttpServletResponse response);
    
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
    
}
