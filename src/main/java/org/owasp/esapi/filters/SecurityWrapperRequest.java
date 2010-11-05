/**
 * OWASP Enterprise Security API (ESAPI) This file is part of the Open Web
 * Application Security Project (OWASP) Enterprise Security API (ESAPI) project.
 * For details, please see <a
 * href="http://www.owasp.org/index.php/ESAPI">http://
 * www.owasp.org/index.php/ESAPI</a>. Copyright (c) 2007 - The OWASP Foundation
 * The ESAPI is published by OWASP under the BSD license. You should read and
 * accept the LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect
 *         Security</a>
 * @created 2007
 */
package org.owasp.esapi.filters;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletInputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.errors.AccessControlException;

/**
 * This request wrapper simply overrides unsafe methods in the
 * HttpServletRequest API with safe versions that return canonicalized data
 * where possible. The wrapper returns a safe value when a validation error is
 * detected, including stripped or empty strings.
 */
public class SecurityWrapperRequest extends HttpServletRequestWrapper implements HttpServletRequest {

    private final Logger logger = ESAPI.getLogger("SecurityWrapperRequest");

    private String allowableContentRoot = "WEB-INF";

    /** 
     * Construct a safe request that overrides the default request methods with
     * safer versions.
     * 
     * @param request The {@code HttpServletRequest} we are wrapping.
     */
    public SecurityWrapperRequest(HttpServletRequest request) {
    	super( request );
    }

    private HttpServletRequest getHttpServletRequest() {
    	return (HttpServletRequest)super.getRequest();
    }
    
    /**
     * Same as HttpServletRequest, no security changes required.
     * @param name The attribute name
     * @return The attribute value
     */
    public Object getAttribute(String name) {
        return getHttpServletRequest().getAttribute(name);
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return An {@code Enumeration} of attribute names.
     */
    public Enumeration getAttributeNames() {
        return getHttpServletRequest().getAttributeNames();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return The authentication type
     */
    public String getAuthType() {
        return getHttpServletRequest().getAuthType();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return  The character-encoding for this {@code HttpServletRequest}
     */
    public String getCharacterEncoding() {
        return getHttpServletRequest().getCharacterEncoding();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return The content-length for this {@code HttpServletRequest}
     */
    public int getContentLength() {
        return getHttpServletRequest().getContentLength();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return The content-type for this {@code HttpServletRequest}
     */
    public String getContentType() {
        return getHttpServletRequest().getContentType();
    }

    /**
     * Returns the context path from the HttpServletRequest after canonicalizing
     * and filtering out any dangerous characters.
     * @return The context path for this {@code HttpServletRequest}
     */
    public String getContextPath() {
        String path = getHttpServletRequest().getContextPath();
        String clean = "";
        try {
            clean = ESAPI.validator().getValidInput("HTTP context path: " + path, path, "HTTPContextPath", 150, true);
        } catch (ValidationException e) {
            // already logged
        }
        return clean;
    }

    /**
     * Returns the array of Cookies from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters.
     * @return An array of {@code Cookie}s for this {@code HttpServletRequest}
     */
    public Cookie[] getCookies() {
        Cookie[] cookies = getHttpServletRequest().getCookies();
        if (cookies == null) return new Cookie[0];
        
        List<Cookie> newCookies = new ArrayList<Cookie>();
        for (Cookie c : cookies) {
            // build a new clean cookie
            try {
                // get data from original cookie
                String name = ESAPI.validator().getValidInput("Cookie name: " + c.getName(), c.getName(), "HTTPCookieName", 150, true);
                String value = ESAPI.validator().getValidInput("Cookie value: " + c.getValue(), c.getValue(), "HTTPCookieValue", 1000, true);
                int maxAge = c.getMaxAge();
                String domain = c.getDomain();
                String path = c.getPath();
				
                Cookie n = new Cookie(name, value);
                n.setMaxAge(maxAge);

                if (domain != null) {
                    n.setDomain(ESAPI.validator().getValidInput("Cookie domain: " + domain, domain, "HTTPHeaderValue", 200, false));
                }
                if (path != null) {
                    n.setPath(ESAPI.validator().getValidInput("Cookie path: " + path, path, "HTTPHeaderValue", 200, false));
                }
                newCookies.add(n);
            } catch (ValidationException e) {
                logger.warning(Logger.SECURITY_FAILURE, "Skipping bad cookie: " + c.getName() + "=" + c.getValue(), e );
            }
        }
        return newCookies.toArray(new Cookie[newCookies.size()]);
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @param name Specifies the name of the HTTP request header; e.g.,
     *             {@code If-Modified-Since}.
     * @return a long value representing the date specified in the header
     * expressed as the number of milliseconds since {@code January 1, 1970 GMT},
     * or {@code -1} if the named header was not included with the request.
     */
    public long getDateHeader(String name) {
        return getHttpServletRequest().getDateHeader(name);
    }

    /**
     * Returns the named header from the HttpServletRequest after canonicalizing
     * and filtering out any dangerous characters.
     * @param name The name of an HTTP request header
     * @return The specified header value is returned.
     */
    public String getHeader(String name) {
        String value = getHttpServletRequest().getHeader(name);
        String clean = "";
        try {
            clean = ESAPI.validator().getValidInput("HTTP header value: " + value, value, "HTTPHeaderValue", 150, true);
        } catch (ValidationException e) {
            // already logged
        }
        return clean;
    }

    /**
     * Returns the enumeration of header names from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters.
     * @return An {@code Enumeration} of header names associated with this request.
     */
    public Enumeration getHeaderNames() {
        Vector<String> v = new Vector<String>();
        Enumeration en = getHttpServletRequest().getHeaderNames();
        while (en.hasMoreElements()) {
            try {
                String name = (String) en.nextElement();
                String clean = ESAPI.validator().getValidInput("HTTP header name: " + name, name, "HTTPHeaderName", 150, true);
                v.add(clean);
            } catch (ValidationException e) {
                // already logged
            }
        }
        return v.elements();
    }

    /**
     * Returns the enumeration of headers from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters.
     * @param name The name of an HTTP request header.
     * @return An {@code Enumeration} of headers from the request after
     *         canonicalizing and filtering has been performed.
     */
    public Enumeration getHeaders(String name) {
        Vector<String> v = new Vector<String>();
        Enumeration en = getHttpServletRequest().getHeaders(name);
        while (en.hasMoreElements()) {
            try {
                String value = (String) en.nextElement();
                String clean = ESAPI.validator().getValidInput("HTTP header value (" + name + "): " + value, value, "HTTPHeaderValue", 150, true);
                v.add(clean);
            } catch (ValidationException e) {
                // already logged
            }
        }
        return v.elements();
    }

    /**
     * Same as HttpServletRequest, no security changes required. Note that this
     * input stream may contain attacks and the developer is responsible for
     * canonicalizing, validating, and encoding any data from this stream.
     * @return The {@code ServletInputStream} associated with this
     *         {@code HttpServletRequest}.
     * @throws IOException Thrown if an input exception is thrown, such as the
     *         remote peer closing the connection.
     */
    public ServletInputStream getInputStream() throws IOException {
        return getHttpServletRequest().getInputStream();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @param name The name of an HTTP request header.
     * @return Returns the value of the specified request header as an {@code int}.
     */
    public int getIntHeader(String name) {
        return getHttpServletRequest().getIntHeader(name);
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return A {@code String} containing the IP address on which the
     *         request was received.
     */
    public String getLocalAddr() {
        return getHttpServletRequest().getLocalAddr();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return The preferred {@code Locale} for the client.
     */
    public Locale getLocale() {
        return getHttpServletRequest().getLocale();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return An {@code Enumeration} of preferred {@code Locale}
     *         objects for the client.
     */
    public Enumeration getLocales() {
        return getHttpServletRequest().getLocales();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return A {@code String} containing the host name of the IP on which
     *         the request was received.
     */
    public String getLocalName() {
        return getHttpServletRequest().getLocalName();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return Returns the Internet Protocol (IP) port number of the interface
     *         on which the request was received.
     */
    public int getLocalPort() {
        return getHttpServletRequest().getLocalPort();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return Returns the name of the HTTP method with which this request was made.
     */
    public String getMethod() {
        return getHttpServletRequest().getMethod();
    }

    /**
     * Returns the named parameter from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters.
     * @param name The parameter name for the request
     * @return The "scrubbed" parameter value.
     */
    public String getParameter(String name) {
        return getParameter(name, true);
    }

    /**
     * Returns the named parameter from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters.
     * @param name The parameter name for the request
     * @param allowNull Whether null values are allowed
     * @return The "scrubbed" parameter value.
     */
    public String getParameter(String name, boolean allowNull) {
        return getParameter(name, allowNull, 2000, "HTTPParameterValue");
    }

    /**
     * Returns the named parameter from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters.
     * @param name The parameter name for the request
     * @param allowNull Whether null values are allowed
     * @param maxLength The maximum length allowed
     * @return The "scrubbed" parameter value.
     */
    public String getParameter(String name, boolean allowNull, int maxLength) {
        return getParameter(name,allowNull,maxLength,"HTTPParameterValue");
    }

    /**
     * Returns the named parameter from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters.
     * @param name The parameter name for the request
     * @param allowNull Whether null values are allowed
     * @param maxLength The maximum length allowed
     * @param regexName The name of the regex mapped from ESAPI.properties
     * @return The "scrubbed" parameter value.
     */
    public String getParameter(String name, boolean allowNull, int maxLength, String regexName) {
        String orig = getHttpServletRequest().getParameter(name);
        String clean = null;
        try {
            clean = ESAPI.validator().getValidInput("HTTP parameter name: " + name, orig, regexName, maxLength, allowNull);
        } catch (ValidationException e) {
            // already logged
        }
        return clean;
    }

    /**
     * Returns the parameter map from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters.
     * @return A {@code Map} containing scrubbed parameter names / value pairs.
     */
    public Map getParameterMap() {
        @SuppressWarnings({"unchecked"})
        Map<String,String[]> map = getHttpServletRequest().getParameterMap();
        Map<String,String[]> cleanMap = new HashMap<String,String[]>();
        for (Object o : map.entrySet()) {
            try {
                Map.Entry e = (Map.Entry) o;
                String name = (String) e.getKey();
                String cleanName = ESAPI.validator().getValidInput("HTTP parameter name: " + name, name, "HTTPParameterName", 100, true);

                String[] value = (String[]) e.getValue();
                String[] cleanValues = new String[value.length];
                for (int j = 0; j < value.length; j++) {
                    String cleanValue = ESAPI.validator().getValidInput("HTTP parameter value: " + value[j], value[j], "HTTPParameterValue", 2000, true);
                    cleanValues[j] = cleanValue;
                }
                cleanMap.put(cleanName, cleanValues);
            } catch (ValidationException e) {
                // already logged
            }
        }
        return cleanMap;
    }

    /**
     * Returns the enumeration of parameter names from the HttpServletRequest
     * after canonicalizing and filtering out any dangerous characters.
     * @return An {@code Enumeration} of properly "scrubbed" parameter names.
     */
    public Enumeration getParameterNames() {
        Vector<String> v = new Vector<String>();
        Enumeration en = getHttpServletRequest().getParameterNames();
        while (en.hasMoreElements()) {
            try {
                String name = (String) en.nextElement();
                String clean = ESAPI.validator().getValidInput("HTTP parameter name: " + name, name, "HTTPParameterName", 150, true);
                v.add(clean);
            } catch (ValidationException e) {
                // already logged
            }
        }
        return v.elements();
    }

    /**
     * Returns the array of matching parameter values from the
     * HttpServletRequest after canonicalizing and filtering out any dangerous
     * characters.
     * @param name The parameter name
     * @return An array of matching "scrubbed" parameter values or
     * <code>null</code> if the parameter does not exist.
     */
    public String[] getParameterValues(String name) {
        String[] values = getHttpServletRequest().getParameterValues(name);
        List<String> newValues;

	if(values == null)
		return null;
        newValues = new ArrayList<String>();
        for (String value : values) {
            try {
                String cleanValue = ESAPI.validator().getValidInput("HTTP parameter value: " + value, value, "HTTPParameterValue", 2000, true);
                newValues.add(cleanValue);
            } catch (ValidationException e) {
                logger.warning(Logger.SECURITY_FAILURE, "Skipping bad parameter");
            }
        }
        return newValues.toArray(new String[newValues.size()]);
    }

    /**
     * Returns the path info from the HttpServletRequest after canonicalizing
     * and filtering out any dangerous characters.
     * @return Returns any extra path information, appropriately scrubbed,
     *         associated with the URL the client sent when it made this request.
     */
    public String getPathInfo() {
        String path = getHttpServletRequest().getPathInfo();
		if (path == null) return null;
        String clean = "";
        try {
            clean = ESAPI.validator().getValidInput("HTTP path: " + path, path, "HTTPPath", 150, true);
        } catch (ValidationException e) {
            // already logged
        }
        return clean;
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return Returns any extra path information, appropriate scrubbed,
     *         after the servlet name but before the query string, and
     *         translates it to a real path.
     */
    public String getPathTranslated() {
        return getHttpServletRequest().getPathTranslated();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return Returns the name and version of the protocol the request uses in
     *       the form protocol/majorVersion.minorVersion, for example, HTTP/1.1.
     */
    public String getProtocol() {
        return getHttpServletRequest().getProtocol();
    }

    /**
     * Returns the query string from the HttpServletRequest after canonicalizing
     * and filtering out any dangerous characters.
     * @return The scrubbed query string is returned.
     */
    public String getQueryString() {
        String query = getHttpServletRequest().getQueryString();
        String clean = "";
        try {
            clean = ESAPI.validator().getValidInput("HTTP query string: " + query, query, "HTTPQueryString", 2000, true);
        } catch (ValidationException e) {
            // already logged
        }
        return clean;
    }

    /**
     * Same as HttpServletRequest, no security changes required. Note that this
     * reader may contain attacks and the developer is responsible for
     * canonicalizing, validating, and encoding any data from this stream.
     * @return aA {@code BufferedReader} containing the body of the request. 
     * @throws IOException If an input error occurred while reading the request
     *                     body (e.g., premature EOF).
     */
    public BufferedReader getReader() throws IOException {
        return getHttpServletRequest().getReader();
    }

    // CHECKME: Should this be deprecated since ServletRequest.getRealPath(String)
    //          is deprecated? Should use ServletContext.getRealPath(String) instead.
    /**
     * Same as HttpServletRequest, no security changes required.
     * @param path A virtual path on a web or application server; e.g., "/index.htm".
     * @return Returns a String containing the real path for a given virtual path.
     * @deprecated in servlet spec 2.1. Use {@link javax.servlet.ServletContext#getRealPath(String)} instead.
     */
    @SuppressWarnings({"deprecation"})
    @Deprecated
    public String getRealPath(String path) {
        return getHttpServletRequest().getRealPath(path);
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return Returns the IP address of the client or last proxy that sent the request.
     */
    public String getRemoteAddr() {
        return getHttpServletRequest().getRemoteAddr();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return The remote host
     */
    public String getRemoteHost() {
        return getHttpServletRequest().getRemoteHost();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return The remote port
     */
    public int getRemotePort() {
        return getHttpServletRequest().getRemotePort();
    }

    /**
     * Returns the name of the ESAPI user associated with this getHttpServletRequest().
     * @return Returns the fully qualified name of the client or the last proxy
     *         that sent the request
     */
    public String getRemoteUser() {
        return ESAPI.authenticator().getCurrentUser().getAccountName();
    }

    /**
     * Checks to make sure the path to forward to is within the WEB-INF
     * directory and then returns the dispatcher. Otherwise returns null.
     * @param path The path to create a request dispatcher for
     * @return A {@code RequestDispatcher} object that acts as a wrapper for the
     *         resource at the specified path, or null if the servlet container
     *         cannot return a {@code RequestDispatcher}.
     */
    public RequestDispatcher getRequestDispatcher(String path) {
        if (path.startsWith(allowableContentRoot)) {
            return getHttpServletRequest().getRequestDispatcher(path);
        }
        return null;
    }

    /**
     * Returns the URI from the HttpServletRequest after canonicalizing and
     * filtering out any dangerous characters. Code must be very careful not to
     * depend on the value of a requested session id reported by the user.
     * @return The requested Session ID
     */
    public String getRequestedSessionId() {
        String id = getHttpServletRequest().getRequestedSessionId();
        String clean = "";
        try {
            clean = ESAPI.validator().getValidInput("Requested cookie: " + id, id, "HTTPJSESSIONID", 50, false);
        } catch (ValidationException e) {
            // already logged
        }
        return clean;
    }

    /**
     * Returns the URI from the HttpServletRequest after canonicalizing and
     * filtering out any dangerous characters.
     * @return The current request URI
     */
    public String getRequestURI() {
        String uri = getHttpServletRequest().getRequestURI();
        String clean = "";
        try {
            clean = ESAPI.validator().getValidInput("HTTP URI: " + uri, uri, "HTTPURI", 2000, false);
        } catch (ValidationException e) {
            // already logged
        }
        return clean;
    }

    /**
     * Returns the URL from the HttpServletRequest after canonicalizing and
     * filtering out any dangerous characters.
     * @return The currect request URL
     */
    public StringBuffer getRequestURL() {
        String url = getHttpServletRequest().getRequestURL().toString();
        String clean = "";
        try {
            clean = ESAPI.validator().getValidInput("HTTP URL: " + url, url, "HTTPURL", 2000, false);
        } catch (ValidationException e) {
            // already logged
        }
        return new StringBuffer(clean);
    }

    /**
     * Returns the scheme from the HttpServletRequest after canonicalizing and
     * filtering out any dangerous characters.
     * @return The scheme of the current request
     */
    public String getScheme() {
        String scheme = getHttpServletRequest().getScheme();
        String clean = "";
        try {
            clean = ESAPI.validator().getValidInput("HTTP scheme: " + scheme, scheme, "HTTPScheme", 10, false);
        } catch (ValidationException e) {
            // already logged
        }
        return clean;
    }

    /**
     * Returns the server name (host header) from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters.
     * @return The local server name
     */
    public String getServerName() {
        String name = getHttpServletRequest().getServerName();
        String clean = "";
        try {
            clean = ESAPI.validator().getValidInput("HTTP server name: " + name, name, "HTTPServerName", 100, false);
        } catch (ValidationException e) {
            // already logged
        }
        return clean;
    }

    /**
     * Returns the server port (after the : in the host header) from the
     * HttpServletRequest after parsing and checking the range 0-65536.
     * @return The local server port
     */
	public int getServerPort() {
		int port = getHttpServletRequest().getServerPort();
		if ( port < 0 || port > 0xFFFF ) {
			logger.warning( Logger.SECURITY_FAILURE, "HTTP server port out of range: " + port );
			port = 0;
		}
		return port;
	}
 	

    /**
     * Returns the server path from the HttpServletRequest after canonicalizing
     * and filtering out any dangerous characters.
     * @return The servlet path
     */
    public String getServletPath() {
        String path = getHttpServletRequest().getServletPath();
        String clean = "";
        try {
            clean = ESAPI.validator().getValidInput("HTTP servlet path: " + path, path, "HTTPServletPath", 100, false);
        } catch (ValidationException e) {
            // already logged
        }
        return clean;
    }

    /**
     * Returns a session, creating it if necessary, and sets the HttpOnly flag
     * on the Session ID cookie.
     * @return The current session
     */
    public HttpSession getSession() {
		HttpSession session = getHttpServletRequest().getSession();

		// send a new cookie header with HttpOnly on first and second responses
	    if (ESAPI.securityConfiguration().getForceHttpOnlySession()) {
	        if (session.getAttribute("HTTP_ONLY") == null) {
				session.setAttribute("HTTP_ONLY", "set");
				Cookie cookie = new Cookie(ESAPI.securityConfiguration().getHttpSessionIdName(), session.getId());
				cookie.setPath( getHttpServletRequest().getContextPath() );
				cookie.setMaxAge(-1); // session cookie
	            HttpServletResponse response = ESAPI.currentResponse();
	            if (response != null) {
	                ESAPI.currentResponse().addCookie(cookie);
	            }
	        }
	    }
        return session;
    }

    /**
     * Returns a session, creating it if necessary, and sets the HttpOnly flag
     * on the Session ID cookie.
     * @param create Create a new session if one doesn't exist
     * @return The current session
     */
    public HttpSession getSession(boolean create) {
        HttpSession session = getHttpServletRequest().getSession(create);
        if (session == null) {
            return null;
        }

        // send a new cookie header with HttpOnly on first and second responses
        if (ESAPI.securityConfiguration().getForceHttpOnlySession()) {
	        if (session.getAttribute("HTTP_ONLY") == null) {
	            session.setAttribute("HTTP_ONLY", "set");
	            Cookie cookie = new Cookie(ESAPI.securityConfiguration().getHttpSessionIdName(), session.getId());
	            cookie.setMaxAge(-1); // session cookie
	            cookie.setPath( getHttpServletRequest().getContextPath() );
	            HttpServletResponse response = ESAPI.currentResponse();
	            if (response != null) {
	                ESAPI.currentResponse().addCookie(cookie);
	            }
	        }
        }
        return session;
    }

    /**
     * Returns the ESAPI User associated with this getHttpServletRequest().
     * @return The ESAPI User
     */
    public Principal getUserPrincipal() {
        return ESAPI.authenticator().getCurrentUser();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return if requested session id is from a cookie
     */
    public boolean isRequestedSessionIdFromCookie() {
        return getHttpServletRequest().isRequestedSessionIdFromCookie();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return Whether the requested session id is from the URL
     * @deprecated in servlet spec 2.1. Use {@link #isRequestedSessionIdFromURL()} instead.
     */
    @SuppressWarnings({"deprecation"})
    @Deprecated
    public boolean isRequestedSessionIdFromUrl() {
        return getHttpServletRequest().isRequestedSessionIdFromUrl();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return Whether the requested session id is from the URL
     */
    public boolean isRequestedSessionIdFromURL() {
        return getHttpServletRequest().isRequestedSessionIdFromURL();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return Whether the requested session id is valid
     */
    public boolean isRequestedSessionIdValid() {
        return getHttpServletRequest().isRequestedSessionIdValid();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return Whether the current request is secure
     */
    public boolean isSecure() {
        try {
            ESAPI.httpUtilities().assertSecureChannel();
        } catch (AccessControlException e) {
            return false;
        }
        return true;
    }

    /**
     * Returns true if the ESAPI User associated with this request has the
     * specified role.
     * @param role The role to check
     * @return Whether the current user is in the passed role
     */
    public boolean isUserInRole(String role) {
        return ESAPI.authenticator().getCurrentUser().isInRole(role);
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @param name The attribute name
     */
    public void removeAttribute(String name) {
        getHttpServletRequest().removeAttribute(name);
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @param name The attribute name
     * @param o The attribute value
     */
    public void setAttribute(String name, Object o) {
        getHttpServletRequest().setAttribute(name, o);
    }

    /**
     * Sets the character encoding scheme to the ESAPI configured encoding scheme.
     * @param enc The encoding scheme
     * @throws UnsupportedEncodingException
     */
    public void setCharacterEncoding(String enc) throws UnsupportedEncodingException {
        getHttpServletRequest().setCharacterEncoding(ESAPI.securityConfiguration().getCharacterEncoding());
    }

    public String getAllowableContentRoot() {
        return allowableContentRoot;
    }

    public void setAllowableContentRoot(String allowableContentRoot) {
        this.allowableContentRoot = allowableContentRoot.startsWith( "/" ) ? allowableContentRoot : "/" + allowableContentRoot;
    }
}
