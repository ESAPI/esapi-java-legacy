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
package org.owasp.esapi.filters;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.errors.ValidationException;


/**
 * This request wrapper simply overrides unsafe methods in the HttpServletRequest
 * API with safe versions that return canonicalized data where possible. The wrapper
 * returns a safe value when a validation error is detected, including stripped or 
 * empty strings.
 */
public class SafeRequest implements HttpServletRequest {

	private HttpServletRequest request;
    private final Logger logger = ESAPI.getLogger("SafeRequest");
	
	/**
	 * Construct a safe request that overrides the default request methods with safer versions.
	 * @param request
	 */
    public SafeRequest(HttpServletRequest request) {
    	this.request = request;
    }
    
    /**
     * Same as HttpServletRequest, no security changes required.
     */
	public Object getAttribute(String name) {
		return request.getAttribute(name);
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     */
	public Enumeration getAttributeNames() {
		return request.getAttributeNames();
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     */
    public String getAuthType() {
		return request.getAuthType();
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     */
	public String getCharacterEncoding() {
		return request.getCharacterEncoding();
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     */
	public int getContentLength() {
		return request.getContentLength();
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     */
	public String getContentType() {
		return request.getContentType();
	}

    /**
     * Returns the context path from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters. 
     */
    public String getContextPath() {
    	String path = request.getContextPath();
    	String clean = "";
		try {
			clean = ESAPI.validator().getValidInput( "HTTP context path: " + path, path, "HTTPContextPath", 150, false );
		} catch (ValidationException e ) {
			// already logged
		}
		return clean;
	}

    
    /**
     * Returns the array of Cookies from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters. 
     */
	public Cookie[] getCookies() {
		Cookie[] cookies = request.getCookies();
		List newCookies = new ArrayList();
		for ( int i = 0; i < cookies.length; i++ ) {
			Cookie c = cookies[i];

			// build a new clean cookie
			try {
				// get data from original cookie
				String name = ESAPI.validator().getValidInput( "Cookie name: " + c.getName(), c.getName(), "HTTPCookieName", 150, false );
				String value = ESAPI.validator().getValidInput( "Cookie value: " + c.getValue(), c.getValue(), "HTTPCookieValue", 1000, false );
				int maxAge = c.getMaxAge();
				String domain = c.getDomain();
				String path = c.getPath();
				
				Cookie n = new Cookie( name, value );
				n.setMaxAge(maxAge);
								
				if ( domain != null ) {
					n.setDomain(ESAPI.validator().getValidInput( "Cookie domain: " + domain, domain, "HTTPHeaderValue", 200, false ));
				}
				if ( path != null ) {
					n.setPath(ESAPI.validator().getValidInput( "Cookie path: " + path, path, "HTTPHeaderValue", 200, false ));
				}
				newCookies.add( n );
			} catch( ValidationException e ) {
				e.printStackTrace();
				logger.warning(Logger.SECURITY, "Skipping bad cookie: " + c.getName() + "=" + c.getValue() );
			}
		}
		return (Cookie[])newCookies.toArray(new Cookie[newCookies.size()]);
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     */
    public long getDateHeader(String name) {
    	return request.getDateHeader(name);
	}

    /**
     * Returns the named header from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters. 
     */
	public String getHeader(String name) {
    	String value = request.getHeader(name);
    	String clean = "";
		try {
			clean = ESAPI.validator().getValidInput( "HTTP header value: " + value, value, "HTTPHeaderValue", 150, false );
		} catch (ValidationException e ) {
			// already logged
		}
		return clean;
	}

    /**
     * Returns the enumeration of header names from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters. 
     */
	public Enumeration getHeaderNames() {
		Vector v = new Vector();
		Enumeration en = request.getHeaderNames();
		while ( en.hasMoreElements() ) {
			try {
				String name = (String)en.nextElement();
				String clean = ESAPI.validator().getValidInput( "HTTP header name: " + name, name, "HTTPHeaderName", 150, false );
				v.add( clean );
			} catch (ValidationException e ) {
				// already logged
			}
		}
		return v.elements();
	}

    /**
     * Returns the enumeration of headers from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters. 
     */
	public Enumeration getHeaders(String name) {
		Vector v = new Vector();
		Enumeration en = request.getHeaders(name);
		while ( en.hasMoreElements() ) {
			try {
				String value = (String)en.nextElement();
				String clean = ESAPI.validator().getValidInput( "HTTP header value (" +name+ "): " + value, value, "HTTPHeaderValue", 150, false );
				v.add( clean );
			} catch (ValidationException e ) {
				// already logged
			}
		}
		return v.elements();
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     * Note that this input stream may contain attacks and the
     * developer is responsible for canonicalizing, validating,
     * and encoding any data from this stream.
     */
	public ServletInputStream getInputStream() throws IOException {
		return request.getInputStream();
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     */
    public int getIntHeader(String name) {
    	return request.getIntHeader(name);
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     */
	public String getLocalAddr() {
		return request.getLocalAddr();
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     */
	public Locale getLocale() {
		return request.getLocale();
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     */
    public Enumeration getLocales() {
		return request.getLocales();
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     */
	public String getLocalName() {
		return request.getLocalName();
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     */
	public int getLocalPort() {
		return request.getLocalPort();
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     */
    public String getMethod() {
		return request.getMethod();
	}

    /**
     * Returns the named parameter from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters. 
     */
	public String getParameter(String name) {
		String orig = request.getParameter( name );
		String clean = "";
		try {
			clean = ESAPI.validator().getValidInput( "HTTP parameter name: " + name, orig, "HTTPParameterValue", 2000, false );
		} catch (ValidationException e ) {
			// already logged
		}
		return clean;
	}

    /**
     * Returns the parameter map from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters. 
     */
	public Map getParameterMap() {
		Map map = request.getParameterMap();
		HashMap cleanMap = new HashMap();
		Iterator i = map.entrySet().iterator();
		while ( i.hasNext() ) {
			try {
				Map.Entry e = (Map.Entry)i.next();
				String name = (String)e.getKey();
				String cleanName = ESAPI.validator().getValidInput( "HTTP parameter name: " + name, name, "HTTPParameterName", 100, false );

				String[] value = (String[])e.getValue();
				String[] cleanValues = new String[value.length];
				for( int j = 0; j < value.length; j++ ) {
					String cleanValue = ESAPI.validator().getValidInput( "HTTP parameter value: " + value[j], value[j], "HTTPParameterValue", 2000, false );
					cleanValues[j] = cleanValue;
				}
				cleanMap.put( cleanName, cleanValues);
			} catch( ValidationException e ) {
				// already logged
			}
		}
		return cleanMap;
	}

    /**
     * Returns the enumeration of parameter names from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters. 
     */
	public Enumeration getParameterNames() {
		Vector v = new Vector();
		Enumeration en = request.getParameterNames();
		while ( en.hasMoreElements() ) {
			try {
				String name = (String)en.nextElement();
				String clean = ESAPI.validator().getValidInput( "HTTP parameter name: " + name, name, "HTTPParameterName", 150, false );
				v.add( clean );
			} catch (ValidationException e ) {
				// already logged
			}
		}
		return v.elements();
	}

    /**
     * Returns the array of matching parameter values from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters. 
     */
	public String[] getParameterValues(String name) {
		String[] values = request.getParameterValues(name);
		List newValues = new ArrayList();
		for ( int i = 0; i < values.length; i++ ) {
			try {
				String value = values[i];
				String cleanValue = ESAPI.validator().getValidInput( "HTTP parameter value: " + value, value, "HTTPParameterValue", 2000, false );
				newValues.add( cleanValue );
			} catch( ValidationException e ) {
				logger.warning(Logger.SECURITY, "Skipping bad parameter" );
			}
		}
		return (String[])newValues.toArray();
	}

    /**
     * Returns the path info from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters. 
     */
    public String getPathInfo() {
    	String path = request.getPathInfo();
    	String clean = "";
		try {
			clean = ESAPI.validator().getValidInput( "HTTP path: " + path, path, "HTTPPath", 150, false );
		} catch (ValidationException e ) {
			// already logged
		}
		return clean;
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     */
   public String getPathTranslated() {
		return request.getPathTranslated();
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     */
	public String getProtocol() {
		return request.getProtocol();
	}

    /**
     * Returns the query string from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters. 
     */
	public String getQueryString() {
    	String query = request.getQueryString();
    	String clean = "";
		try {
			clean = ESAPI.validator().getValidInput( "HTTP query string: " + query, query, "HTTPQueryString", 2000, false );
		} catch (ValidationException e ) {
			// already logged
		}
		return clean;
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     * Note that this reader may contain attacks and the
     * developer is responsible for canonicalizing, validating,
     * and encoding any data from this stream.
     */
	public BufferedReader getReader() throws IOException {
		return request.getReader();
	}

	/**
     * Same as HttpServletRequest, no security changes required.
     */
	public String getRealPath(String path) {
		return request.getRealPath(path);
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     */
	public String getRemoteAddr() {
		return request.getRemoteAddr();
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     */
	public String getRemoteHost() {
		return request.getRemoteHost();
	}

    /**
     * Same as HttpServletRequest, no security changes required.
     */
	public int getRemotePort() {
		return request.getRemotePort();
	}

    /**
     * Returns the name of the ESAPI user associated with this request.
     */
	public String getRemoteUser() {
		return ESAPI.authenticator().getCurrentUser().getAccountName();
	}

    /**
     * Checks to make sure the path to forward to is within the WEB-INF directory
     * and then returns the dispatcher. Otherwise returns null.
     */
	public RequestDispatcher getRequestDispatcher(String path) {
		if (path.startsWith("WEB-INF")) {
			return request.getRequestDispatcher(path);
		}
		return null;
	}

    /**
     * Returns the URI from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters.
     * Code must be very careful not to depend on the value of a requested session id
     * reported by the user.
	 */
	public String getRequestedSessionId() {
   	String id = request.getRequestedSessionId();
    	String clean = "";
		try {
			clean = ESAPI.validator().getValidInput( "Requested cookie: " + id, id, "HTTPJSESSIONID", 50, false );
		} catch (ValidationException e ) {
			// already logged
		}
		return clean;
	}

    /**
     * Returns the URI from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters. 
     */
	public String getRequestURI() {
    	String uri = request.getRequestURI();
    	String clean = "";
		try {
			clean = ESAPI.validator().getValidInput( "HTTP URI: " + uri, uri, "HTTPURI", 2000, false );
		} catch (ValidationException e ) {
			// already logged
		}
		return clean;
	}

    /**
     * Returns the URL from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters. 
     */
	public StringBuffer getRequestURL() {
    	String url = request.getRequestURL().toString();
    	String clean = "";
		try {
			clean = ESAPI.validator().getValidInput( "HTTP URL: " + url, url, "HTTPURL", 2000, false );
		} catch (ValidationException e ) {
			// already logged
		}
		return new StringBuffer( clean );
	}

    /**
     * Returns the scheme from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters. 
     */
	public String getScheme() {
    	String scheme = request.getScheme();
    	String clean = "";
		try {
			clean = ESAPI.validator().getValidInput( "HTTP scheme: " + scheme, scheme, "HTTPScheme", 10, false );
		} catch (ValidationException e ) {
			// already logged
		}
		return clean;
	}

    /**
     * Returns the server name (host header) from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters. 
     */
	public String getServerName() {
    	String name = request.getServerName();
    	String clean = "";
		try {
			clean = ESAPI.validator().getValidInput( "HTTP server name: " + name, name, "HTTPServerName", 100, false );
		} catch (ValidationException e ) {
			// already logged
		}
		return clean;
	}

    /**
     * Returns the server port (after the : in the host header) from the HttpServletRequest after
     * parsing and checking the range 0-65536. 
     */
	public int getServerPort() {
		int port = request.getServerPort();
		if ( port < 0 || port > 0xFFFF ) {
			logger.warning( Logger.SECURITY, "HTTP server port out of range: " + port );
			port = 0;
		}
		return port;
	}
 	
    /**
     * Returns the server path from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters. 
     */
	public String getServletPath() {
    	String path = request.getServletPath();
    	String clean = "";
		try {
			clean = ESAPI.validator().getValidInput( "HTTP servlet path: " + path, path, "HTTPServletPath", 100, false );
		} catch (ValidationException e ) {
			// already logged
		}
		return clean;
	}

	/**
     * Returns a session, creating it if necessary, and sets the HttpOnly flag on the JSESSIONID cookie.
     */
	public HttpSession getSession() {
		HttpSession session = request.getSession();

		// send a new cookie header with HttpOnly on first and second responses
		if ( session.getAttribute("HTTP_ONLY") == null ) {
			session.setAttribute("HTTP_ONLY", "set" );
			Cookie cookie=new Cookie("JSESSIONID", session.getId());
			cookie.setMaxAge(-1); // session cookie
			HttpServletResponse response = ESAPI.currentResponse();
			if ( response != null ) {
				ESAPI.currentResponse().addCookie(cookie);
			}
		}
		
		return session;
	}

	/**
     * Returns a session, creating it if necessary, and sets the HttpOnly flag on the JSESSIONID cookie.
     */
	public HttpSession getSession(boolean create) {
		HttpSession session = request.getSession( create );
		if ( session == null ) {
			return null;
		}
		// send a new cookie header with HttpOnly on first and second responses
		if ( session.getAttribute("HTTP_ONLY") == null ) {
			session.setAttribute("HTTP_ONLY", "set" );
			Cookie cookie=new Cookie("JSESSIONID", session.getId());
			cookie.setMaxAge(-1); // session cookie
			HttpServletResponse response = ESAPI.currentResponse();
			if ( response != null ) {
				ESAPI.currentResponse().addCookie(cookie);
			}
		}
		
		return session;
	}

	/**
     * Returns the ESAPI User associated with this request.
     */
	public Principal getUserPrincipal() {
		return ESAPI.authenticator().getCurrentUser();
	}

	/**
     * Same as HttpServletRequest, no security changes required.
     */
	public boolean isRequestedSessionIdFromCookie() {
		return request.isRequestedSessionIdFromCookie();
	}

	/**
     * Same as HttpServletRequest, no security changes required.
     */
	public boolean isRequestedSessionIdFromUrl() {
		return request.isRequestedSessionIdFromUrl();
	}

	/**
     * Same as HttpServletRequest, no security changes required.
     */
	public boolean isRequestedSessionIdFromURL() {
		return request.isRequestedSessionIdFromURL();
	}

	/**
     * Same as HttpServletRequest, no security changes required.
     */
	public boolean isRequestedSessionIdValid() {
		return request.isRequestedSessionIdValid();
	}

	/**
     * Same as HttpServletRequest, no security changes required.
     */
	public boolean isSecure() {
		// TODO Check request method to see if this is vulnerable
		return request.isSecure();
	}

	/**
     * Returns true if the ESAPI User associated with this request has the specified role.
     */
	public boolean isUserInRole(String role) {
		return ESAPI.authenticator().getCurrentUser().isInRole(role);
	}

	/**
     * Same as HttpServletRequest, no security changes required.
     */
	public void removeAttribute(String name) {
		request.removeAttribute(name);
	}

	/**
     * Same as HttpServletRequest, no security changes required.
     */
	public void setAttribute(String name, Object o) {
		request.setAttribute(name, o);
	}

	/**
     * Sets the character encoding to the ESAPI configured encoding.
     */
	public void setCharacterEncoding(String enc) throws UnsupportedEncodingException {
		request.setCharacterEncoding( ESAPI.securityConfiguration().getCharacterEncoding() );
	}

}

