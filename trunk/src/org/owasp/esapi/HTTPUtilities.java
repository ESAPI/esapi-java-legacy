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
package org.owasp.esapi;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.ProgressListener;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.errors.ValidationUploadException;

/**
 * Reference implementation of the IHTTPUtilities interface. This implementation
 * uses the Apache Commons FileUploader library, which in turn uses the Apache
 * Commons IO library.
 * <P>
 * To simplify the interface, this class uses the current request and response that
 * are tracked by ThreadLocal variables in the Authenticator. This means that you
 * must have called ESAPI.authenticator().setCurrentHTTP(null, response) before
 * calling these methods. This is done automatically by the Authenticator.login() method.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.interfaces.IHTTPUtilities
 */
public class HTTPUtilities implements org.owasp.esapi.interfaces.IHTTPUtilities {

	/** The logger. */
	private static final Logger logger = Logger.getLogger("ESAPI", "HTTPUtilities");

	/** The max bytes. */
	int maxBytes = ESAPI.securityConfiguration().getAllowedFileUploadSize();
	

	public HTTPUtilities() {
	}

	// FIXME: Enhance - consider adding addQueryChecksum(String href) that would just verify that none of the parameters in the querystring have changed.  Could do the same for forms.
	// FIXME: Enhance - also verifyQueryChecksum()
	
	

	// FIXME: need to make this easier to add to forms.
	/**
	 * @see org.owasp.esapi.interfaces.IHTTPUtilities#addCSRFToken(java.lang.String)
	 */
	public String addCSRFToken(String href) {
		User user = ESAPI.authenticator().getCurrentUser();		
		
		// FIXME: AAA getCurrentUser should never return null
		if (user.isAnonymous() || user == null) {
			return href;
		}

		if ( ( href.indexOf( '?') != -1 ) || ( href.indexOf( '&' ) != -1 ) ) {
			return href + "&" + user.getCSRFToken();
		} else {
			return href + "?" + user.getCSRFToken();
		}
	}

	
	/**
	 * Adds a cookie to the HttpServletResponse that uses Secure and HttpOnly
	 * flags. This implementation does not use the addCookie method because
	 * it does not support HttpOnly, so it just creates a cookie header manually.
	 * 
	 * @see org.owasp.esapi.interfaces.IHTTPUtilities#safeAddCookie(java.lang.String,
	 *      java.lang.String, java.util.Date, java.lang.String,
	 *      java.lang.String, javax.servlet.http.HttpServletResponse)
	 */
	public void safeAddCookie(String name, String value, int maxAge, String domain, String path) {
		HttpServletResponse response = getCurrentResponse();
		try {
			String cookieName = ESAPI.validator().getValidInput( "safeAddCookie", name, "HTTPCookieName", 50, false);
			String cookieValue = ESAPI.validator().getValidInput( "safeAddCookie", value, "HTTPCookieValue", 5000, false);
			
			// FIXME: AAA need to validate domain and path! Otherwise response splitting etc..  Can use Cookie object?
			
			// create the special cookie header
			// Set-Cookie:<name>=<value>[; <name>=<value>][; expires=<date>][;
			// domain=<domain_name>][; path=<some_path>][; secure][;HttpOnly
			// FIXME: AAA test if setting a separate set-cookie header for each cookie works!
			String header = cookieName + "=" + cookieValue;
			if ( maxAge != -1 ) header += "; Max-Age=" + maxAge;
			if ( domain != null ) header += "; Domain=" + domain;
			if ( path != null ) header += "; Path=" + path;
			header += "; Secure; HttpOnly";
			response.addHeader("Set-Cookie", header);
			
		} catch( ValidationException e ) {
			logger.logWarning(Logger.SECURITY, "Attempt to set invalid cookie denied", e);
		}
	}
	
	/*
	 * Adds a header to an HttpServletResponse after checking for special
	 * characters (such as CRLF injection) that could enable attacks like
	 * response splitting and other header-based attacks that nobody has thought
	 * of yet.
	 * 
	 * @see org.owasp.esapi.interfaces.IHTTPUtilities#safeAddHeader(java.lang.String,
	 *      java.lang.String, java.lang.String,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	public void safeAddHeader(String name, String value) {
		// FIXME: this isn't a drop-in replacement -- need to make safe behavior with a log message
		HttpServletResponse response = getCurrentResponse();
		try {
			String headerName = ESAPI.validator().getValidInput( "safeAddHeader", name, "HTTPHeaderName", 50, false);
			String headerValue = ESAPI.validator().getValidInput( "safeAddHeader", value, "HTTPHeaderValue", 500, false);
			response.addHeader(headerName, headerValue);
		} catch( ValidationException e ) {
			logger.logWarning(Logger.SECURITY, "Attempt to set invalid header denied", e);
		}
	}


	// FIXME: make configurable
	public void safeSendError(int sc) throws IOException {
		HttpServletResponse response = getCurrentResponse();
		response.sendError(response.SC_OK, getHttpMessage(sc) );
	}
	
	// FIXME: make configurable
	public void safeSendError(int sc, String msg) throws IOException {
		HttpServletResponse response = getCurrentResponse();
		// FIXME: safe msg
		response.sendError(response.SC_OK, msg );
	}

	/* returns a text message for the http response code */
	private String getHttpMessage( int sc ) {
		// FIXME: implement
		return "HTTP error code: " + sc;
	}
	
	public void safeSetDateHeader( String name, long date ) {
		HttpServletResponse response = getCurrentResponse();
		try {
			String safeName = ESAPI.validator().getValidInput("safeSetDateHeader", name, "HTTPHeaderName", 20, false);
			response.setDateHeader(safeName, date);
		} catch (ValidationException e) {
			logger.logWarning(Logger.SECURITY, "Attempt to set invalid date header name denied", e);
		}
	}

	public void safeSetIntHeader( String name, int value ) {
		HttpServletResponse response = getCurrentResponse();
		try {
			String safeName = ESAPI.validator().getValidInput("safeSetDateHeader", name, "HTTPHeaderName", 20, false);
			response.setIntHeader(safeName, value);
		} catch (ValidationException e) {
			logger.logWarning(Logger.SECURITY, "Attempt to set invalid int header name denied", e);
		}
	}

	public void safeSetCharacterEncodingInResponse( String charset ) {
		HttpServletResponse response = getCurrentResponse();
		response.setCharacterEncoding(charset);
	}

	public void safeAddCookie( Cookie cookie ) {
		HttpServletResponse response = getCurrentResponse();
		response.addCookie(cookie);
	}

	public void safeSetLocale( Locale loc ) {
		HttpServletResponse response = getCurrentResponse();
		response.setLocale(loc);
	}

	public void safeSetStatus( int sc ) {
		HttpServletResponse response = getCurrentResponse();
		response.setStatus(sc);
	}

	public void safeSetStatus( int sc, String sm ) {
		HttpServletResponse response = getCurrentResponse();
		// FIXME: safe message
		response.setStatus(response.SC_OK, sm);
	}
	

	public void safeSetCharacterEncodingInRequest( String env ) throws UnsupportedEncodingException {
		getCurrentRequest().setCharacterEncoding(env);
	}
	
	
	/*
	 * Sets a header in an HttpServletResponse after checking for special
	 * characters (such as CRLF injection) that could enable attacks like
	 * response splitting and other header-based attacks that nobody has thought
	 * of yet.
	 * 
	 * @see org.owasp.esapi.interfaces.IHTTPUtilities#safeAddHeader(java.lang.String,
	 *      java.lang.String, java.lang.String,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	public void safeSetHeader(String name, String value) throws ValidationException {
		HttpServletResponse response = getCurrentResponse();
		try {
			String safeName = ESAPI.validator().getValidInput("setSafeHeader", name, "HTTPHeaderName", 20, false);
			String safeValue = ESAPI.validator().getValidInput("setSafeHeader", value, "HTTPHeaderValue", 500, false);
			response.setHeader(safeName, safeValue);
		} catch (ValidationException e) {
			logger.logWarning(Logger.SECURITY, "Attempt to set invalid header denied", e);
		}
	}
	
	//FIXME: AAA add these to the interface
	/**
	 * Return exactly what was sent to prevent URL rewriting. URL rewriting is intended to be a session management
	 * scheme that doesn't require cookies, but exposes the sessionid in many places, including the URL bar,
	 * favorites, HTML files in cache, logs, and cut-and-paste links. For these reasons, session rewriting is
	 * more dangerous than the evil cookies it was intended to replace.
	 * 
	 * @param url
	 * @return
	 */
	public String safeEncodeURL( String url ) {
		return url;
	}
	
	/**
	 * Return exactly what was sent to prevent URL rewriting. URL rewriting is intended to be a session management
	 * scheme that doesn't require cookies, but exposes the sessionid in many places, including the URL bar,
	 * favorites, HTML files in cache, logs, and cut-and-paste links. For these reasons, session rewriting is
	 * more dangerous than the evil cookies it was intended to replace.
	 * 
	 * @param url
	 * @return
	 */
	public String safeEncodeRedirectURL( String url ) {
		return url;
	}
	
	
    /*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IHTTPUtilities#changeSessionIdentifier(javax.servlet.http.HttpServletRequest)
	 */
	public HttpSession changeSessionIdentifier() throws AuthenticationException {
		HttpServletRequest request = getCurrentRequest();
		Map temp = new HashMap();
		HttpSession session = request.getSession( false );

		// make a copy of the session content
		if ( session != null ) {
			Enumeration e = session.getAttributeNames();
			while (e != null && e.hasMoreElements()) {
				String name = (String) e.nextElement();
				Object value = session.getAttribute(name);
				temp.put(name, value);
			}
			session.invalidate();
		}

		HttpSession newSession = request.getSession(true);

		// copy back the session content
		Iterator i = temp.entrySet().iterator();
		while (i.hasNext()) {
			Map.Entry entry = (Map.Entry) i.next();
			newSession.setAttribute((String) entry.getKey(), entry.getValue());
		}
		return newSession;
	}

	
	
	// FIXME: ENHANCE - add configuration for entry pages that don't require a token 
	/*
	 * This implementation uses the parameter name to store the token.
	 * (non-Javadoc)
	 * @see org.owasp.esapi.interfaces.IHTTPUtilities#verifyCSRFToken()
	 */
	public void verifyCSRFToken() throws IntrusionException {
		HttpServletRequest request = getCurrentRequest();
		User user = ESAPI.authenticator().getCurrentUser();
		
		if( request.getAttribute(user.getCSRFToken()) != null ) return;
		if (request.getParameter(user.getCSRFToken()) == null) {
			throw new IntrusionException("Authentication failed", "Possibly forged HTTP request without proper CSRF token detected");
		}
	}
    
    /*
	 * (non-Javadoc)
	 * @see org.owasp.esapi.interfaces.IHTTPUtilities#decryptHiddenField(java.lang.String)
	 */
	public String decryptHiddenField(String encrypted) {
    	try {
    		return ESAPI.encryptor().decrypt(encrypted);
    	} catch( EncryptionException e ) {
    		throw new IntrusionException("Invalid request","Tampering detected. Hidden field data did not decrypt properly.", e);
    	}
    }
	
	
	/*
	 * (non-Javadoc)
	 * @see org.owasp.esapi.interfaces.IHTTPUtilities#decryptQuueryString(java.lang.String)
	 */
	public Map decryptQueryString(String encrypted) throws EncryptionException {
		// FIXME: AAA needs test cases
		String plaintext = ESAPI.encryptor().decrypt(encrypted);
		return queryToMap(plaintext);
	}

	/**
	 * @throws EncryptionException 
     * @see org.owasp.esapi.interfaces.IHTTPUtilities#decryptStateFromCookie()
     */
    public Map decryptStateFromCookie() throws EncryptionException {
    	// FIXME: consider getEncryptedCookieValue( String name )
		HttpServletRequest request = getCurrentRequest();
		Cookie[] cookies = request.getCookies();
		Cookie c = null;
		for ( int i = 0; i < cookies.length; i++ ) {
			if ( cookies[i].getName().equals( "state" ) ) {
				c = cookies[i];
			}
		}
		String encrypted = c.getValue();
		String plaintext = ESAPI.encryptor().decrypt(encrypted);
		
		return queryToMap( plaintext );
    }

	/*
	 * (non-Javadoc)
	 * @see org.owasp.esapi.interfaces.IHTTPUtilities#encryptHiddenField(java.lang.String)
	 */
	public String encryptHiddenField(String value) throws EncryptionException {
		// FIXME: this needs better support
		// like cookie with name-value pairs
		// and an easy way to decrypt to a hashmap
    	return ESAPI.encryptor().encrypt(value);
	}
	
	/*
	 * (non-Javadoc)
	 * @see org.owasp.esapi.interfaces.IHTTPUtilities#encryptQueryString(java.lang.String)
	 */
	public String encryptQueryString(String query) throws EncryptionException {
		// FIXME: this needs better support
		// like cookie with name-value pairs
		// and an easy way to decrypt to a hashmap
		return ESAPI.encryptor().encrypt( query );
	}

	/**
	 * @throws EncryptionException 
     * @see org.owasp.esapi.interfaces.IHTTPUtilities#encryptStateInCookie(java.util.Map)
     */
    public void encryptStateInCookie(Map cleartext) throws EncryptionException {
    	StringBuffer sb = new StringBuffer();    	
    	Iterator i = cleartext.entrySet().iterator();
    	while ( i.hasNext() ) {
    		try {
	    		Map.Entry entry = (Map.Entry)i.next();
	    		String name = ESAPI.encoder().encodeForURL( entry.getKey().toString() );
	    		String value = ESAPI.encoder().encodeForURL( entry.getValue().toString() );
	    		sb.append( name + "=" + value );
	    		if ( i.hasNext() ) sb.append( "&" );
    		} catch( EncodingException e ) {
    			logger.logError(Logger.SECURITY, "Problem encrypting state in cookie - skipping entry", e );
    		}
    	}
    	// FIXME: AAA - add a check to see if cookie length will exceed 2K limit
    	String encrypted = ESAPI.encryptor().encrypt(sb.toString());
    	this.safeAddCookie("state", encrypted, -1, null, null );
    }

	/**
	 * Uses the Apache Commons FileUploader to parse the multipart HTTP request
	 * and extract any files therein. Note that the progress of any uploads is
	 * put into a session attribute, where it can be retrieved with a simple
	 * JSP.
	 * 
	 * @see org.owasp.esapi.interfaces.IHTTPUtilities#safeGetFileUploads(javax.servlet.http.HttpServletRequest,
	 *      java.io.File, java.io.File, int)
	 * @return list of File objects for new files in final directory
	 */
	public List getSafeFileUploads(File tempDir, File finalDir) throws ValidationException {
		if ( !tempDir.exists() ) tempDir.mkdirs();
		if ( !finalDir.exists() ) finalDir.mkdirs();
		List newFiles = new ArrayList();
		HttpServletRequest request = getCurrentRequest();
		try {
			final HttpSession session = request.getSession();
			if (!ServletFileUpload.isMultipartContent(request)) {
				throw new ValidationUploadException("Upload failed", "Not a multipart request");
			}

			// this factory will store ALL files in the temp directory,
			// regardless of size
			DiskFileItemFactory factory = new DiskFileItemFactory(0, tempDir);
			ServletFileUpload upload = new ServletFileUpload(factory);
			upload.setSizeMax(maxBytes);

			// Create a progress listener
			ProgressListener progressListener = new ProgressListener() {
				private long megaBytes = -1;
				private long progress = 0;

				public void update(long pBytesRead, long pContentLength, int pItems) {
					if (pItems == 0)
						return;
					long mBytes = pBytesRead / 1000000;
					if (megaBytes == mBytes)
						return;
					megaBytes = mBytes;
					progress = (long) (((double) pBytesRead / (double) pContentLength) * 100);
					session.setAttribute("progress", Long.toString(progress));
					// logger.logSuccess(Logger.SECURITY, "   Item " + pItems + " (" + progress + "% of " + pContentLength + " bytes]");
				}
			};
			upload.setProgressListener(progressListener);

			List items = upload.parseRequest(request);
			Iterator i = items.iterator();
			while (i.hasNext()) {
				FileItem item = (FileItem) i.next();
				if (!item.isFormField() && item.getName() != null && !(item.getName().equals("")) ) {
					String[] fparts = item.getName().split("[\\/\\\\]");
					String filename = fparts[fparts.length - 1];

					if (!ESAPI.validator().isValidFileName("upload", filename, false)) {
						throw new ValidationUploadException("Upload only simple filenames with the following extensions " + ESAPI.securityConfiguration().getAllowedFileExtensions(), "Upload failed isValidFileName check");
					}

					logger.logCritical(Logger.SECURITY, "File upload requested: " + filename);
					File f = new File(finalDir, filename);
					if (f.exists()) {
						String[] parts = filename.split("\\/.");
						String extension = "";
						if (parts.length > 1) {
							extension = parts[parts.length - 1];
						}
						String filenm = filename.substring(0, filename.length() - extension.length());
						f = File.createTempFile(filenm, "." + extension, finalDir);
					}
					item.write(f);
					newFiles.add( f );
					// delete temporary file
					item.delete();
					logger.logCritical(Logger.SECURITY, "File successfully uploaded: " + f);
					session.setAttribute("progress", Long.toString(0));
				}
			}
		} catch (Exception e) {
			if (e instanceof ValidationUploadException)
				throw (ValidationException) e;
			throw new ValidationUploadException("Upload failure", "Problem during upload:" + e.getMessage(), e);
		}
		return newFiles;
	}

	/**
	 * Returns true if the request was transmitted over an SSL enabled
	 * connection. This implementation ignores the built-in isSecure() method
	 * and uses the URL to determine if the request was transmitted over SSL.
	 */
	public boolean isSecureChannel() {
		HttpServletRequest request = getCurrentRequest();
		return (request.getRequestURL().charAt(4) == 's');
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IHTTPUtilities#killAllCookies(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	public void killAllCookies() {
		HttpServletRequest request = getCurrentRequest();
		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (int i = 0; i < cookies.length; i++) {
				Cookie cookie = cookies[i];
				killCookie(cookie.getName());
			}
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IHTTPUtilities#killCookie(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	public void killCookie(String name) {
		HttpServletRequest request = getCurrentRequest();
		HttpServletResponse response = getCurrentResponse();
		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (int i = 0; i < cookies.length; i++) {
				Cookie cookie = cookies[i];
				if (cookie.getName().equals(name)) {
					String path = request.getContextPath();
					String header = name + "=deleted; Max-Age=0; Path=" + path;
					response.addHeader("Set-Cookie", header);
				}
			}
		}
	}

	private Map queryToMap(String query) {
		TreeMap map = new TreeMap();
		String[] parts = query.split("&");
		for ( int j = 0; j < parts.length; j++ ) {
			try {
				String[] nvpair = parts[j].split("=");
				String name = ESAPI.encoder().decodeFromURL(nvpair[0]);
				String value = ESAPI.encoder().decodeFromURL(nvpair[1]);
				map.put( name, value);
			} catch( EncodingException e ) {
				// skip and continue
			}
		}
		return map;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IHTTPUtilities#safeSendForward(java.lang.String)
	 */
	public void safeSendForward(String context, String location) throws AccessControlException,ServletException,IOException {
		// FIXME: should this be configurable?  What is a good forward policy?
		// I think not allowing forwards to public URLs is good, as it bypasses many access controls
		
		HttpServletRequest request = getCurrentRequest();
		HttpServletResponse response = getCurrentResponse();
		if (!location.startsWith("WEB-INF")) {
			throw new AccessControlException("Forward failed", "Bad forward location: " + location);
		}
		RequestDispatcher dispatcher = request.getRequestDispatcher(location);
		dispatcher.forward(request, response);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IHTTPUtilities#safeSendRedirect(java.lang.String)
	 */
	public void safeSendRedirect(String context, String location) throws IOException {
		HttpServletResponse response = getCurrentResponse();
		if (!ESAPI.validator().isValidRedirectLocation(context, location, false)) {
			logger.logCritical(Logger.SECURITY, "Bad redirect location: " + location );
			throw new IOException("Redirect failed");
		}
		response.sendRedirect(location);
	}

	/**
	 * Set the character encoding on every HttpServletResponse in order to limit
	 * the ways in which the input data can be represented. This prevents
	 * malicious users from using encoding and multi-byte escape sequences to
	 * bypass input validation routines. The default is text/html; charset=UTF-8
	 * character encoding, which is the default in early versions of HTML and
	 * HTTP. See RFC 2047 (http://ds.internic.net/rfc/rfc2045.txt) for more
	 * information about character encoding and MIME.
	 * 
	 * @see org.owasp.esapi.interfaces.IHTTPUtilities#safeSetContentType(java.lang.String)
	 */
	public void safeSetContentType() {
		HttpServletResponse response = getCurrentResponse();
		response.setContentType(((SecurityConfiguration)ESAPI.securityConfiguration()).getResponseContentType());
	}

	/**
	 * Set headers to protect sensitive information against being cached in the
	 * browser.
	 * 
	 * @see org.owasp.esapi.interfaces.IHTTPUtilities#setNoCacheHeaders(javax.servlet.http.HttpServletResponse)
	 */
	public void setNoCacheHeaders() {
		HttpServletResponse response = getCurrentResponse();
		
		// HTTP 1.1
		response.setHeader("Cache-Control", "no-store");
		response.setHeader("Cache-Control", "no-cache");
		response.setHeader("Cache-Control", "must-revalidate");

		// HTTP 1.0
		response.setHeader("Pragma","no-cache");
		response.setDateHeader("Expires", -1);
	}

    /*
     * The currentRequest ThreadLocal variable is used to make the currentRequest available to any call in any part of an
     * application. This enables API's for actions that require the request to be much simpler. For example, the logout()
     * method in the Authenticator class requires the currentRequest to get the session in order to invalidate it.
     */
    private ThreadLocalRequest currentRequest = new ThreadLocalRequest();

    private class ThreadLocalRequest extends InheritableThreadLocal {
        
        public Object initialValue() {
        	return null;
        }
        
        public HttpServletRequest getRequest() {
            return (HttpServletRequest)super.get();
        }

        public void setRequest(HttpServletRequest newRequest) {
            super.set(newRequest);
        }
    };

    /*
     * The currentResponse ThreadLocal variable is used to make the currentResponse available to any call in any part of an
     * application. This enables API's for actions that require the response to be much simpler. For example, the logout()
     * method in the Authenticator class requires the currentResponse to kill the JSESSIONID cookie.
     */
    private ThreadLocalResponse currentResponse = new ThreadLocalResponse();

    private class ThreadLocalResponse extends InheritableThreadLocal {
        
        public Object initialValue() {
        	return null;
        }
        
        public HttpServletResponse getResponse() {
            return (HttpServletResponse)super.get();
        }

        public void setResponse(HttpServletResponse newResponse) {
            super.set(newResponse);
        }
    };


	/* (non-Javadoc)
     * @see org.owasp.esapi.interfaces.IHTTPUtilities#getCurrentRequest()
     */
    public HttpServletRequest getCurrentRequest() {
        HttpServletRequest request = (HttpServletRequest)currentRequest.get();
		if ( request == null ) throw new NullPointerException( "Cannot use current request until it is set, typically via login" );
		return request;
    }

	/* (non-Javadoc)
     * @see org.owasp.esapi.interfaces.IHTTPUtilities#getCurrentResponse()
     */
    public HttpServletResponse getCurrentResponse() {
        HttpServletResponse response = (HttpServletResponse)currentResponse.get();
		if ( response == null ) throw new NullPointerException( "Cannot use current response until it is set, typically via login" );
        return response;
    }

	/* (non-Javadoc)
     * @see org.owasp.esapi.interfaces.IHTTPUtilities#setCurrentHttp(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    public void setCurrentHTTP(HttpServletRequest request, HttpServletResponse response) {
    	currentRequest.set(request);
        currentResponse.set(response);
    }

}
