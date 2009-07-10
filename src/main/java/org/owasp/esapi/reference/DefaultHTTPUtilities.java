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
package org.owasp.esapi.reference;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
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
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.StringUtilities;
import org.owasp.esapi.User;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.IntegrityException;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.errors.ValidationUploadException;

/**
 * Reference implementation of the HTTPUtilities interface. This implementation
 * uses the Apache Commons FileUploader library, which in turn uses the Apache
 * Commons IO library.
 * <P>
 * To simplify the interface, some methods use the current request and response that
 * are tracked by ThreadLocal variables in the Authenticator. This means that you
 * must have called ESAPI.authenticator().setCurrentHTTP(request, response) before
 * calling these methods.
 * <P>
 * Typically, this is done by calling the Authenticator.login() method, which
 * calls setCurrentHTTP() automatically. However if you want to use these methods
 * in another application, you should explicitly call setCurrentHTTP() in your
 * own code. In either case, you *must* call ESAPI.clearCurrent() to clear threadlocal
 * variables before the thread is reused. The advantages of having identity everywhere
 * outweigh the disadvantages of this approach.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.HTTPUtilities
 */
public class DefaultHTTPUtilities implements org.owasp.esapi.HTTPUtilities {
	
	/**
     * Defines the ThreadLocalRequest to store the current request for this thread.
     */
    private class ThreadLocalRequest extends InheritableThreadLocal {
        
        public HttpServletRequest getRequest() {
            return (HttpServletRequest)super.get();
        }
        
        public Object initialValue() {
        	return null;
        }

        public void setRequest(HttpServletRequest newRequest) {
            super.set(newRequest);
        }
    }
    
	/**
     * Defines the ThreadLocalResponse to store the current response for this thread.
     */
    private class ThreadLocalResponse extends InheritableThreadLocal {
        
        public HttpServletResponse getResponse() {
            return (HttpServletResponse)super.get();
        }
        
        public Object initialValue() {
        	return null;
        }

        public void setResponse(HttpServletResponse newResponse) {
            super.set(newResponse);
        }
    }
	
    /** The logger. */
	private final Logger logger = ESAPI.getLogger("HTTPUtilities");

    /** The max bytes. */
	static final int maxBytes = ESAPI.securityConfiguration().getAllowedFileUploadSize();


    /*
     * The currentRequest ThreadLocal variable is used to make the currentRequest available to any call in any part of an
     * application. This enables API's for actions that require the request to be much simpler. For example, the logout()
     * method in the Authenticator class requires the currentRequest to get the session in order to invalidate it.
     */
    private ThreadLocalRequest currentRequest = new ThreadLocalRequest();

	/*
     * The currentResponse ThreadLocal variable is used to make the currentResponse available to any call in any part of an
     * application. This enables API's for actions that require the response to be much simpler. For example, the logout()
     * method in the Authenticator class requires the currentResponse to kill the JSESSIONID cookie.
     */
    private ThreadLocalResponse currentResponse = new ThreadLocalResponse();

    
    
	/**
     * No arg constructor.
     */
    public DefaultHTTPUtilities() {
	}

	
	/**
	 * {@inheritDoc}
     * This implementation uses a custom "set-cookie" header rather than Java's
     * cookie interface which doesn't allow the use of HttpOnly. Configure the
     * HttpOnly and Secure settings in ESAPI.properties.
	 */
	public void addCookie( Cookie cookie ) {
		addCookie( getCurrentResponse(), cookie );
    }

    /**
	 * {@inheritDoc}
     * This implementation uses a custom "set-cookie" header rather than Java's
     * cookie interface which doesn't allow the use of HttpOnly. Configure the
     * HttpOnly and Secure settings in ESAPI.properties.
	 */
    public void addCookie(HttpServletResponse response, Cookie cookie) {
        String name = cookie.getName();
        String value = cookie.getValue();
        int maxAge = cookie.getMaxAge();
        String domain = cookie.getDomain();
        String path = cookie.getPath();
        boolean secure = cookie.getSecure();

        // validate the name and value
        ValidationErrorList errors = new ValidationErrorList();
        String cookieName = ESAPI.validator().getValidInput("cookie name", name, "HTTPCookieName", 50, false, errors);
        String cookieValue = ESAPI.validator().getValidInput("cookie value", value, "HTTPCookieValue", 5000, false, errors);

        // if there are no errors, then set the cookie either with a header or normally
        if (errors.size() == 0) {
        	if ( ESAPI.securityConfiguration().getForceHttpOnlyCookies() ) {
	            String header = createCookieHeader(cookieName, cookieValue, maxAge, domain, path, secure);
	            addHeader(response, "Set-Cookie", header);
        	} else {
        		response.addCookie(cookie);
        	}
            return;
        }
        logger.warning(Logger.SECURITY_FAILURE, "Attempt to add unsafe data to cookie (skip mode). Skipping cookie and continuing.");
    }

    
    
	/**
	 * {@inheritDoc}
	 */
	public String addCSRFToken(String href) {
		User user = ESAPI.authenticator().getCurrentUser();		
		if (user.isAnonymous()) {
			return href;
		}

		// if there are already parameters append with &, otherwise append with ?
		String token = CSRF_TOKEN_NAME + "=" + user.getCSRFToken();
		return href.indexOf( '?') != -1 ? href + "&" + token : href + "?" + token;
	}

    /**
	 * {@inheritDoc}
     */
    public void addHeader(String name, String value) {
    	addHeader( getCurrentResponse(), name, value );
    }
	
    /**
	 * {@inheritDoc}
     */
    public void addHeader(HttpServletResponse response, String name, String value) {
        try {
            String strippedName = StringUtilities.replaceLinearWhiteSpace(name);
            String strippedValue = StringUtilities.replaceLinearWhiteSpace(value);
            String safeName = ESAPI.validator().getValidInput("addHeader", strippedName, "HTTPHeaderName", 20, false);
            String safeValue = ESAPI.validator().getValidInput("addHeader", strippedValue, "HTTPHeaderValue", 500, false);
            response.addHeader(safeName, safeValue);
        } catch (ValidationException e) {
            logger.warning(Logger.SECURITY_FAILURE, "Attempt to add invalid header denied", e);
        }
    }

	
	/**
	 * {@inheritDoc}
	 */
	public void assertSecureRequest() throws AccessControlException {
    	assertSecureRequest( getCurrentRequest() );
    }

	/**
	 * {@inheritDoc}
     */
	public void assertSecureRequest(HttpServletRequest request) throws AccessControlException {
		if ( !isSecureChannel( request ) ) {
			throw new AccessControlException( "Insecure request received", "Received non-SSL request: " + request.getRequestURL() );
		}
		String receivedMethod = request.getMethod();
		String requiredMethod = "POST";
		if ( !receivedMethod.equals( requiredMethod ) ) {
			throw new AccessControlException( "Insecure request received", "Received request using " + receivedMethod + " when only " + requiredMethod + " is allowed" );
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	public HttpSession changeSessionIdentifier() throws AuthenticationException {
    	return changeSessionIdentifier( getCurrentRequest() );
    }
	
	/**
	 * {@inheritDoc}
     */
	public HttpSession changeSessionIdentifier(HttpServletRequest request) throws AuthenticationException {
		
		// get the current session
		HttpSession oldSession = request.getSession();
		
		// make a copy of the session content
		Map temp = new HashMap();
		Enumeration e = oldSession.getAttributeNames();
		while (e != null && e.hasMoreElements()) {
			String name = (String) e.nextElement();
			Object value = oldSession.getAttribute(name);
			temp.put(name, value);
		}

		// kill the old session and create a new one
		oldSession.invalidate();
		HttpSession newSession = request.getSession();
		User user = ESAPI.authenticator().getCurrentUser();
		user.addSession( newSession );
		user.removeSession( oldSession );
		
		// copy back the session content
		Iterator i = temp.entrySet().iterator();
		while (i.hasNext()) {
			Map.Entry entry = (Map.Entry) i.next();
			newSession.setAttribute((String) entry.getKey(), entry.getValue());
		}
		return newSession;
	}
	
	/**
	 * {@inheritDoc}
	 */
    public void clearCurrent() {
		currentRequest.set(null);
		currentResponse.set(null);
	}

	private String createCookieHeader(String name, String value, int maxAge, String domain, String path, boolean secure) {
        // create the special cookie header instead of creating a Java cookie
        // Set-Cookie:<name>=<value>[; <name>=<value>][; expires=<date>][;
        // domain=<domain_name>][; path=<some_path>][; secure][;HttpOnly
        String header = name + "=" + value;
        header += "; Max-Age=" + maxAge;
        if (domain != null) {
            header += "; Domain=" + domain;
        }
        if (path != null) {
            header += "; Path=" + path;
        }
        if ( secure || ESAPI.securityConfiguration().getForceSecureCookies() ) {
            header += "; Secure";
        }
        if ( ESAPI.securityConfiguration().getForceHttpOnlyCookies() ) {
            header += "; HttpOnly";
        }
        return header;
    }
	
	/**
	 * {@inheritDoc}
	 */
	public String decryptHiddenField(String encrypted) {
    	try {
    		return ESAPI.encryptor().decrypt(encrypted);
    	} catch( EncryptionException e ) {
    		throw new IntrusionException("Invalid request","Tampering detected. Hidden field data did not decrypt properly.", e);
    	}
    }

	/**
	 * {@inheritDoc}
	 */
	public Map decryptQueryString(String encrypted) throws EncryptionException {
		String plaintext = ESAPI.encryptor().decrypt(encrypted);
		return queryToMap(plaintext);
	}
	
	/**
	 * {@inheritDoc}
	 */
	public Map decryptStateFromCookie() throws EncryptionException {
		return decryptStateFromCookie( getCurrentRequest() );
    }

	/**
	 * {@inheritDoc}
     *
     * @param request
     */
    public Map decryptStateFromCookie(HttpServletRequest request) throws EncryptionException {
    	try {
    		String encrypted = getCookie( request, ESAPI_STATE );
    		if ( encrypted == null ) return new HashMap();		
    		String plaintext = ESAPI.encryptor().decrypt(encrypted);		
    		return queryToMap( plaintext );
    	} catch( ValidationException e ) {
        	return null;
    	}
    }
	
	/**
	 * {@inheritDoc}
	 */
	public String encryptHiddenField(String value) throws EncryptionException {
    	return ESAPI.encryptor().encrypt(value);
	}
	
	/**
	 * {@inheritDoc}
	 */
	public String encryptQueryString(String query) throws EncryptionException {
		return ESAPI.encryptor().encrypt( query );
	}
	
	/**
	 * {@inheritDoc}
     */
    public void encryptStateInCookie(HttpServletResponse response, Map cleartext) throws EncryptionException {
    	StringBuilder sb = new StringBuilder();    	
    	Iterator i = cleartext.entrySet().iterator();
    	while ( i.hasNext() ) {
    		try {
	    		Map.Entry entry = (Map.Entry)i.next();
	    		String name = ESAPI.encoder().encodeForURL( entry.getKey().toString() );
	    		String value = ESAPI.encoder().encodeForURL( entry.getValue().toString() );
	    		sb.append( name + "=" + value );
	    		if ( i.hasNext() ) sb.append( "&" );
    		} catch( EncodingException e ) {
    			logger.error(Logger.SECURITY_FAILURE, "Problem encrypting state in cookie - skipping entry", e );
    		}
    	}
    	
		String encrypted = ESAPI.encryptor().encrypt(sb.toString());
		
		if ( encrypted.length() > (MAX_COOKIE_LEN ) ) {
			logger.error(Logger.SECURITY_FAILURE, "Problem encrypting state in cookie - skipping entry");
			throw new EncryptionException("Encryption failure", "Encrypted cookie state of " + encrypted.length() + " longer than allowed " + MAX_COOKIE_LEN );
		}
		
    	Cookie cookie = new Cookie( ESAPI_STATE, encrypted );
    	addCookie( response, cookie );
    }
		
	/**
	 * {@inheritDoc}
	 */
	public void encryptStateInCookie( Map cleartext ) throws EncryptionException {
		encryptStateInCookie( getCurrentResponse(), cleartext );
    }

	
	/**
	 * {@inheritDoc}
	 */
	public String getCookie( HttpServletRequest request, String name ) throws ValidationException {
        Cookie c = getFirstCookie( request, name );
        if ( c == null ) return null;
		String value = c.getValue(); 
		return ESAPI.validator().getValidInput("HTTP cookie value: " + value, value, "HTTPCookieValue", 1000, false);
	}
	
	/**
	 * {@inheritDoc}
	 */
    public String getCookie( String name ) throws ValidationException {
    	return getCookie( getCurrentRequest(), name );
    }
    
	/**
	 * {@inheritDoc}
	 */
	public String getCSRFToken() {
		User user = ESAPI.authenticator().getCurrentUser();		
		if (user == null) return null;
		return user.getCSRFToken();
	}
	
	
	/**
	 * {@inheritDoc}
	 */
    public HttpServletRequest getCurrentRequest() {
    	return (HttpServletRequest)currentRequest.get();
    }

	
	/**
	 * {@inheritDoc}
	 */
    public HttpServletResponse getCurrentResponse() {
        return (HttpServletResponse)currentResponse.get();
    }
	
	/**
	 * {@inheritDoc}
	 */
    public List getFileUploads() throws ValidationException {
    	return getFileUploads( getCurrentRequest(), ESAPI.securityConfiguration().getUploadDirectory(), ESAPI.securityConfiguration().getAllowedFileExtensions() );
    }

    /**
	 * {@inheritDoc}
	 */
    public List getFileUploads(HttpServletRequest request) throws ValidationException {
    	return getFileUploads(request, ESAPI.securityConfiguration().getUploadDirectory(), ESAPI.securityConfiguration().getAllowedFileExtensions());
    }
	
    /**
	 * {@inheritDoc}
	 */
    public List getFileUploads(HttpServletRequest request, File finalDir ) throws ValidationException {
    	return getFileUploads(request, finalDir, ESAPI.securityConfiguration().getAllowedFileExtensions());
    }
	
	/**
	 * {@inheritDoc}
	 */
	public List getFileUploads(HttpServletRequest request, File finalDir, List allowedExtensions) throws ValidationException {
        File tempDir = ESAPI.securityConfiguration().getUploadTempDirectory();
		if ( !tempDir.exists() ) {
		    if ( !tempDir.mkdirs() ) throw new ValidationUploadException( "Upload failed", "Could not create temp directory: " + tempDir.getAbsolutePath() );
		}
		
		if( finalDir != null){
			if ( !finalDir.exists() ) { 
				if ( !finalDir.mkdirs() ) throw new ValidationUploadException( "Upload failed", "Could not create final upload directory: " + finalDir.getAbsolutePath() );
			}
		}
		else {
			if ( !ESAPI.securityConfiguration().getUploadDirectory().exists()) { 
				if ( !ESAPI.securityConfiguration().getUploadDirectory().mkdirs() ) throw new ValidationUploadException( "Upload failed", "Could not create final upload directory: " + ESAPI.securityConfiguration().getUploadDirectory().getAbsolutePath() );
			}
			finalDir = ESAPI.securityConfiguration().getUploadDirectory();
		}
		
		List newFiles = new ArrayList();
		try {
			final HttpSession session = request.getSession(false);
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
					if ( session != null ) {
					    session.setAttribute("progress", Long.toString(progress));
					}
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

					if (!ESAPI.validator().isValidFileName("upload", filename, allowedExtensions, false)) {
						throw new ValidationUploadException("Upload only simple filenames with the following extensions " + allowedExtensions, "Upload failed isValidFileName check");
					}

					logger.info(Logger.SECURITY_SUCCESS, "File upload requested: " + filename);
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
					logger.fatal(Logger.SECURITY_SUCCESS, "File successfully uploaded: " + f);
					if ( session != null ) {
					    session.setAttribute("progress", Long.toString(0));
					}
				}
			}
		} catch (Exception e) {
			if (e instanceof ValidationUploadException) {
				throw (ValidationException)e;
			}
			throw new ValidationUploadException("Upload failure", "Problem during upload:" + e.getMessage(), e);
		}
		return newFiles;
	}


	
	/**
     * Utility to return the first cookie matching the provided name.
     * @param request
     * @param name
     */
	private Cookie getFirstCookie(HttpServletRequest request, String name) {
		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (int i = 0; i < cookies.length; i++) {
				Cookie cookie = cookies[i];
				if (cookie.getName().equals(name)) {
					return cookie;
				}
			}
		}
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getHeader( HttpServletRequest request, String name ) throws ValidationException {
        String value = request.getHeader(name);
        return ESAPI.validator().getValidInput("HTTP header value: " + value, value, "HTTPHeaderValue", 150, false);
	}

    
	/**
	 * {@inheritDoc}
	 */
    public String getHeader( String name ) throws ValidationException {
    	return getHeader( getCurrentRequest(), name );
    }

    
    /**
	 * {@inheritDoc}
	 */
	public String getParameter( HttpServletRequest request, String name ) throws ValidationException {
	    String value = request.getHeader(name);
	    return ESAPI.validator().getValidInput("HTTP parameter value: " + value, value, "HTTPParameterValue", 2000, false);
	}

	/**
	 * {@inheritDoc}
	 */
    public String getParameter( String name ) throws ValidationException {
    	return getParameter( getCurrentRequest(), name );
    }

	/**
	 * Returns true if the request was transmitted over an SSL enabled
	 * connection. This implementation ignores the built-in isSecure() method
	 * and uses the URL to determine if the request was transmitted over SSL.
	 */
	private boolean isSecureChannel(HttpServletRequest request) {
	    if ( request == null ) return false;
	    StringBuffer sb = request.getRequestURL();
	    if ( sb == null ) return false;
	    String url = sb.toString();
	    return url.startsWith( "https" );
	}

	
	/**
	 * {@inheritDoc}
	 */
    public void killAllCookies() {
    	killAllCookies( getCurrentRequest(), getCurrentResponse() );
    }	
	
	/**
	 * {@inheritDoc}
     *
     * @param request
     * @param response
     */
	public void killAllCookies(HttpServletRequest request, HttpServletResponse response) {
		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (int i = 0; i < cookies.length; i++) {
				Cookie cookie = cookies[i];
				killCookie(request, response, cookie.getName());
			}
		}
	}

	
	/**
	 * {@inheritDoc}
     *
     * @param request
     * @param response
     * @param name
     */
	public void killCookie(HttpServletRequest request, HttpServletResponse response, String name) {
		String path = "//";
		String domain="";
		Cookie cookie = getFirstCookie(request, name);
		if ( cookie != null ) {
			path = cookie.getPath();
			domain = cookie.getDomain();
		}
		Cookie deleter = new Cookie( name, "deleted" );
		deleter.setMaxAge( 0 );
		if ( domain != null ) deleter.setDomain( domain );
		if ( path != null ) deleter.setPath( path );
		response.addCookie( deleter );
	}	
	
	
	/**
	 * {@inheritDoc}
	 */
    public void killCookie( String name ) {
    	killCookie( getCurrentRequest(), getCurrentResponse(), name );
    }

	
	/**
	 * {@inheritDoc}
	 */
    public void logHTTPRequest() {
    	logHTTPRequest( getCurrentRequest(), logger, null );
    }

	/**
	 * {@inheritDoc}
	 */
    public void logHTTPRequest(HttpServletRequest request, Logger logger) {
    	logHTTPRequest( request, logger, null );
    }	
	
		/**
		 * Formats an HTTP request into a log suitable string. This implementation logs the remote host IP address (or
		 * hostname if available), the request method (GET/POST), the URL, and all the querystring and form parameters. All
		 * the parameters are presented as though they were in the URL even if they were in a form. Any parameters that
		 * match items in the parameterNamesToObfuscate are shown as eight asterisks.
		 * 
		 * 
		 * @param request
		 */
		public void logHTTPRequest(HttpServletRequest request, Logger logger, List parameterNamesToObfuscate) {
			StringBuilder params = new StringBuilder();
		    Iterator i = request.getParameterMap().keySet().iterator();
		    while (i.hasNext()) {
		        String key = (String) i.next();
		        String[] value = (String[]) request.getParameterMap().get(key);
		        for (int j = 0; j < value.length; j++) {
		            params.append(key + "=");
		            if (parameterNamesToObfuscate != null && parameterNamesToObfuscate.contains(key)) {
		                params.append("********");
		            } else {
		                params.append(value[j]);
		            }
		            if (j < value.length - 1) {
		                params.append("&");
		            }
		        }
		        if (i.hasNext())
		            params.append("&");
		    }
		    Cookie[] cookies = request.getCookies();
		    if ( cookies != null ) {
		            for ( int c=0; c<cookies.length; c++ ) {
		                    if ( !cookies[c].getName().equals("JSESSIONID")) {
		                            params.append( "+" + cookies[c].getName() + "=" + cookies[c].getValue() );
		                    }
		            }
		    }
		    String msg = request.getMethod() + " " + request.getRequestURL() + (params.length() > 0 ? "?" + params : "");
		    logger.info(Logger.SECURITY_SUCCESS, msg);
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
				// skip the nvpair with the encoding problem - note this is already logged.
			}
		}
		return map;
	}	

	/**
	 * {@inheritDoc}
	 * 
	 * This implementation simply checks to make sure that the forward location starts with "WEB-INF" and
	 * is intended for use in frameworks that forward to JSP files inside the WEB-INF folder.
	 */
	public void sendForward(HttpServletRequest request, HttpServletResponse response, String location) throws AccessControlException,ServletException,IOException {
		if (!location.startsWith("WEB-INF")) {
			throw new AccessControlException("Forward failed", "Bad forward location: " + location);
		}
		RequestDispatcher dispatcher = request.getRequestDispatcher(location);
		dispatcher.forward( request, response );
	}

	/**
	 * {@inheritDoc}
	 */
    public void sendForward( String location )  throws AccessControlException,ServletException,IOException {
    	sendForward( getCurrentRequest(), getCurrentResponse(), location);
    }	
    
	/**
	 * {@inheritDoc}
	 * 
	 * This implementation checks against the list of safe redirect locations defined in ESAPI.properties.
     *
     * @param request
     * @param response
     */
    public void sendRedirect(HttpServletResponse response, String location) throws AccessControlException, IOException {
        if (!ESAPI.validator().isValidRedirectLocation("Redirect", location, false)) {
            logger.fatal(Logger.SECURITY_FAILURE, "Bad redirect location: " + location);
            throw new IOException("Redirect failed");
        }
        response.sendRedirect(location);
    }
	
	/**
	 * {@inheritDoc}
	 */
    public void sendRedirect( String location )  throws AccessControlException,IOException {
    	sendRedirect( getCurrentResponse(), location);
    }
    
	/**
	 * {@inheritDoc}
	 */
    public void setContentType() {
    	setContentType( getCurrentResponse() );
    }


	/**
	 * {@inheritDoc}
	 */
	public void setContentType(HttpServletResponse response) {
		response.setContentType(((DefaultSecurityConfiguration)ESAPI.securityConfiguration()).getResponseContentType());
	}

    /**
	 * {@inheritDoc}
	 */
    public void setCurrentHTTP(HttpServletRequest request, HttpServletResponse response) {
     	currentRequest.set(request);
        currentResponse.set(response);
    }

    /**
	 * {@inheritDoc}
     */
    public void setHeader(HttpServletResponse response, String name, String value) {
        try {
            String strippedName = StringUtilities.replaceLinearWhiteSpace(name);
            String strippedValue = StringUtilities.replaceLinearWhiteSpace(value);
            String safeName = ESAPI.validator().getValidInput("setHeader", strippedName, "HTTPHeaderName", 20, false);
            String safeValue = ESAPI.validator().getValidInput("setHeader", strippedValue, "HTTPHeaderValue", 500, false);
            response.setHeader(safeName, safeValue);
        } catch (ValidationException e) {
            logger.warning(Logger.SECURITY_FAILURE, "Attempt to set invalid header denied", e);
        }
    }

    
	/**
	 * {@inheritDoc}
	 */
    public void setHeader( String name, String value ) {
    	setHeader( getCurrentResponse(), name, value );
    }
    
    
    /**
	 * {@inheritDoc}
	 */
    public void setNoCacheHeaders() {
    	setNoCacheHeaders( getCurrentResponse() );
    }
    
	/**
	 * {@inheritDoc}
     *
     * @param response
     */
	public void setNoCacheHeaders(HttpServletResponse response) {
		// HTTP 1.1
		response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");

		// HTTP 1.0
		response.setHeader("Pragma","no-cache");
		response.setDateHeader("Expires", -1);
	}
        
	/**
	 * {@inheritDoc}
	 * 
	 * Save the user's remember me data in an encrypted cookie and send it to the user. 
	 * Any old remember me cookie is destroyed first. Setting this cookie will keep the user 
	 * logged in until the maxAge passes, the password is changed, or the cookie is deleted.
	 * If the cookie exists for the current user, it will automatically be used by ESAPI to
	 * log the user in, if the data is valid and not expired. 
     *
     * @param request
     * @param response
     */
	public String setRememberToken( HttpServletRequest request, HttpServletResponse response, String password, int maxAge, String domain, String path ) {
		User user = ESAPI.authenticator().getCurrentUser();		
		try {
			killCookie(request, response, REMEMBER_TOKEN_COOKIE_NAME );
			// seal already contains random data
			String clearToken = user.getAccountName() + "|" + password;
			long expiry = ESAPI.encryptor().getRelativeTimeStamp(maxAge * 1000);
			String cryptToken = ESAPI.encryptor().seal(clearToken, expiry);
			Cookie cookie = new Cookie( REMEMBER_TOKEN_COOKIE_NAME, cryptToken );
			cookie.setMaxAge( maxAge );
			cookie.setDomain( domain );
			cookie.setPath( path );
			response.addCookie( cookie );
			logger.info(Logger.SECURITY_SUCCESS, "Enabled remember me token for " + user.getAccountName() );
			return cryptToken;
		} catch( IntegrityException e ) {
			logger.warning(Logger.SECURITY_FAILURE, "Attempt to set remember me token failed for " + user.getAccountName(), e );
			return null;
		}
	}
    
    /**
	 * {@inheritDoc}
	 */
    public String setRememberToken( String password, int maxAge, String domain, String path ) {
    	return setRememberToken( getCurrentRequest(), getCurrentResponse(), password, maxAge, domain, path );
    }
    
    
    /**
	 * {@inheritDoc}
	 */
	public void verifyCSRFToken() throws IntrusionException {
    	verifyCSRFToken( getCurrentRequest() );
    }

    /**
	 * {@inheritDoc}
	 * 
	 * This implementation uses the CSRF_TOKEN_NAME parameter for the token.
     *
     * @param request
     */	  
	public void verifyCSRFToken(HttpServletRequest request) throws IntrusionException {
		User user = ESAPI.authenticator().getCurrentUser();
		
		// check if user authenticated with this request - no CSRF protection required
		if( request.getAttribute(user.getCSRFToken()) != null ) {
			return;
		}
		String token = request.getParameter(CSRF_TOKEN_NAME);
		if ( !user.getCSRFToken().equals( token ) ) {
			throw new IntrusionException("Authentication failed", "Possibly forged HTTP request without proper CSRF token detected");
		}
	};
    
}
