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
import org.owasp.esapi.User;
import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.IntegrityException;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.errors.ValidationUploadException;
import org.owasp.esapi.filters.SafeRequest;
import org.owasp.esapi.filters.SafeResponse;

/**
 * Reference implementation of the HTTPUtilities interface. This implementation
 * uses the Apache Commons FileUploader library, which in turn uses the Apache
 * Commons IO library.
 * <P>
 * To simplify the interface, this class uses the current request and response that
 * are tracked by ThreadLocal variables in the Authenticator. This means that you
 * must have called ESAPI.authenticator().setCurrentHTTP(request, response) before
 * calling these methods.
 * <P>
 * Typically, this is done by calling the Authenticator.login() method, which
 * calls setCurrentHTTP() automatically. However if you want to use these methods
 * in another application, you should explicitly call setCurrentHTTP() in your
 * own code.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.HTTPUtilities
 */
public class DefaultHTTPUtilities implements org.owasp.esapi.HTTPUtilities {

	/** The logger. */
	private final Logger logger = ESAPI.getLogger("HTTPUtilities");

	/** The max bytes. */
	int maxBytes = ESAPI.securityConfiguration().getAllowedFileUploadSize();
	
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


	public DefaultHTTPUtilities() {
	}

	/**
	 * @see org.owasp.esapi.HTTPUtilities#addCSRFToken(java.lang.String)
	 */
	public String addCSRFToken(String href) {
		User user = ESAPI.authenticator().getCurrentUser();		
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
     * Returns the first cookie matching the provided name.
     */
	public Cookie getCookie(HttpServletRequest request, String name) {
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
	 * @see org.owasp.esapi.HTTPUtilities#getCSRFToken()
	 */
	public String getCSRFToken() {
		User user = ESAPI.authenticator().getCurrentUser();		
		
		if (user == null) return null;
		return user.getCSRFToken();
	}
	
	/**
	 * Save the user's remember me token in a cookie. Old remember me cookies should be
	 * destroyed first. Setting this cookie will keep the user logged in until the
	 * maxAge passes, the password is changed, or the cookie is deleted.
	 */
	public String setRememberToken( HttpServletRequest request, HttpServletResponse response, String password, int maxAge, String domain, String path ) {
		User user = ESAPI.authenticator().getCurrentUser();		
		try {
			killCookie(request, response, REMEMBER_TOKEN_COOKIE_NAME );
			String random = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			String clearToken = random + ":" + user.getAccountName() + ":" + password;
			long expiry = ESAPI.encryptor().getRelativeTimeStamp(maxAge * 1000);
			String cryptToken = ESAPI.encryptor().seal(clearToken, expiry);
			new SafeResponse(response).addCookie(REMEMBER_TOKEN_COOKIE_NAME, cryptToken, maxAge, domain, path );
			logger.info(Logger.SECURITY, "Enabled remember me token for " + user.getAccountName() );
			return cryptToken;
		} catch( IntegrityException e ) {
			logger.warning(Logger.SECURITY, "Attempt to set remember me token failed for " + user.getAccountName(), e );
			return null;
		}
	}
	
	/**
	 * Verifies that the request is "secure" by checking that the method is a POST and
	 * that SSL has been used.  The POST ensures that the data does not end up in bookmarks,
	 * web logs, referer headers, and other exposed sources.  The SSL ensures that data
	 * has not been exposed in transit.
	 */
	public void assertSecureRequest(HttpServletRequest request) throws AccessControlException {
		if ( !isSecureChannel( request ) ) {
			throw new AccessControlException( "Insecure request received", "Received non-SSL request" );
		}
		String receivedMethod = request.getMethod();
		String requiredMethod = "POST";
		if ( !receivedMethod.equals( requiredMethod ) ) {
			throw new AccessControlException( "Insecure request received", "Received request using " + receivedMethod + " when only " + requiredMethod + " is allowed" );
		}
	}
	
	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.HTTPUtilities#changeSessionIdentifier()
	 */
	public HttpSession changeSessionIdentifier(HttpServletRequest request) throws AuthenticationException {
		
		// get the current session
		HttpSession session = request.getSession();
		
		// make a copy of the session content
		Map temp = new HashMap();
		Enumeration e = session.getAttributeNames();
		while (e != null && e.hasMoreElements()) {
			String name = (String) e.nextElement();
			Object value = session.getAttribute(name);
			temp.put(name, value);
		}

		// kill the old session and create a new one
		session.invalidate();
		HttpSession newSession = request.getSession();

		// copy back the session content
		Iterator i = temp.entrySet().iterator();
		while (i.hasNext()) {
			Map.Entry entry = (Map.Entry) i.next();
			newSession.setAttribute((String) entry.getKey(), entry.getValue());
		}
		return newSession;
	}

	
	
	/*
	 * This implementation uses the parameter name to store the token. This makes the CSRF
	 * token a bit harder to search for in an XSS attack.
	 * (non-Javadoc)
	 * @see org.owasp.esapi.HTTPUtilities#verifyCSRFToken()
	 */
	public void verifyCSRFToken(HttpServletRequest request) throws IntrusionException {
		User user = ESAPI.authenticator().getCurrentUser();
		
		// check if user authenticated with this request - no CSRF protection required
		if( request.getAttribute(user.getCSRFToken()) != null ) {
			return;
		}
		if ( request.getParameter(user.getCSRFToken()) == null) {
			throw new IntrusionException("Authentication failed", "Possibly forged HTTP request without proper CSRF token detected");
		}
	}
    
    /*
	 * (non-Javadoc)
	 * @see org.owasp.esapi.HTTPUtilities#decryptHiddenField(java.lang.String)
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
	 * @see org.owasp.esapi.HTTPUtilities#decryptQuueryString(java.lang.String)
	 */
	public Map decryptQueryString(String encrypted) throws EncryptionException {
		String plaintext = ESAPI.encryptor().decrypt(encrypted);
		return queryToMap(plaintext);
	}

	/**
	 * @throws EncryptionException 
     * @see org.owasp.esapi.HTTPUtilities#decryptStateFromCookie()
     */
    public Map decryptStateFromCookie(HttpServletRequest request) throws EncryptionException {
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
	 * @see org.owasp.esapi.HTTPUtilities#encryptHiddenField(java.lang.String)
	 */
	public String encryptHiddenField(String value) throws EncryptionException {
    	return ESAPI.encryptor().encrypt(value);
	}
	
	/*
	 * (non-Javadoc)
	 * @see org.owasp.esapi.HTTPUtilities#encryptQueryString(java.lang.String)
	 */
	public String encryptQueryString(String query) throws EncryptionException {
		return ESAPI.encryptor().encrypt( query );
	}

	/**
	 * @throws EncryptionException 
     * @see org.owasp.esapi.HTTPUtilities#encryptStateInCookie(java.util.Map)
     */
    public void encryptStateInCookie(HttpServletResponse response, Map cleartext) throws EncryptionException {
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
    			logger.error(Logger.SECURITY, "Problem encrypting state in cookie - skipping entry", e );
    		}
    	}
    	String encrypted = ESAPI.encryptor().encrypt(sb.toString());
    	new SafeResponse(response).addCookie("state", encrypted, -1, null, null );
    }

	/**
	 * Uses the Apache Commons FileUploader to parse the multipart HTTP request
	 * and extract any files therein. Note that the progress of any uploads is
	 * put into a session attribute, where it can be retrieved with a simple
	 * JSP.
	 * 
	 * @see org.owasp.esapi.HTTPUtilities#safeGetFileUploads(java.io.File, java.io.File)
	 * @return list of File objects for new files in final directory
	 */
	public List getSafeFileUploads(HttpServletRequest request, File tempDir, File finalDir) throws ValidationException {
		if ( !tempDir.exists() ) tempDir.mkdirs();
		if ( !finalDir.exists() ) finalDir.mkdirs();
		List newFiles = new ArrayList();
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

					logger.info(Logger.SECURITY, "File upload requested: " + filename);
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
					logger.fatal(Logger.SECURITY, "File successfully uploaded: " + f);
					session.setAttribute("progress", Long.toString(0));
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
	 * Returns true if the request was transmitted over an SSL enabled
	 * connection. This implementation ignores the built-in isSecure() method
	 * and uses the URL to determine if the request was transmitted over SSL.
	 */
	public boolean isSecureChannel(HttpServletRequest request) {
		return (request.getRequestURL().charAt(4) == 's');
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.HTTPUtilities#killAllCookies()
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

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.HTTPUtilities#killCookie(java.lang.String)
	 */
	public void killCookie(HttpServletRequest request, HttpServletResponse response, String name) {
		String path = "//";
		String domain="";
		Cookie cookie = ESAPI.httpUtilities().getCookie(request, name);
		if ( cookie != null ) {
			path = cookie.getPath();
			domain = cookie.getDomain();
		}
		SafeResponse safeResponse = new SafeResponse( response );
		safeResponse.addCookie(name, "deleted", 0, domain, path);
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

	/*
	 * This implementation simply checks to make sure that the forward location starts with "WEB-INF" and
	 * is intended for use in frameworks that forward to JSP files inside the WEB-INF folder.
	 * 
	 * @see org.owasp.esapi.HTTPUtilities#safeSendForward(java.lang.String, java.lang.String)
	 */
	public void safeSendForward(HttpServletRequest request, HttpServletResponse response, String context, String location) throws AccessControlException,ServletException,IOException {
		if (!location.startsWith("WEB-INF")) {
			throw new AccessControlException("Forward failed", "Bad forward location: " + location);
		}
		RequestDispatcher dispatcher = request.getRequestDispatcher(location);
		dispatcher.forward( request, response );
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
	 * @see org.owasp.esapi.HTTPUtilities#safeSetContentType(java.lang.String)
	 */
	public void safeSetContentType(HttpServletResponse response) {
		response.setContentType(((DefaultSecurityConfiguration)ESAPI.securityConfiguration()).getResponseContentType());
	}

	/**
	 * Set headers to protect sensitive information against being cached in the
	 * browser.
	 * 
	 * @see org.owasp.esapi.HTTPUtilities#setNoCacheHeaders(javax.servlet.http.HttpServletResponse)
	 */
	public void setNoCacheHeaders(HttpServletResponse response) {
		// HTTP 1.1
		response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");

		// HTTP 1.0
		response.setHeader("Pragma","no-cache");
		response.setDateHeader("Expires", -1);
	}


	/* (non-Javadoc)
     * @see org.owasp.esapi.HTTPUtilities#getCurrentRequest()
     */
    public SafeRequest getCurrentRequest() {
        SafeRequest request = (SafeRequest)currentRequest.get();
		if ( request == null ) throw new NullPointerException( "Cannot use current request until it is set with HTTPUtilities.setCurrentHTTP()" );
		return request;
    }

	/* (non-Javadoc)
     * @see org.owasp.esapi.HTTPUtilities#getCurrentResponse()
     */
    public SafeResponse getCurrentResponse() {
        SafeResponse response = (SafeResponse)currentResponse.get();
		if ( response == null ) throw new NullPointerException( "Cannot use current response until it is set with HTTPUtilities.setCurrentHTTP()" );
        return response;
    }

	/* (non-Javadoc)
     * @see org.owasp.esapi.HTTPUtilities#setCurrentHTTP(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    public void setCurrentHTTP(HttpServletRequest request, HttpServletResponse response) {
    	SafeRequest safeRequest = null;
    	SafeResponse safeResponse = null;
    	
    	// wrap if necessary
    	if ( request instanceof SafeRequest ) {
    		safeRequest = (SafeRequest)request;
    	} else {
    		safeRequest = new SafeRequest( request );
    	}
    	if ( response instanceof SafeResponse ) {
    		safeResponse = (SafeResponse)response;
    	} else {
    		safeResponse = new SafeResponse( response );
    	}
    	
    	currentRequest.set(safeRequest);
        currentResponse.set(safeResponse);
    }

    public void logHTTPRequest(HttpServletRequest request, Logger logger) {
    	logHTTPRequest( request, logger, null );
    }
    
    /**
     * Formats an HTTP request into a log suitable string. This implementation logs the remote host IP address (or
     * hostname if available), the request method (GET/POST), the URL, and all the querystring and form parameters. All
     * the parameters are presented as though they were in the URL even if they were in a form. Any parameters that
     * match items in the parameterNamesToObfuscate are shown as eight asterisks.
     * 
     * @see org.owasp.esapi.Logger#logHTTPRequest(org.owasp.esapi.Logger,java.util.List)
     */
    public void logHTTPRequest(HttpServletRequest request, Logger logger, List parameterNamesToObfuscate) {
        StringBuffer params = new StringBuffer();
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
        logger.info(Logger.SECURITY, msg);
    }

    /**
     * Defines the ThreadLocalRequest to store the current request for this thread.
     */
    private class ThreadLocalRequest extends InheritableThreadLocal {
        
        public Object initialValue() {
        	return null;
        }
        
        public SafeRequest getRequest() {
            return (SafeRequest)super.get();
        }

        public void setRequest(SafeRequest newRequest) {
            super.set(newRequest);
        }
    };

    /**
     * Defines the ThreadLocalResponse to store the current response for this thread.
     */
    private class ThreadLocalResponse extends InheritableThreadLocal {
        
        public Object initialValue() {
        	return null;
        }
        
        public SafeResponse getResponse() {
            return (SafeResponse)super.get();
        }

        public void setResponse(SafeResponse newResponse) {
            super.set(newResponse);
        }
    };
    
}
