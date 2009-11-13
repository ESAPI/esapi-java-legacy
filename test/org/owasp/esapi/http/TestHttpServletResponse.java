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
package org.owasp.esapi.http;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

/**
 * The Class TestHttpServletResponse.
 * 
 * @author jwilliams
 */
public class TestHttpServletResponse implements HttpServletResponse {

	/** The cookies. */
	List cookies = new ArrayList();
	
	/** The header names. */
	List headerNames = new ArrayList();
	
	/** The header values. */
	List headerValues = new ArrayList();
	
	/** The status. */
	int status = 200;
	
    /**
     * {@inheritDoc}
	 */
	public void addCookie(Cookie cookie) {
		cookies.add( cookie );
	}

	/**
	 * Gets the cookies.
	 * 
	 * @return the cookies
	 */
	public List getCookies() {
		return cookies;
	}
	
	public Cookie getCookie( String name ) {
		Iterator i = cookies.iterator();
		while ( i.hasNext() ) {
			Cookie c = (Cookie)i.next();
			if ( c.getName().equals( name ) ) {
				return c;
			}
		}
		return null;
	}
	
    /**
     * {@inheritDoc}
	 */
	public void addDateHeader(String name, long date) {
		headerNames.add( name );
		headerValues.add( ""+date );
	}

    /**
     * {@inheritDoc}
	 */
	public void addHeader(String name, String value) {
		headerNames.add( name );
		headerValues.add( value );
	}

    /**
     * {@inheritDoc}
	 */
	public void addIntHeader(String name, int value) {
		headerNames.add( name );
		headerValues.add( ""+value );
	}

    /**
     * {@inheritDoc}
	 */
	public boolean containsHeader(String name) {
		return headerNames.contains(name);
	}

    /**
     * {@inheritDoc}
	 */
	/**
	 * Gets the header.
	 * 
	 * @param name
	 *            the name
	 * 
	 * @return the header
	 */
	public String getHeader(String name) {
		int index = headerNames.indexOf(name);
		if ( index != -1 ) {
			return (String)headerValues.get(index);
		}
		return null;
	}

	/**
	 * Gets the header names.
	 * 
	 * @return the header names
	 */
	public List getHeaderNames() {
		return headerNames;
	}
	

    /**
     * {@inheritDoc}
	 */
	public String encodeRedirectURL(String url) {
	
		return null;
	}

    /**
     * {@inheritDoc}
	 */
	public String encodeRedirectUrl(String url) {
	
		return null;
	}

    /**
     * {@inheritDoc}
	 */
	public String encodeURL(String url) {
	
		return null;
	}

    /**
     * {@inheritDoc}
	 */
	public String encodeUrl(String url) {
	
		return null;
	}

    /**
     * {@inheritDoc}
	 */
	public void sendError(int sc) throws IOException {
	

	}

    /**
     * {@inheritDoc}
	 */
	public void sendError(int sc, String msg) throws IOException {
	

	}

    /**
     * {@inheritDoc}
	 */
	public void sendRedirect(String location) throws IOException {
	

	}

    /**
     * {@inheritDoc}
	 */
	public void setDateHeader(String name, long date) {
		headerNames.add( name );
		headerValues.add( ""+date );
	}

    /**
     * {@inheritDoc}
	 */
	public void setHeader(String name, String value) {
		headerNames.add( name );
		headerValues.add( value );
	}

    /**
     * {@inheritDoc}
	 */
	public void setIntHeader(String name, int value) {
		headerNames.add( name );
		headerValues.add( ""+value );
	}

    /**
     * {@inheritDoc}
	 */
	public void setStatus(int sc) {
		status = sc;
	}

	/**
	 * Gets the status.
	 * 
	 * @return the status
	 */
	public int getStatus() {
		return status;
	}
	
    /**
     * {@inheritDoc}
	 */
	public void setStatus(int sc, String sm) {
	

	}

    /**
     * {@inheritDoc}
	 */
	public void flushBuffer() throws IOException {
	

	}

    /**
     * {@inheritDoc}
	 */
	public int getBufferSize() {
	
		return 0;
	}

    /**
     * {@inheritDoc}
	 */
	public String getCharacterEncoding() {
	
		return null;
	}

    /**
     * {@inheritDoc}
	 */
	public String getContentType() {
	
		return null;
	}

    /**
     * {@inheritDoc}
	 */
	public Locale getLocale() {
	
		return null;
	}

    /**
     * {@inheritDoc}
	 */
	public ServletOutputStream getOutputStream() throws IOException {
	
		return null;
	}

    /**
     * {@inheritDoc}
	 */
	public PrintWriter getWriter() throws IOException {
	
		return null;
	}

    /**
     * {@inheritDoc}
	 */
	public boolean isCommitted() {
	
		return false;
	}

    /**
     * {@inheritDoc}
	 */
	public void reset() {
	

	}

    /**
     * {@inheritDoc}
	 */
	public void resetBuffer() {
	

	}

    /**
     * {@inheritDoc}
	 */
	public void setBufferSize(int size) {
	

	}

    /**
     * {@inheritDoc}
	 */
	public void setCharacterEncoding(String charset) {
	

	}

    /**
     * {@inheritDoc}
	 */
	public void setContentLength(int len) {
	

	}

    /**
     * {@inheritDoc}
	 */
	public void setContentType(String type) {
	

	}

    /**
     * {@inheritDoc}
	 */
	public void setLocale(Locale loc) {
	

	}

}
