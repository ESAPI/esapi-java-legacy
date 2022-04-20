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
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.ESAPI;

/**
 * The Class MockHttpServletResponse.
 * 
 * @author jwilliams
 */
public class MockHttpServletResponse implements HttpServletResponse {

	/** The cookies. */
	List<Cookie> cookies = new ArrayList<Cookie>();

	/** The header names. */
	List<String> headerNames = new ArrayList<String>();

	/** The header values. */
	List<String> headerValues = new ArrayList<String>();

	/** The status. */
	int status = 200;

	StringBuffer body = new StringBuffer();

	String contentType = "text/html; charset=ISO-8895-1";

	public String getBody() {
		return body.toString();
	}
	
	/**
	 * {@inheritDoc}
	 */
	public void addCookie(Cookie cookie) {
		cookies.add(cookie);
	}

	public List<Cookie> getCookies() {
		return cookies;
	}

	public Cookie getCookie(String name) {
		Iterator<Cookie> i = cookies.iterator();
		while (i.hasNext()) {
			Cookie c = i.next();
			if (c.getName().equals(name)) {
				return c;
			}
		}
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	public void addDateHeader(String name, long date) {
		headerNames.add(name);
		headerValues.add("" + date);
	}

	/**
	 * {@inheritDoc}
	 */
	public void addHeader(String name, String value) {
		headerNames.add(name);
		headerValues.add(value);
	}

	/**
	 * {@inheritDoc}
	 */
	public void addIntHeader(String name, int value) {
		headerNames.add(name);
		headerValues.add("" + value);
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
	public String getHeader(String name) {
		int index = headerNames.indexOf(name);
		if (index != -1) {
			return headerValues.get(index);
		}
		return null;
	}

	/**
	 * Gets the header names.
	 * 
	 * @return the header names
	 */
	public List<String> getHeaderNames() {
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
	 * @deprecated
	 */
	@Deprecated
	public String encodeRedirectUrl(String url) {
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	public String encodeURL(String url) {
		String enc = url;
		try { enc = ESAPI.encoder().encodeForURL(url);
		} catch( Exception e ) {}
		return enc;
	}

	/**
	 * {@inheritDoc}
	 * @deprecated
	 */
	@Deprecated
	public String encodeUrl(String url) {
		return encodeURL( url );
	}

	/**
	 * {@inheritDoc}
	 */
	public void sendError(int sc) throws IOException {
		status = sc;
	}

	/**
	 * {@inheritDoc}
	 */
	public void sendError(int sc, String msg) throws IOException {
		status = sc;
	}

	/**
	 * {@inheritDoc}
	 */
	public void sendRedirect(String location) throws IOException {
		status = HttpServletResponse.SC_MOVED_PERMANENTLY;
		body = new StringBuffer( "Redirect to " + location );
	}

	/**
	 * {@inheritDoc}
	 */
	public void setDateHeader(String name, long date) {
		headerNames.add(name);
		headerValues.add("" + date);
	}

	/**
	 * {@inheritDoc}
	 */
	public void setHeader(String name, String value) {
		headerNames.add(name);
		headerValues.add(value);
	}

	/**
	 * {@inheritDoc}
	 */
	public void setIntHeader(String name, int value) {
		headerNames.add(name);
		headerValues.add("" + value);
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
	 * @deprecated
	 */
	@Deprecated
	public void setStatus(int sc, String sm) {
		status = sc;
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
		return body.length();
	}

	/**
	 * {@inheritDoc}
	 */
	public String getCharacterEncoding() {
		return "UTF-8";
	}

	/**
	 * {@inheritDoc}
	 */
	public String getContentType() {
		return contentType;
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
		return new ServletOutputStream() {
			public void write(int b) throws IOException {
				body.append((char)b);
			}
		};
	}

	/**
	 * {@inheritDoc}
	 */
	public PrintWriter getWriter() throws IOException {
		return new PrintWriter( getOutputStream(), true );
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
		body = new StringBuffer();
		cookies = new ArrayList<Cookie>();
		headerNames = new ArrayList<String>();
		headerValues = new ArrayList<String>();
		status = 200;
	}

	/**
	 * {@inheritDoc}
	 */
	public void resetBuffer() {
		body = new StringBuffer();
	}

	public void setBody( String value ) {
		body = new StringBuffer( value );
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
		contentType = type;
	}

	/**
	 * {@inheritDoc}
	 */
	public void setLocale(Locale loc) {

	}

	/*
	 * Dump the response in a semi-readable format close to a real HTTP response on the wire
	 */
	public void dump() {
        System.out.println();
		System.out.println( "  " + this.getStatus() + " " );
        for ( Object name : getHeaderNames() ) System.out.println( "  " + name + "=" + getHeader( (String)name ) );
        System.out.println( "  BODY: " + this.getBody() );
        System.out.println();
	}

    @Override
    public Collection<String> getHeaders(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
	
}
