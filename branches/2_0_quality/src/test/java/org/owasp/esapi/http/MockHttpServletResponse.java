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

import org.owasp.esapi.ESAPI;

/**
 * The Class MockHttpServletResponse.
 * 
 * @author jwilliams
 */
public class MockHttpServletResponse implements HttpServletResponse {

	/** The cookies. */
	List cookies = new ArrayList();

	/** The header names. */
	List headerNames = new ArrayList();

	/** The header values. */
	List headerValues = new ArrayList();

	/** The status. */
	int status = 200;

	StringBuffer body = new StringBuffer();

	public String getBody() {
		return body.toString();
	}
	
	/**
	 * {@inheritDoc}
	 * 
	 * @param cookie
	 */
	public void addCookie(Cookie cookie) {
		cookies.add(cookie);
	}

	/**
	 * Gets the cookies.
	 * 
	 * @return the cookies
	 */
	public List getCookies() {
		return cookies;
	}

	/**
	 * 
	 * @param name
	 * @return
	 */
	public Cookie getCookie(String name) {
		Iterator i = cookies.iterator();
		while (i.hasNext()) {
			Cookie c = (Cookie) i.next();
			if (c.getName().equals(name)) {
				return c;
			}
		}
		return null;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param name
	 * @param date
	 */
	public void addDateHeader(String name, long date) {
		headerNames.add(name);
		headerValues.add("" + date);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param name
	 * @param value
	 */
	public void addHeader(String name, String value) {
		headerNames.add(name);
		headerValues.add(value);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param name
	 * @param value
	 */
	public void addIntHeader(String name, int value) {
		headerNames.add(name);
		headerValues.add("" + value);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param name
	 * @return
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
		if (index != -1) {
			return (String) headerValues.get(index);
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
	 * 
	 * @param url
	 * @return
	 */
	public String encodeRedirectURL(String url) {
		return null;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param url
	 * @return
	 */
	public String encodeRedirectUrl(String url) {
		return null;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param url
	 * @return
	 */
	public String encodeURL(String url) {
		String enc = url;
		try { enc = ESAPI.encoder().encodeForURL(url);
		} catch( Exception e ) {}
		return enc;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param url
	 * @return
	 */
	public String encodeUrl(String url) {
		return encodeURL( url );
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param sc
	 * @throws IOException
	 */
	public void sendError(int sc) throws IOException {
		status = sc;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param sc
	 * @param msg
	 * @throws IOException
	 */
	public void sendError(int sc, String msg) throws IOException {
		status = sc;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param location
	 * @throws IOException
	 */
	public void sendRedirect(String location) throws IOException {
		status = HttpServletResponse.SC_MOVED_PERMANENTLY;
		body = new StringBuffer( "Redirect to " + location );
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param name
	 * @param date
	 */
	public void setDateHeader(String name, long date) {
		headerNames.add(name);
		headerValues.add("" + date);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param name
	 * @param value
	 */
	public void setHeader(String name, String value) {
		headerNames.add(name);
		headerValues.add(value);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param name
	 * @param value
	 */
	public void setIntHeader(String name, int value) {
		headerNames.add(name);
		headerValues.add("" + value);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param sc
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
	 * 
	 * @param sc
	 * @param sm
	 */
	public void setStatus(int sc, String sm) {
		status = sc;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @throws IOException
	 */
	public void flushBuffer() throws IOException {

	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return
	 */
	public int getBufferSize() {
		return body.length();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return
	 */
	public String getCharacterEncoding() {
		return "UTF-8";
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return
	 */
	public String getContentType() {
		return "text/html";
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return
	 */
	public Locale getLocale() {

		return null;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return
	 * @throws IOException
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
	 * 
	 * @return
	 * @throws IOException
	 */
	public PrintWriter getWriter() throws IOException {
		return new PrintWriter( getOutputStream(), true );
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @return
	 */
	public boolean isCommitted() {

		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	public void reset() {
		body = new StringBuffer();
		cookies = new ArrayList();
		headerNames = new ArrayList();
		headerValues = new ArrayList();
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
	 * 
	 * @param size
	 */
	public void setBufferSize(int size) {

	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param charset
	 */
	public void setCharacterEncoding(String charset) {

	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param len
	 */
	public void setContentLength(int len) {

	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param type
	 */
	public void setContentType(String type) {

	}

	/**
	 * {@inheritDoc}
	 * 
	 * @param loc
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
	
}
