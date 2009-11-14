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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.Principal;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
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
import javax.servlet.http.HttpSession;

/**
 * The Class MockHttpServletRequest.
 * 
 * @author jwilliams
 */
public class MockHttpServletRequest implements HttpServletRequest
{
	private static final String HDR_CONTENT_TYPE = "Content-Type";
	private static final String[] EMPTY_STRING_ARRAY = new String[0];

	/** The requestDispatcher */
	private RequestDispatcher requestDispatcher = new MockRequestDispatcher();

	/** The session. */
	private MockHttpSession session = null;

	/** The cookies. */
	private ArrayList cookies = new ArrayList();

	/** The parameters. */
	private Map<String,String[]> parameters = new HashMap<String,String[]>();

	/** The headers. */
	private Map<String,List<String>> headers = new HashMap<String,List<String>>();

	private byte[] body;

	private String scheme = "https";

	private String remoteHost = "64.14.103.52";

	private String serverHost = "64.14.103.52";

	private String uri = "/test";

	private String url = "https://www.example.com" + uri;

	private String querystring = "pid=1&qid=test";

	private String method = "POST";

	private Map<String,Object> attrs = new HashMap<String,Object>();

	/**
	 *
	 */
	public MockHttpServletRequest() {
	}

	/**
	 *
	 * @param uri
	 * @param body
	 */
	public MockHttpServletRequest(String uri, byte[] body) {
		this.body = body;
		this.uri = uri;
	}

	public MockHttpServletRequest( URL url ) {
		scheme = url.getProtocol();
		serverHost = url.getHost();
		uri = url.getPath();
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getAuthType() {
		return null;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getContextPath() {
		return null;
	}

	/**
	 * Adds the parameter.
	 * 
	 * @param name the name
	 * @param value the value
	 */
	public void addParameter(String name, String value) {
		String[] old = parameters.get(name);
		if ( old == null ) {
			old = new String[0];
		}
		String[] updated = new String[old.length + 1];
		for ( int i = 0; i < old.length; i++ ) updated[i] = old[i];
		updated[old.length] = value;
		parameters.put(name, updated);
	}

	/**
	 * removeParameter removes the parameter name from the parameters map if it exists
	 *  
	 * @param name
	 * 			parameter name to be removed
	 */
	public void removeParameter( String name ) {
		parameters.remove( name );
	}

	/**
	 * Adds the header.
	 * 
	 * @param name the name
	 * @param value the value
	 */
	public void addHeader(String name, String value)
	{
		List<String> values;

		if((values = headers.get(name))==null)
		{
			values = new ArrayList<String>();
			headers.put(name, values);
		}
		values.add(value);
	}

	/**
	 * Set a header replacing any previous value(s).
	 * @param name the header name
	 * @param value the header value
	 */
	public void setHeader(String name, String value)
	{
		List<String> values = new ArrayList<String>();

		values.add(value);
		headers.put(name,values);
	}

	/**
	 * Sets the cookies.
	 * 
	 * @param list the new cookies
	 */
	public void setCookies(ArrayList list) {
		cookies = list;
	}

	/**
	 *
	 * @param name
	 * @param value
	 */
	public void setCookie(String name, String value ) {
		Cookie c = new Cookie( name, value );
		cookies.add( c );
	}

	public boolean clearCookie(String name) {
		return cookies.remove(name);
	}

	/**
	 * @return 
	 *
	 */
	public void clearCookies() {
		cookies.clear();
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public Cookie[] getCookies() {
		if ( cookies.isEmpty() ) return null;
		return (Cookie[]) cookies.toArray(new Cookie[0]);
	}

	/**
	 * {@inheritDoc}
	 * @param name 
	 * @return
	 */
	public long getDateHeader(String name) {
		try {
			Date date = SimpleDateFormat.getDateTimeInstance().parse( getParameter( name ) );
			return date.getTime(); // TODO needs to be HTTP format
		} catch( ParseException e ) {
			return 0;
		}
	}

	/**
	 * {@inheritDoc}
	 * @param name 
	 * @return
	 */
	public String getHeader(String name) {
		List<String> values;

		if((values = headers.get(name))==null)
			return null;
		if(values.size() == 0)
			return null;
		return values.get(0);
	}

	/**
	 * {@inheritDoc}
	 * @return Enumeration of header names as strings
	 */
	public Enumeration getHeaderNames()
	{
		return Collections.enumeration(headers.keySet());
	}

	/**
	 * {@inheritDoc}
	 * @param name
	 * @return
	 */
	public Enumeration getHeaders(String name) {
		Vector v = new Vector();
		v.add( getHeader( name ) );
		return v.elements();
	}

	/**
	 * {@inheritDoc}
	 * @param name 
	 * @return
	 */
	public int getIntHeader(String name) {

		return 0;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getMethod() {
		return method;
	}

	/**
	 *
	 * @param value
	 */
	public void setMethod( String value ) {
		method = value;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getPathInfo() {

		return null;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getPathTranslated() {

		return null;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getQueryString() {
		return querystring;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getRemoteUser() {

		return null;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getRequestURI() {
		return uri;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public StringBuffer getRequestURL() {
		return new StringBuffer( getScheme() + "://" + this.getServerName() + getRequestURI() + "?" + getQueryString() );
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getRequestedSessionId() {

		return null;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getServletPath() {

		return null;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public HttpSession getSession() {
		if (session != null) {
			return getSession(false);
		}
		return getSession(true);
	}

	/**
	 * {@inheritDoc}
	 * @param create 
	 * @return
	 */
	public HttpSession getSession(boolean create) {
		if (session == null && create) {
			session = new MockHttpSession();
		} else if (session != null && session.getInvalidated()) {
			session = new MockHttpSession();
		}
		return session;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public Principal getUserPrincipal() {

		return null;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public boolean isRequestedSessionIdFromCookie() {

		return false;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public boolean isRequestedSessionIdFromURL() {

		return false;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 * @deprecated
	 */
	@Deprecated
	public boolean isRequestedSessionIdFromUrl() {

		return false;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public boolean isRequestedSessionIdValid() {

		return false;
	}

	/**
	 * {@inheritDoc}
	 * @param role 
	 * @return
	 */
	public boolean isUserInRole(String role) {

		return false;
	}

	/**
	 * {@inheritDoc}
	 * @param name
	 * @return
	 */
	public Object getAttribute(String name) {
		return attrs.get(name);
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public Enumeration getAttributeNames() {
		return Collections.enumeration(attrs.keySet());
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getCharacterEncoding() {

		return null;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public int getContentLength() {
		return body.length;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getContentType() {
		return getHeader(HDR_CONTENT_TYPE);
	}

	/**
	 *
	 * @param value
	 */
	public void setContentType( String value ) {
		setHeader(HDR_CONTENT_TYPE, value);
	}

	/**
	 * {@inheritDoc}
	 * @return
	 * @throws IOException
	 */
	public ServletInputStream getInputStream() throws IOException {
		return new MockServletInputStream(body);
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getLocalAddr() {
		return "10.1.43.6";
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getLocalName() {
		return "www.domain.com";
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public int getLocalPort() {
		return 80;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public Locale getLocale() {
		return null;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public Enumeration getLocales() {
		return null;
	}

	/**
	 * {@inheritDoc}
	 * @param name
	 * @return
	 */
	public String getParameter(String name) {
		String[] values = parameters.get(name);
		if ( values == null ) return null;
		return values[0];
	}

	public void clearParameter(String name) {
		parameters.remove( name );
	}

	public void clearParameters() {
		parameters.clear();
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public Map getParameterMap() {
		return parameters;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public Enumeration getParameterNames() {
		return Collections.enumeration(parameters.keySet());
	}

	/**
	 * {@inheritDoc}
	 * @param name
	 * @return
	 */
	public String[] getParameterValues(String name) {
		return parameters.get(name);
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getProtocol() {
		return "HTTP/1.1";
	}

	/**
	 * {@inheritDoc}
	 * @return 
	 * @throws IOException
	 */
	public BufferedReader getReader() throws IOException {

		return null;
	}

	/**
	 * {@inheritDoc}
	 * @param path
	 * @return
	 * @deprecated
	 */
	@Deprecated
	public String getRealPath(String path) {

		return null;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getRemoteAddr() {
		return remoteHost;
	}

	public void setRemoteAddr(String remoteHost) {
		this.remoteHost = remoteHost;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getRemoteHost() {
		return remoteHost;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public int getRemotePort() {

		return 0;
	}

	/**
	 * {@inheritDoc}
	 * @param path
	 * @return
	 */
	public RequestDispatcher getRequestDispatcher(String path) {
		return requestDispatcher;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getScheme() {
		return scheme;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public String getServerName() {
		return serverHost;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public int getServerPort() {

		return 80;
	}

	/**
	 * {@inheritDoc}
	 * @return
	 */
	public boolean isSecure() {
		return scheme.equals( "https" );
	}

	/**
	 * {@inheritDoc}
	 * @param name
	 */
	public void removeAttribute(String name) {
		attrs.remove(name);
	}

	/**
	 * {@inheritDoc}
	 * @param name 
	 * @param o
	 */
	public void setAttribute(String name, Object o) {
		attrs.put(name,o);
	}

	/**
	 * {@inheritDoc}
	 * @param env
	 * @throws UnsupportedEncodingException
	 */
	public void setCharacterEncoding(String env) throws UnsupportedEncodingException {

	}

	/**
	 *
	 * @param uri
	 * @throws java.io.UnsupportedEncodingException
	 */
	public void setRequestURI(String uri) throws UnsupportedEncodingException {
		this.uri = uri;
	}

	/**
	 *
	 * @param url
	 * @throws java.io.UnsupportedEncodingException
	 */
	public void setRequestURL(String url) throws UnsupportedEncodingException {
		// get the scheme
		int p = url.indexOf( ":" );
		this.scheme = url.substring( 0, p );

		// get the querystring
		int q = url.indexOf( "?" );
		if ( q != -1 ) {
			querystring = url.substring( q+1 );
			url = url.substring( 0, q );
		}
		this.url = url;
	}

	public void setScheme( String scheme ) {
		this.scheme = scheme;
	}

	public void dump()
	{
		String[] names;

		System.out.println();
		System.out.println( "  " + this.getMethod() + " " + this.getRequestURL() );

		names = headers.keySet().toArray(EMPTY_STRING_ARRAY);
		Arrays.sort(names);	// make debugging a bit easier...
		for (String name : names)
			for(String value : headers.get(name))
				System.out.println( "  " + name + ": " + value);
		names = parameters.keySet().toArray(EMPTY_STRING_ARRAY);
		Arrays.sort(names);
		for (String name : names) {
			for(String value : parameters.get(name))
				System.out.println( "  " + name + "=" + value);
		}
		System.out.println( "\n" );
	}

}
