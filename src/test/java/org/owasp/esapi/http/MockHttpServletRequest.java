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
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;
import javax.servlet.AsyncContext;
import javax.servlet.DispatcherType;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.Part;

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
	private ArrayList<Cookie> cookies = new ArrayList<Cookie>();

	/** The parameters. */
	private Map<String,String[]> parameters = new HashMap<String,String[]>();

	/** The headers. */
	private Map<String,List<String>> headers = new HashMap<String,List<String>>();

	private byte[] body;

	private String scheme = "https";

	private String remoteHost = "64.14.103.52";

	private String serverHost = "64.14.103.52";

	private String uri = "/test";

	private String queryString = "pid=1&qid=test";

	private String method = "POST";

	private Map<String,Object> attrs = new HashMap<String,Object>();

	public MockHttpServletRequest() {
	}

	public MockHttpServletRequest(String uri, byte[] body) {
		this.body = body;
		this.uri = uri;
	}

	public MockHttpServletRequest( URL url ) {
		scheme = url.getProtocol();
		serverHost = url.getHost();
		uri = url.getPath();
	}

	public String getAuthType() {
		return null;
	}

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
	public void setCookies(ArrayList<Cookie> list) {
		cookies = list;
	}

	public void setCookie(String name, String value ) {
		Cookie c = new Cookie( name, value );
		cookies.add( c );
	}

	public boolean clearCookie(String name) {
		return cookies.remove(name);
	}

	public void clearCookies() {
		cookies.clear();
	}

	/**
	 * {@inheritDoc}
	 */
	public Cookie[] getCookies() {
		if ( cookies.isEmpty() ) return null;
		return cookies.toArray(new Cookie[0]);
	}

	/**
	 * {@inheritDoc}
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
	 * @return The requested header value.
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
	public Enumeration<String> getHeaderNames()
	{
		return Collections.enumeration(headers.keySet());
	}

	/**
	 * {@inheritDoc}
	 */
	public Enumeration<String> getHeaders(String name) {
		Vector<String> v = new Vector<String>();
		v.add( getHeader( name ) );
		return v.elements();
	}

	/**
	 * {@inheritDoc}
	 */
	public int getIntHeader(String name) {

		return 0;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getMethod() {
		return method;
	}

	public void setMethod( String value ) {
		method = value;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getPathInfo() {

		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getPathTranslated() {

		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getQueryString() {
		return queryString;
	}

	/**
	 * Set the query string to return.
	 * @param str The query string to return.
	 */
	public void setQueryString(String str)
	{
		this.queryString = str;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getRemoteUser() {

		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getRequestURI() {
		return uri;
	}

	/**
	 * {@inheritDoc}
	 */
	public StringBuffer getRequestURL() {
		return new StringBuffer( getScheme() + "://" + this.getServerName() + getRequestURI() + "?" + getQueryString() );
	}

	/**
	 * {@inheritDoc}
	 */
	public String getRequestedSessionId() {

		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getServletPath() {

		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	public HttpSession getSession() {
		if (session != null) {
			return getSession(false);
		}
		return getSession(true);
	}

	/**
	 * {@inheritDoc}
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
	 */
	public Principal getUserPrincipal() {

		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isRequestedSessionIdFromCookie() {

		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isRequestedSessionIdFromURL() {

		return false;
	}

	/**
	 * {@inheritDoc}
	 * @deprecated
	 */
	@Deprecated
	public boolean isRequestedSessionIdFromUrl() {

		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isRequestedSessionIdValid() {

		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isUserInRole(String role) {

		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	public Object getAttribute(String name) {
		return attrs.get(name);
	}

	/**
	 * {@inheritDoc}
	 */
	public Enumeration<String> getAttributeNames() {
		return Collections.enumeration(attrs.keySet());
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
	public int getContentLength() {
		return body.length;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getContentType() {
		return getHeader(HDR_CONTENT_TYPE);
	}

	public void setContentType( String value ) {
		setHeader(HDR_CONTENT_TYPE, value);
	}

	/**
	 * {@inheritDoc}
	 */
	public ServletInputStream getInputStream() throws IOException {
		return new MockServletInputStream(body);
	}

	/**
	 * {@inheritDoc}
	 */
	public String getLocalAddr() {
		return "10.1.43.6";
	}

	/**
	 * {@inheritDoc}
	 */
	public String getLocalName() {
		return "www.domain.com";
	}

	/**
	 * {@inheritDoc}
	 */
	public int getLocalPort() {
		return 80;
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
	public Enumeration<Locale> getLocales() {
		return null;
	}

	/**
	 * {@inheritDoc}
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
	 */
	public Map<String, String[]> getParameterMap() {
		return parameters;
	}

	/**
	 * {@inheritDoc}
	 */
	public Enumeration<String> getParameterNames() {
		return Collections.enumeration(parameters.keySet());
	}

	/**
	 * {@inheritDoc}
	 */
	public String[] getParameterValues(String name) {
		return parameters.get(name);
	}

	/**
	 * {@inheritDoc}
	 */
	public String getProtocol() {
		return "HTTP/1.1";
	}

	/**
	 * {@inheritDoc}
	 */
	public BufferedReader getReader() throws IOException {

		return null;
	}

	/**
	 * {@inheritDoc}
	 * @deprecated
	 */
	@Deprecated
	public String getRealPath(String path) {

		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getRemoteAddr() {
		return remoteHost;
	}

	public void setRemoteAddr(String remoteHost) {
		this.remoteHost = remoteHost;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getRemoteHost() {
		return remoteHost;
	}

	/**
	 * {@inheritDoc}
	 */
	public int getRemotePort() {

		return 0;
	}

	/**
	 * {@inheritDoc}
	 */
	public RequestDispatcher getRequestDispatcher(String path) {
		return requestDispatcher;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getScheme() {
		return scheme;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getServerName() {
		return serverHost;
	}

	/**
	 * {@inheritDoc}
	 */
	public int getServerPort() {
		return 80;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isSecure() {
		return scheme.equals( "https" );
	}

	/**
	 * {@inheritDoc}
	 */
	public void removeAttribute(String name) {
		attrs.remove(name);
	}

	/**
	 * {@inheritDoc}
	 */
	public void setAttribute(String name, Object o) {
		attrs.put(name,o);
	}

	/**
	 * {@inheritDoc}
	 */
	public void setCharacterEncoding(String env) throws UnsupportedEncodingException {

	}

	public void setRequestURI(String uri) throws UnsupportedEncodingException {
		this.uri = uri;
	}

	public void setRequestURL(String url) throws UnsupportedEncodingException {
		// get the scheme
		int p = url.indexOf( ":" );
		this.scheme = url.substring( 0, p );

		// get the queryString
		int q = url.indexOf( "?" );
		if ( q != -1 )
		{
			queryString = url.substring( q+1 );
			url = url.substring( 0, q );
		}
		else
			queryString = null;
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

    @Override
    public boolean authenticate(HttpServletResponse hsr) throws IOException, ServletException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void login(String string, String string1) throws ServletException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void logout() throws ServletException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Collection<Part> getParts() throws IOException, ServletException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Part getPart(String string) throws IOException, ServletException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public ServletContext getServletContext() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public AsyncContext startAsync() throws IllegalStateException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public AsyncContext startAsync(ServletRequest sr, ServletResponse sr1) throws IllegalStateException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean isAsyncStarted() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean isAsyncSupported() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public AsyncContext getAsyncContext() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public DispatcherType getDispatcherType() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}
