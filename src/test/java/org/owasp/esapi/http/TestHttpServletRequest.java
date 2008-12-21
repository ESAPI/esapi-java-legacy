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
import java.security.Principal;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletInputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * The Class TestHttpServletRequest.
 * 
 * @author jwilliams
 */
public class TestHttpServletRequest implements HttpServletRequest {

	/** The requestDispatcher */
	private RequestDispatcher requestDispatcher = new TestRequestDispatcher();
	
    /** The session. */
    private TestHttpSession session = null;

    /** The cookies. */
    private ArrayList cookies = new ArrayList();

    /** The parameters. */
    private Map parameters = new HashMap();

    /** The headers. */
    private Map headers = new HashMap();
    
    private byte[] body;

    private String uri = "/test";

    private String url = "https://www.example.com/test";

    private String contentType = null;
    
    private String method = "POST";
    
    /**
     *
     */
    public TestHttpServletRequest() {
    }

    /**
     *
     * @param uri
     * @param body
     */
    public TestHttpServletRequest(String uri, byte[] body) {
        this.body = body;
        this.uri = uri;
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
        String[] old = (String[])parameters.get(name);
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
    public void addHeader(String name, String value) {
        headers.put(name, value);
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
    
    /**
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

        return 0;
    }

    /**
     * {@inheritDoc}
     * @param name 
     * @return
     */
    public String getHeader(String name) {
        if (name.equals("Content-type")) {
            return "multipart/form-data; boundary=xxx";
        }
        return (String)headers.get(name);
    }

    /**
     * {@inheritDoc}
     * @return
     */
    public Enumeration getHeaderNames() {
        Vector v = new Vector( headers.keySet() );
        return v.elements();
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

        return null;
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
        return new StringBuffer( url );
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
            session = new TestHttpSession();
        } else if (session != null && session.getInvalidated()) {
            session = new TestHttpSession();
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
     */
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

        return null;
    }

    /**
     * {@inheritDoc}
     * @return
     */
    public Enumeration getAttributeNames() {

        return null;
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
        return contentType;
    }

    /**
     *
     * @param value
     */
    public void setContentType( String value ) {
    	contentType = value;
    }
    
    /**
     * {@inheritDoc}
     * @return
     * @throws IOException
     */
    public ServletInputStream getInputStream() throws IOException {
        return new TestServletInputStream(body);
    }

    /**
     * {@inheritDoc}
     * @return
     */
    public String getLocalAddr() {

        return null;
    }

    /**
     * {@inheritDoc}
     * @return
     */
    public String getLocalName() {

        return null;
    }

    /**
     * {@inheritDoc}
     * @return
     */
    public int getLocalPort() {

        return 0;
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
        String[] values = (String[]) parameters.get(name);
        if ( values == null ) return null;
        return values[0];
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
        Vector v = new Vector( parameters.keySet() );
        return v.elements();
    }

    /**
     * {@inheritDoc}
     * @param name
     * @return
     */
    public String[] getParameterValues(String name) {
        return (String[])parameters.get(name);
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
     */
    public String getRealPath(String path) {

        return null;
    }

    /**
     * {@inheritDoc}
     * @return
     */
    public String getRemoteAddr() {

        return null;
    }

    /**
     * {@inheritDoc}
     * @return
     */
    public String getRemoteHost() {

        return null;
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

        return null;
    }

    /**
     * {@inheritDoc}
     * @return
     */
    public String getServerName() {

        return null;
    }

    /**
     * {@inheritDoc}
     * @return
     */
    public int getServerPort() {

        return 0;
    }

    /**
     * {@inheritDoc}
     * @return
     */
    public boolean isSecure() {

        return false;
    }

    /**
     * {@inheritDoc}
     * @param name
     */
    public void removeAttribute(String name) {

    }

    /**
     * {@inheritDoc}
     * @param name 
     * @param o
     */
    public void setAttribute(String name, Object o) {

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
        this.url = url;
    }

}
