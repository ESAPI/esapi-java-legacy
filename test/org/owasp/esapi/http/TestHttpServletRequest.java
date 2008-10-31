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

    private String contentType = null;
    
    private String method = "POST";
    
    public TestHttpServletRequest() {
    }

    public TestHttpServletRequest(String uri, byte[] body) {
        this.body = body;
        this.uri = uri;
    }

    /**
     * {@inheritDoc}
     */
    public String getAuthType() {
        return null;
    }

    /**
     * {@inheritDoc}
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

    public void setCookie(String name, String value ) {
    	Cookie c = new Cookie( name, value );
    	cookies.add( c );
    }
    
    public void clearCookies() {
    	cookies.clear();
    }
    
    /**
     * {@inheritDoc}
     */
    public Cookie[] getCookies() {
        return (Cookie[]) cookies.toArray(new Cookie[0]);
    }

    /**
     * {@inheritDoc}
     */
    public long getDateHeader(String name) {

        return 0;
    }

    /**
     * {@inheritDoc}
     */
    public String getHeader(String name) {
        if (name.equals("Content-type")) {
            return "multipart/form-data; boundary=xxx";
        }
        return (String)headers.get(name);
    }

    /**
     * {@inheritDoc}
     */
    public Enumeration getHeaderNames() {
        Vector v = new Vector( headers.keySet() );
        return v.elements();
    }

    /**
     * {@inheritDoc}
     */
    public Enumeration getHeaders(String name) {
        Vector v = new Vector();
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

        return null;
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
        return new StringBuffer("https://localhost" + uri);
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
            session = new TestHttpSession();
        } else if (session != null && session.getInvalidated()) {
            session = new TestHttpSession();
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
     */
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

        return null;
    }

    /**
     * {@inheritDoc}
     */
    public Enumeration getAttributeNames() {

        return null;
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
        return contentType;
    }

    public void setContentType( String value ) {
    	contentType = value;
    }
    
    /**
     * {@inheritDoc}
     */
    public ServletInputStream getInputStream() throws IOException {
        return new TestServletInputStream(body);
    }

    /**
     * {@inheritDoc}
     */
    public String getLocalAddr() {

        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getLocalName() {

        return null;
    }

    /**
     * {@inheritDoc}
     */
    public int getLocalPort() {

        return 0;
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
    public Enumeration getLocales() {

        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getParameter(String name) {
        String[] values = (String[]) parameters.get(name);
        if ( values == null ) return null;
        return values[0];
    }

    /**
     * {@inheritDoc}
     */
    public Map getParameterMap() {
        return parameters;
    }

    /**
     * {@inheritDoc}
     */
    public Enumeration getParameterNames() {
        Vector v = new Vector( parameters.keySet() );
        return v.elements();
    }

    /**
     * {@inheritDoc}
     */
    public String[] getParameterValues(String name) {
        return (String[])parameters.get(name);
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
     */
    public String getRealPath(String path) {

        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getRemoteAddr() {

        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getRemoteHost() {

        return null;
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

        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getServerName() {

        return null;
    }

    /**
     * {@inheritDoc}
     */
    public int getServerPort() {

        return 0;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isSecure() {

        return false;
    }

    /**
     * {@inheritDoc}
     */
    public void removeAttribute(String name) {

    }

    /**
     * {@inheritDoc}
     */
    public void setAttribute(String name, Object o) {

    }

    /**
     * {@inheritDoc}
     */
    public void setCharacterEncoding(String env) throws UnsupportedEncodingException {

    }

    public void setRequestURI(String uri) throws UnsupportedEncodingException {
    	this.uri = uri;
    }

}
