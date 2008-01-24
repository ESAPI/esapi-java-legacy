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

    /** The session. */
    private TestHttpSession session = null;

    /** The cookies. */
    private ArrayList cookies = new ArrayList();

    /** The parameters. */
    private Map parameters = new HashMap();

    /** The headers. */
    private Map headers = new HashMap();
    
    private byte[] body;

    private String uri = null;

    public TestHttpServletRequest() {
    }

    public TestHttpServletRequest(String uri, byte[] body) {
        this.body = body;
        this.uri = uri;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getAuthType()
     */
    public String getAuthType() {
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getContextPath()
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
    
    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getCookies()
     */
    public Cookie[] getCookies() {
        return (Cookie[]) cookies.toArray(new Cookie[0]);
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getDateHeader(java.lang.String)
     */
    public long getDateHeader(String name) {

        return 0;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getHeader(java.lang.String)
     */
    public String getHeader(String name) {
        if (name.equals("Content-type")) {
            return "multipart/form-data; boundary=xxx";
        }
        return (String)headers.get(name);
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getHeaderNames()
     */
    public Enumeration getHeaderNames() {
        Vector v = new Vector( headers.keySet() );
        return v.elements();
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getHeaders(java.lang.String)
     */
    public Enumeration getHeaders(String name) {
        Vector v = new Vector();
        v.add( getHeader( name ) );
        return v.elements();
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getIntHeader(java.lang.String)
     */
    public int getIntHeader(String name) {

        return 0;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getMethod()
     */
    public String getMethod() {
        return "POST";
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getPathInfo()
     */
    public String getPathInfo() {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getPathTranslated()
     */
    public String getPathTranslated() {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getQueryString()
     */
    public String getQueryString() {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getRemoteUser()
     */
    public String getRemoteUser() {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getRequestURI()
     */
    public String getRequestURI() {
        return uri;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getRequestURL()
     */
    public StringBuffer getRequestURL() {
        return new StringBuffer("https://localhost" + uri);
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getRequestedSessionId()
     */
    public String getRequestedSessionId() {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getServletPath()
     */
    public String getServletPath() {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getSession()
     */
    public HttpSession getSession() {
        if (session != null) {
            return getSession(false);
        }
        return getSession(true);
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getSession(boolean)
     */
    public HttpSession getSession(boolean create) {
        if (session == null && create) {
            session = new TestHttpSession();
        } else if (session != null && session.getInvalidated()) {
            session = new TestHttpSession();
        }
        return session;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#getUserPrincipal()
     */
    public Principal getUserPrincipal() {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#isRequestedSessionIdFromCookie()
     */
    public boolean isRequestedSessionIdFromCookie() {

        return false;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#isRequestedSessionIdFromURL()
     */
    public boolean isRequestedSessionIdFromURL() {

        return false;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#isRequestedSessionIdFromUrl()
     */
    public boolean isRequestedSessionIdFromUrl() {

        return false;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#isRequestedSessionIdValid()
     */
    public boolean isRequestedSessionIdValid() {

        return false;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.http.HttpServletRequest#isUserInRole(java.lang.String)
     */
    public boolean isUserInRole(String role) {

        return false;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getAttribute(java.lang.String)
     */
    public Object getAttribute(String name) {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getAttributeNames()
     */
    public Enumeration getAttributeNames() {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getCharacterEncoding()
     */
    public String getCharacterEncoding() {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getContentLength()
     */
    public int getContentLength() {
        return body.length;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getContentType()
     */
    public String getContentType() {
        return "multipart/form-data; boundary=xxx";
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getInputStream()
     */
    public ServletInputStream getInputStream() throws IOException {
        return new TestServletInputStream(body);
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getLocalAddr()
     */
    public String getLocalAddr() {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getLocalName()
     */
    public String getLocalName() {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getLocalPort()
     */
    public int getLocalPort() {

        return 0;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getLocale()
     */
    public Locale getLocale() {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getLocales()
     */
    public Enumeration getLocales() {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getParameter(java.lang.String)
     */
    public String getParameter(String name) {
        String[] values = (String[]) parameters.get(name);
        return values[0];
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getParameterMap()
     */
    public Map getParameterMap() {
        return parameters;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getParameterNames()
     */
    public Enumeration getParameterNames() {
        Vector v = new Vector( parameters.keySet() );
        return v.elements();
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getParameterValues(java.lang.String)
     */
    public String[] getParameterValues(String name) {
        return (String[])parameters.get(name);
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getProtocol()
     */
    public String getProtocol() {
        return "HTTP/1.1";
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getReader()
     */
    public BufferedReader getReader() throws IOException {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getRealPath(java.lang.String)
     */
    public String getRealPath(String path) {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getRemoteAddr()
     */
    public String getRemoteAddr() {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getRemoteHost()
     */
    public String getRemoteHost() {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getRemotePort()
     */
    public int getRemotePort() {

        return 0;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getRequestDispatcher(java.lang.String)
     */
    public RequestDispatcher getRequestDispatcher(String path) {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getScheme()
     */
    public String getScheme() {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getServerName()
     */
    public String getServerName() {

        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#getServerPort()
     */
    public int getServerPort() {

        return 0;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#isSecure()
     */
    public boolean isSecure() {

        return false;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#removeAttribute(java.lang.String)
     */
    public void removeAttribute(String name) {

    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#setAttribute(java.lang.String, java.lang.Object)
     */
    public void setAttribute(String name, Object o) {

    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.ServletRequest#setCharacterEncoding(java.lang.String)
     */
    public void setCharacterEncoding(String env) throws UnsupportedEncodingException {

    }

}
