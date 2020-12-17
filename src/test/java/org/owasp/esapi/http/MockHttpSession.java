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

import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;

/**
 * The Class MockHttpSession.
 * 
 * @author jwilliams
 */
public class MockHttpSession implements HttpSession {

	/** The invalidated. */
	boolean invalidated = false;
	
	/** The creation time. */
	private long creationTime=new Date().getTime();
	
	/** The accessed time. */
	private long accessedTime=new Date().getTime();
	
	/** The count. */
	private static int count = 1;
	
	/** The sessionid. */
	private int sessionid=count++;
	
	/** The attributes. */
	private Map<String, Object> attributes = new HashMap<String, Object>();
	
	/**
	 * Instantiates a new test HTTP session.
	 */
	public MockHttpSession() {
		// to replace synthetic accessor method
	}
	
	/**
	 * Instantiates a new test http session.
	 * 
	 * @param creationTime
	 *            the creation time
	 * @param accessedTime
	 *            the accessed time
	 */
	public MockHttpSession( long creationTime, long accessedTime ) {
		this.creationTime = creationTime;
		this.accessedTime = accessedTime;
	}

    /**
     * {@inheritDoc}
     */
	public Object getAttribute(String string) {
		return attributes.get( string );
	}

    /**
     * {@inheritDoc}
     */
	public Enumeration<String> getAttributeNames() {
		Vector<String> v = new Vector<String>( attributes.keySet() );
		return v.elements();
	}

    /**
     * {@inheritDoc}
     */
	public long getCreationTime() {
		return creationTime;
	}

    /**
     * {@inheritDoc}
     */
	public String getId() {
		return ""+sessionid;
	}

	/**
	 * Gets the invalidated.
	 * 
	 * @return the invalidated
	 */
	public boolean getInvalidated() {
		return invalidated;
	}

    /**
     * {@inheritDoc}
     */
	public long getLastAccessedTime() {
		return accessedTime;
	}

    /**
     * {@inheritDoc}
     */
	public int getMaxInactiveInterval() {
		return 0;
	}

    /**
     * {@inheritDoc}
     */
	public ServletContext getServletContext() {
		return null;
	}

    /**
     * {@inheritDoc}
     * @deprecated
     */
        @Deprecated
	// need the full class here as for whatever stupid reason you can't
	// seem to @SuppressWarnings{'deprecation'} on the import... *sigh*
	public javax.servlet.http.HttpSessionContext getSessionContext() {
		return null;
	}

    /**
     * {@inheritDoc}
     * @deprecated
     */
     	@Deprecated
	public Object getValue(String string) {
		return null;
	}

    /**
     * {@inheritDoc}
     * @deprecated
     */
     	@Deprecated
	public String[] getValueNames() {
		return null;
	}

    /**
     * {@inheritDoc}
	 */
	public void invalidate() {
		invalidated = true;
	}
    
    /**
     * {@inheritDoc}
     */
	public boolean isNew() {
		return true;
	}

	/**
     * {@inheritDoc}
     * @deprecated
     */
     	@Deprecated
	public void putValue(String string, Object object) {
		setAttribute( string, object );
	}

    /**
     * {@inheritDoc}
     */
	public void removeAttribute(String string) {
		attributes.remove( string );
	}

    /**
     * {@inheritDoc}
     * @deprecated
     */
     	@Deprecated
	public void removeValue(String string) {
		removeAttribute( string );
	}

    /**
     * {@inheritDoc}
     */
	public void setAttribute(String string, Object object) {
		attributes.put(string, object);
	}

    /**
     * {@inheritDoc}
=     */
	public void setMaxInactiveInterval(int i) {
		// stub
	}
	
    /**
     *
     * @param time
     */
    public void setAccessedTime( long time ) {
		this.accessedTime = time;
	}

	
    /**
     *
     * @param time
     */
    public void setCreationTime( long time ) {
		this.creationTime = time;
	}

}

