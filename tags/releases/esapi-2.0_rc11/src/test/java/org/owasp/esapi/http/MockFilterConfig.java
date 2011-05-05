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

import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;

import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;

/**
 * A filter configuration object used by a servlet container
 * to pass information to a filter during initialization.
 */
public class MockFilterConfig implements FilterConfig {
	private Map map;

	public MockFilterConfig( Map map ) {
		this.map = map;
	}
	
    public String getFilterName() {
    	return "mock";
    }

    /**
     * Returns a reference to the {@link ServletContext} in which the caller
     * is executing.
     */
    public ServletContext getServletContext() {
    	return new MockServletContext();
    }

    /**
     * Returns a <code>String</code> containing the value of the
     * named initialization parameter, or <code>null</code> if
     * the parameter does not exist.
     */
    public String getInitParameter(String name) {
    	return (String)map.get( name );
    }

    /**
     * Returns the names of the filter's initialization parameters
     * as an <code>Enumeration</code> of <code>String</code> objects,
     * or an empty <code>Enumeration</code> if the filter has
     * no initialization parameters.
     */
    public Enumeration getInitParameterNames() {
    	return Collections.enumeration( map.keySet() );
    }
}
