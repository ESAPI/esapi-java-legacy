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
 * @author     Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created    February 6, 2009
 */

package org.owasp.esapi.filters;
import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

/**
 * The {@code ClickjackFilter} is discussed at
 * {@link http://www.owasp.org/index.php/ClickjackFilter_for_Java_EE}.
 * <pre>
 *     <filter>
 *            <filter-name>ClickjackFilterDeny</filter-name>
 *            <filter-class>org.owasp.filters.ClickjackFilter</filter-class>
 *            <init-param>
 *                <param-name>mode</param-name>
 *                 <param-value>DENY</param-value>
 *             </init-param>
 *         </filter>
 *         
 *         <filter>
 *             <filter-name>ClickjackFilterSameOrigin</filter-name>
 *             <filter-class>org.owasp.filters.ClickjackFilter</filter-class>
 *             <init-param>
 *                 <param-name>mode</param-name>
 *                 <param-value>SAMEORIGIN</param-value>
 *             </init-param>
 *         </filter>
 *        
 *        <!--  use the Deny version to prevent anyone, including yourself, from framing the page -->
 *        <filter-mapping> 
 *            <filter-name>ClickjackFilterDeny</filter-name>
 *            <url-pattern>/*</url-pattern>
 *        </filter-mapping>
 *         
 *         <!-- use the SameOrigin version to allow your application to frame, but nobody else
 *         <filter-mapping> 
 *            <filter-name>ClickjackFilterSameOrigin</filter-name>
 *             <url-pattern>/*</url-pattern>
 *         </filter-mapping>
 * </pre>
 */
public class ClickjackFilter implements Filter 
{

	private String mode = "DENY";

	/**
	 * Initialize "mode" parameter from web.xml. Valid values are "DENY" and "SAMEORIGIN". 
	 * If you leave this parameter out, the default is to use the DENY mode.
	 * 
	 * @param filterConfig A filter configuration object used by a servlet container
	 *                     to pass information to a filter during initialization. 
	 */
	public void init(FilterConfig filterConfig) {
		String configMode = filterConfig.getInitParameter("mode");
		if ( configMode != null && ( configMode.equals( "DENY" ) || configMode.equals( "SAMEORIGIN" ) ) ) {
			mode = configMode;
		}
	}
	
	/**
	 * Add X-FRAME-OPTIONS response header to tell IE8 (and any other browsers who
	 * decide to implement) not to display this content in a frame. For details, please
	 * refer to
	 * {@link http://blogs.msdn.com/sdl/archive/2009/02/05/clickjacking-defense-in-ie8.aspx}.
	 * 
	 * @param request The request object.
	 * @param response The response object.
	 * @param chain Refers to the {@code FilterChain} object to pass control to the
	 *              next {@code Filter}.
	 * @throws IOException
	 * @throws ServletException
	 */
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException
	{
        HttpServletResponse res = (HttpServletResponse)response;
        chain.doFilter(request, response);
        res.addHeader("X-FRAME-OPTIONS", mode );
	}

	/**
	 * {@inheritDoc}
	 */
	public void destroy() {
	}
	
}
