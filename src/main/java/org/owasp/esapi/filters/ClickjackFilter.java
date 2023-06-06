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

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;

/**
 * The {@code ClickjackFilter} is configured as follows:
 * <pre>
 *
 *     &lt;filter&gt;
 *            &lt;filter-name&gt;ClickjackFilterDeny&lt;/filter-name&gt;
 *            &lt;filter-class&gt;org.owasp.filters.ClickjackFilter&lt;/filter-class&gt;
 *            &lt;init-param&gt;
 *                &lt;param-name&gt;mode&lt;/param-name&gt;
 *                 &lt;param-value&gt;DENY&lt;/param-value&gt;
 *             &lt;/init-param&gt;
 *         &lt;/filter&gt;
 *
 *         &lt;filter&gt;
 *             &lt;filter-name&gt;ClickjackFilterSameOrigin&lt;/filter-name&gt;
 *             &lt;filter-class&gt;org.owasp.filters.ClickjackFilter&lt;/filter-class&gt;
 *             &lt;init-param&gt;
 *                 &lt;param-name&gt;mode&lt;/param-name&gt;
 *                 &lt;param-value&gt;SAMEORIGIN&lt;/param-value&gt;
 *             &lt;/init-param&gt;
 *         &lt;/filter&gt;
 *
 *        &lt;!--  use the Deny version to prevent anyone, including yourself, from framing the page --&gt;
 *        &lt;filter-mapping&gt;
 *            &lt;filter-name&gt;ClickjackFilterDeny&lt;/filter-name&gt;
 *            &lt;url-pattern&gt;/*&lt;/url-pattern&gt;
 *        &lt;/filter-mapping&gt;
 *
 *         &lt;!-- use the SameOrigin version to allow your application to frame, but nobody else
 *         &lt;filter-mapping&gt;
 *            &lt;filter-name&gt;ClickjackFilterSameOrigin&lt;/filter-name&gt;
 *             &lt;url-pattern&gt;/*&lt;/url-pattern&gt;
 *         &lt;/filter-mapping&gt;
 * </pre>
 *
 * @see <a href="https://web.archive.org/web/20131020084831/https://www.owasp.org/index.php/ClickjackFilter_for_Java_EE">
 *          OWASP - Clickjacking Filter for JavaEE</a>
 * @see <a href="https://owasp.org/www-community/attacks/Clickjacking">OWASP - Clickjacking Attack</a>
 * @see <a href="https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html">
 *          OWASP - Clickjacking Defense Cheat Sheet</a>
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
     * @link http://blogs.msdn.com/sdl/archive/2009/02/05/clickjacking-defense-in-ie8.aspx
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
        res.addHeader("X-FRAME-OPTIONS", mode );
        chain.doFilter(request, response);
    }

    /**
     * {@inheritDoc}
     */
    public void destroy() {
    }

}
