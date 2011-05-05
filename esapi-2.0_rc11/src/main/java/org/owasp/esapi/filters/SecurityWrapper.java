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
package org.owasp.esapi.filters;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.StringUtilities;


/**
 * This filter wraps the incoming request and outgoing response and overrides
 * many methods with safer versions. Many of the safer versions simply validate
 * parts of the request or response for unwanted characters before allowing the
 * call to complete. Some examples of attacks that use these
 * vectors include request splitting, response splitting, and file download
 * injection. Attackers use techniques like CRLF injection and null byte injection
 * to confuse the parsing of requests and responses.
 * <p/>
 * <b>Example Configuration #1 (Default Configuration allows /WEB-INF):</b>
 * <pre>
 * &lt;filter&gt;
 *    &lt;filter-name&gt;SecurityWrapperDefault&lt;/filter-name&gt;
 *    &lt;filter-class&gt;org.owasp.filters.SecurityWrapper&lt;/filter-class&gt;
 * &lt;/filter&gt;
 * </pre>
 * <p/>
 * <b>Example Configuration #2 (Allows /servlet)</b>
 * <pre>
 * &lt;filter&gt;
 *    &lt;filter-name&gt;SecurityWrapperForServlet&lt;/filter-name&gt;
 *    &lt;filter-class&gt;org.owasp.filters.SecurityWrapper&lt;/filter-class&gt;
 *    &lt;init-param&gt;
 *       &lt;param-name&gt;allowableResourceRoot&lt;/param-name&gt;
 *       &lt;param-value&gt;/servlet&lt;/param-value&gt;
 *    &lt;/init-param&gt;
 * &lt;/filter&gt;
 * </pre>
 *
 * @author  Chris Schmidt (chrisisbeef@gmail.com)
 */
public class SecurityWrapper implements Filter {

    private final Logger logger = ESAPI.getLogger("SecurityWrapper");

    /**
     * This is the root path of what resources this filter will allow a RequestDispatcher to be dispatched to. This
     * defaults to WEB-INF as best practice dictates that dispatched requests should be done to resources that are
     * not browsable and everything behind WEB-INF is protected by the container. However, it is possible and sometimes
     * required to dispatch requests to places outside of the WEB-INF path (such as to another servlet).
     *
     * See <a href="http://code.google.com/p/owasp-esapi-java/issues/detail?id=70">http://code.google.com/p/owasp-esapi-java/issues/detail?id=70</a>
     * and <a href="https://lists.owasp.org/pipermail/owasp-esapi/2009-December/001672.html">https://lists.owasp.org/pipermail/owasp-esapi/2009-December/001672.html</a>
     * for details.
     */
    private String allowableResourcesRoot = "WEB-INF";

    /**
     *
     * @param request
     * @param response
     * @param chain
     * @throws java.io.IOException
     * @throws javax.servlet.ServletException
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest)) {
            chain.doFilter(request, response);
            return;
        }

        try {
            HttpServletRequest hrequest = (HttpServletRequest)request;
            HttpServletResponse hresponse = (HttpServletResponse)response;

            SecurityWrapperRequest secureRequest = new SecurityWrapperRequest(hrequest);
            SecurityWrapperResponse secureResponse = new SecurityWrapperResponse(hresponse);

            // Set the configuration on the wrapped request
            secureRequest.setAllowableContentRoot(allowableResourcesRoot);

            ESAPI.httpUtilities().setCurrentHTTP(secureRequest, secureResponse);

            chain.doFilter(ESAPI.currentRequest(), ESAPI.currentResponse());
        } catch (Exception e) {
            logger.error( Logger.SECURITY_FAILURE, "Error in SecurityWrapper: " + e.getMessage(), e );
            request.setAttribute("message", e.getMessage() );
        } finally {
            // VERY IMPORTANT
            // clear out the ThreadLocal variables in the authenticator
            // some containers could possibly reuse this thread without clearing the User
            // Issue 70 - http://code.google.com/p/owasp-esapi-java/issues/detail?id=70
            ESAPI.httpUtilities().clearCurrent();
        }
    }

    /**
     *
     */
    public void destroy() {
		// no special action
	}

    /**
     *
     * @param filterConfig
     * @throws javax.servlet.ServletException
     */
    public void init(FilterConfig filterConfig) throws ServletException {
		this.allowableResourcesRoot = StringUtilities.replaceNull( filterConfig.getInitParameter( "allowableResourcesRoot" ), allowableResourcesRoot );
	}
	
}
