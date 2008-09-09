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
import java.util.Date;
import java.util.Stack;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Servlet filter class.
 */
public class RequestRateThrottleFilter implements Filter
{

    private int hits = 5;

    private int period = 10;

    private static final String HITS = "hits";

    private static final String PERIOD = "period";

    /**
     * Called by the web container to indicate to a filter that it is being
     * placed into service. The servlet container calls the init method exactly
     * once after instantiating the filter. The init method must complete
     * successfully before the filter is asked to do any filtering work.
     * 
     * @param filterConfig
     *            configuration object
     */
    public void init(FilterConfig filterConfig)
    {
        hits = Integer.parseInt(filterConfig.getInitParameter(HITS));
        period = Integer.parseInt(filterConfig.getInitParameter(PERIOD));
    }

    /**
     * Checks to see if the current session has exceeded the allowed number
     * of requests in the specified time period. If the threshold has been
     * exceeded, then a short error message is written to the output stream and
     * no further processing is done on the request. Otherwise the request is
     * processed as normal.
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException
    {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpSession session = httpRequest.getSession(true);
        
        synchronized( session ) {
	        Stack times = (Stack) session.getAttribute("times");
	        if (times == null)
	        {
	            times = new Stack();
	            times.push(new Date(0));
	            session.setAttribute("times", times);
	        }
	        times.push(new Date());
	        if (times.size() >= hits)
	        {
	            times.removeElementAt(0);
	        }
	        Date newest = (Date) times.get(times.size() - 1);
	        Date oldest = (Date) times.get(0);
	        long elapsed = newest.getTime() - oldest.getTime();        
	        if (elapsed < period * 1000) // seconds
	        {
	            response.getWriter().println("Request rate too high");
	            return;
	        }
        }        
        chain.doFilter(request, response);
    }

    /**
     * Called by the web container to indicate to a filter that it is being
     * taken out of service. This method is only called once all threads within
     * the filter's doFilter method have exited or after a timeout period has
     * passed. After the web container calls this method, it will not call the
     * doFilter method again on this instance of the filter.
     */
    public void destroy()
    {
        // finalize
    }

}