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

import org.owasp.esapi.ESAPI;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Date;
import java.util.Stack;

/**
 * A simple servlet filter that limits the request rate to a certain threshold of requests per second.
 * The default rate is 5 hits in 10 seconds. This can be overridden in the web.xml file by adding
 * parameters named "hits" and "period" with the desired values. When the rate is exceeded, a short
 * string is written to the response output stream and the chain method is not invoked. Otherwise,
 * processing proceeds as normal.
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
     * @param request 
     * @param response 
     * @param chain 
     * @throws IOException
     * @throws ServletException
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException
    {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpSession session = httpRequest.getSession(true);
        
        synchronized( session.getId().intern() ) {
	        Stack<Date> times = ESAPI.httpUtilities().getSessionAttribute("times");
	        if (times == null)
	        {
	            times = new Stack<Date>();
	            times.push(new Date(0));
	            session.setAttribute("times", times);
	        }
	        times.push(new Date());
	        if (times.size() >= hits)
	        {
	            times.removeElementAt(0);
	        }
	        Date newest = times.get(times.size() - 1);
	        Date oldest = times.get(0);
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