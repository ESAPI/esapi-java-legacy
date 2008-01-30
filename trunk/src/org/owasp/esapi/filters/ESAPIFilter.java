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
package org.owasp.esapi.filters;

import java.io.IOException;
import java.util.Arrays;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.AccessController;
import org.owasp.esapi.Authenticator;
import org.owasp.esapi.HTTPUtilities;
import org.owasp.esapi.Logger;
import org.owasp.esapi.Validator;
import org.owasp.esapi.errors.AuthenticationException;

public class ESAPIFilter implements Filter {

	private static final Logger logger = Logger.getLogger("ESAPIFilter", "ESAPIFilter");

	private static final String[] ignore = { "password" };

	/**
	 * Called by the web container to indicate to a filter that it is being
	 * placed into service. The servlet container calls the init method exactly
	 * once after instantiating the filter. The init method must complete
	 * successfully before the filter is asked to do any filtering work.
	 * 
	 * @param filterConfig
	 *            configuration object
	 */
	public void init(FilterConfig filterConfig) {
	}

	/**
	 * The doFilter method of the Filter is called by the container each time a
	 * request/response pair is passed through the chain due to a client request
	 * for a resource at the end of the chain. The FilterChain passed in to this
	 * method allows the Filter to pass on the request and response to the next
	 * entity in the chain.
	 * 
	 * @param request
	 *            Request object to be processed
	 * @param response
	 *            Response object
	 * @param chain
	 *            current FilterChain
	 * @exception IOException
	 *                if any occurs
	 * @throws ServletException
	 */
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		try {
			// figure out who the current user is
			try {
				Authenticator.getInstance().login(request, response);
			} catch( AuthenticationException e ) {
				Authenticator.getInstance().logout();
				// FIXME: use safeforward!
				// FIXME: make configurable with servletconfig
				RequestDispatcher dispatcher = request.getRequestDispatcher("WEB-INF/login.jsp");
				dispatcher.forward(request, response);
				return;
			}

			// log this request, obfuscating any parameter named password
			logger.logHTTPRequest(Logger.SECURITY, request, Arrays.asList(ignore));

			// check access to this URL
			AccessController.getInstance().isAuthorizedForURL(request.getRequestURI().toString());

			// verify if this request meets the baseline input requirements
			Validator.getInstance().isValidHTTPRequest(request);

			// check for CSRF attacks and set appropriate caching headers
			HTTPUtilities utils = HTTPUtilities.getInstance();
			// utils.checkCSRFToken();
			utils.setNoCacheHeaders();
            utils.safeSetContentType();

			// forward this request on to the web application
			chain.doFilter(request, response);
		} catch (Exception e) {
			logger.logSpecial( "Security error in ESAPI Filter", e );
			response.getWriter().println("<H1>Security Error</H1>");
			e.printStackTrace(response.getWriter());
		} finally {
			// clear out the ThreadLocal variables in the authenticator
			Authenticator.getInstance().clearCurrent();
		}
	}

	/**
	 * Called by the web container to indicate to a filter that it is being
	 * taken out of service. This method is only called once all threads within
	 * the filter's doFilter method have exited or after a timeout period has
	 * passed. After the web container calls this method, it will not call the
	 * doFilter method again on this instance of the filter.
	 */
	public void destroy() {
		// finalize
	}

}