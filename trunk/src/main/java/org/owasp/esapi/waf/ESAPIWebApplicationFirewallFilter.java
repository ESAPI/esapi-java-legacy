/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Arshan Dabirsiaghi <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2009
 */
package org.owasp.esapi.waf;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.fileupload.FileUploadException;
import org.apache.log4j.Logger;
import org.apache.log4j.xml.DOMConfigurator;
import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.BlockAction;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.RedirectAction;
import org.owasp.esapi.waf.configuration.AppGuardianConfiguration;
import org.owasp.esapi.waf.configuration.ConfigurationParser;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;
import org.owasp.esapi.waf.rules.Rule;

/**
 * This is the main class for the ESAPI Web Application Firewall (WAF). It is a standard J2EE servlet filter
 * that, in different methods, invokes the reading of the configuration file and handles the runtime processing
 * and enforcing of the developer-specified rules.
 * 
 * Ideally the filter should be configured to catch all requests (/*) in web.xml. If there are URL segments that
 * need to be extremely fast and don't require any protection, the pattern may be modified with extreme caution.
 *  
 * @author Arshan Dabirsiaghi
 *
 */
public class ESAPIWebApplicationFirewallFilter implements Filter {

	private AppGuardianConfiguration appGuardConfig;

	private static final String CONFIGURATION_FILE_PARAM = "configuration";
	private static final String LOGGING_FILE_PARAM = "log_settings";
	private static final String POLLING_TIME_PARAM = "polling_time";
	
	private static final int DEFAULT_POLLING_TIME = 30000;
	
	private String configurationFilename = null;

	private String logSettingsFilename = null;

	private long pollingTime;
	
	private long lastConfigReadTime;
	
	private static final String SESSION_COOKIE_NAME = "JSESSIONID";
	private static final String FAUX_SESSION_COOKIE = "JSESSIONID_2";
	private static final String SESSION_COOKIE_CANARY = "org.owasp.esapi.waf.canary";

	private FilterConfig fc;
	
	private static Logger logger = Logger.getLogger(ESAPIWebApplicationFirewallFilter.class);

	/**
	 * This function is used in testing to dynamically alter the configuration.
	 * @param is The InputStream from which to read the XML configuration file.
	 */
	public void setConfiguration( String policyFilePath ) throws FileNotFoundException {
		try {
			appGuardConfig = ConfigurationParser.readConfigurationFile(new FileInputStream(new File(policyFilePath)));
			lastConfigReadTime = System.currentTimeMillis();
			configurationFilename = policyFilePath;
		} catch (ConfigurationException e ) {
			e.printStackTrace();
		}
	}
	
	public AppGuardianConfiguration getConfiguration() {
		return appGuardConfig;
	}
	
	
	/**
	 * 
	 * This function is invoked at application startup and when the configuration file
	 * polling period has elapsed and a change in the configuration file has been detected.
	 * 
	 * It's main purpose is to read the configuration file and establish the configuration
	 * object model for use at runtime during the <code>doFilter()</code> method. 
	 */
	public void init(FilterConfig fc) throws ServletException {

		/*
		 * This variable is saved so that we can retrieve it later to re-invoke this function.
		 */
		this.fc = fc;
		
		logger.debug( ">> Initializing WAF" );
		/*
		 * Pull logging file.
		 */

		logSettingsFilename = fc.getInitParameter(LOGGING_FILE_PARAM);

		String realLogSettingsFilename = fc.getServletContext().getRealPath(logSettingsFilename);

		if ( ! new File(realLogSettingsFilename).exists() ) {
			throw new ServletException("[ESAPI WAF] Could not find log file at resolved path: " + realLogSettingsFilename);
		}
		
		/*
		 * Pull main configuration file.
		 */

		configurationFilename = fc.getInitParameter(CONFIGURATION_FILE_PARAM);

		String realConfigFilename = fc.getServletContext().getRealPath(configurationFilename);

		if ( ! new File(realConfigFilename).exists() ) {
			throw new ServletException("[ESAPI WAF] Could not find configuration file at resolved path: " + realConfigFilename);
		}

		/*
		 * Find out polling time from a parameter. If none is provided, use
		 * the default (10 seconds).
		 */
		
		String sPollingTime = fc.getInitParameter(POLLING_TIME_PARAM);
		
		if ( sPollingTime != null ) {
			pollingTime = Long.parseLong(sPollingTime);
		} else {
			pollingTime = DEFAULT_POLLING_TIME;
		}
		
		/*
		 * Open up configuration file and populate the AppGuardian configuration object.
		 */

		try {

			appGuardConfig = ConfigurationParser.readConfigurationFile(new FileInputStream(realConfigFilename));

			DOMConfigurator.configure(realLogSettingsFilename);

			lastConfigReadTime = System.currentTimeMillis();
			
		} catch (FileNotFoundException e) {
			throw new ServletException(e);
		} catch (ConfigurationException e) {
			throw new ServletException(e);
		}

	}

	
	
	/**
	 * 
	 * This method performs the runtime checking of rules on inbound requests and outbound responses. There is
	 * a considerable hack in this function to accomplish setting the HTTPOnly/secure flags on the container's
	 * session cookies, which involves a single extra request-response cycle strictly devoted to that goal. 
	 * 
	 * Because this extra cycle isn't ideal, you should consider enabling this protection in your container's 
	 * configuration instead. Like many other features of the WAF, this should only be done to implement 
	 * short-to-medium term fixes.   
	 */
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
			FilterChain chain) throws IOException, ServletException {

		/*
		 * Check to see if polling time has elapsed. If it has, that means
		 * we should check to see if the config file has been changed. If
		 * it has, then re-read it.
		 */
		
		if ( (System.currentTimeMillis() - lastConfigReadTime) > pollingTime ) {
			File f = new File(configurationFilename);
			if ( f.lastModified() > lastConfigReadTime ) {
				/*
				 * The file has been altered since it was
				 * read in the last time. Must re-read it.
				 */
				init(fc);
			}
		}
		
		logger.debug(">>In WAF doFilter");

		HttpServletRequest httpRequest = (HttpServletRequest)servletRequest;
		HttpServletResponse httpResponse = (HttpServletResponse)servletResponse;

		InterceptingHTTPServletRequest request = null;
		InterceptingHTTPServletResponse response = null;

		/*
		 * First thing to do is create the InterceptingHTTPServletResponse, since
		 * we'll need that possibly before the InterceptingHTTPServletRequest.
		 *
		 * The normal HttpRequest-type objects will suffice us until we get to
		 * stage 2.
		 *
		 * 1st argument = the response to base the instance on
		 * 2nd argument = should we bother intercepting the egress response?
		 * 3rd argument = cookie rules because thats where they mostly get acted on
		 */
		
		if ( 	appGuardConfig.getCookieRules().size() + 
				appGuardConfig.getBeforeResponseRules().size() > 0) {
			response = new InterceptingHTTPServletResponse(httpResponse, true, appGuardConfig.getCookieRules());
		}
		
		/*
		 * Stage 0: Apply any cookie rules for incoming requests that don't yet have sessions.
		 */

		logger.debug(">> Starting Stage 0" );

		if ( httpRequest.getSession(false) == null && ( appGuardConfig.isUsingHttpOnlyFlagOnSessionCookie() ||
				appGuardConfig.isUsingSecureFlagOnSessionCookie() ) ) {

			for(int i=0;httpRequest.getCookies() != null && i<httpRequest.getCookies().length;i++) {

				Cookie cookie = httpRequest.getCookies()[i];

				if ( cookie.getName().equals(FAUX_SESSION_COOKIE) ) {

					/*
					 * Kill the faux cookie.
					 */

					killCookie(	FAUX_SESSION_COOKIE, httpRequest, response );

					/*
					 * Issue the new cookie back to the user, but this time with
					 * the HttpOnly/Secure flags as needed.
					 */

					Cookie newCookie = new Cookie(SESSION_COOKIE_NAME, cookie.getValue());
					cookie.setPath(httpRequest.getContextPath());
					response.addCookie(newCookie, true);

					/*
					 * Now that the 2-stage cookie process is handled and the user's
					 * next request will have the properly protected cookie, force
					 * them to come back and issue the same request and they'll
					 * be allowed through.
					 */

					httpResponse.sendRedirect(httpRequest.getRequestURL().toString());

					return;

				}
			}

			/*
			 * They don't have the faux cookie. That means they need one.
			 */

			httpRequest.getSession(true);

			/*
			 * Put a canary value in their session
			 */

			httpRequest.getSession().setAttribute(SESSION_COOKIE_CANARY,0);

			killCookie(	SESSION_COOKIE_NAME, httpRequest, response );

			Cookie fauxCookie = new Cookie(FAUX_SESSION_COOKIE, httpRequest.getSession().getId());
			fauxCookie.setPath(httpRequest.getContextPath());
			fauxCookie.setMaxAge(httpRequest.getSession().getMaxInactiveInterval());
			response.addCookie(fauxCookie, true);

			response.sendRedirect(httpRequest.getRequestURL().toString());

			return;
		}

		/*
		 * Stage 1: Rules that do not need the request body.
		 */
		logger.debug(">> Starting stage 1" );

		List<Rule> rules = this.appGuardConfig.getBeforeBodyRules();

		for(int i=0;i<rules.size();i++) {

			Rule rule = rules.get(i);
			logger.debug( "  Applying BEFORE rule:  " + rule.getClass().getName() );
			
			/*
			 * The rules execute in check(). The check() method will also log. All we have
			 * to do is decide what other actions to take.
			 */
			Action action = rule.check(httpRequest, response, httpResponse);

			if ( action.isActionNecessary() ) {

				if ( action instanceof BlockAction ) {
					return;

				} else if ( action instanceof RedirectAction ) {
					sendRedirect(response, httpResponse, ((RedirectAction)action).getRedirectURL()); 
					return;

				} else if ( action instanceof DefaultAction ) {

					switch ( AppGuardianConfiguration.DEFAULT_FAIL_ACTION) {
						case AppGuardianConfiguration.BLOCK:
							return;

						case AppGuardianConfiguration.REDIRECT:
							sendRedirect(response, httpResponse);
							return;
					}
				}
			}
		}

		/*
		 * Create the InterceptingHTTPServletRequest.
		 */
		
		try {
			request = new InterceptingHTTPServletRequest((HttpServletRequest)servletRequest);
		} catch (UploadTooLargeException utle) {
			utle.printStackTrace();
		} catch (FileUploadException fue) {
			fue.printStackTrace();
		}

		/*
		 * Stage 2: After the body has been read, but before the the application has gotten it.
		 */
		logger.debug(">> Starting Stage 2" );

		rules = this.appGuardConfig.getAfterBodyRules();

		for(int i=0;i<rules.size();i++) {

			Rule rule = rules.get(i);
			logger.debug( "  Applying BEFORE CHAIN rule:  " + rule.getClass().getName() );

			/*
			 * The rules execute in check(). The check() method will take care of logging. 
			 * All we have to do is decide what other actions to take.
			 */
			Action action = rule.check(request, response, httpResponse);

			if ( action.isActionNecessary() ) {

				if ( action instanceof BlockAction ) {
					return;

				} else if ( action instanceof RedirectAction ) {
					sendRedirect(response, httpResponse, ((RedirectAction)action).getRedirectURL());
					return;

				} else if ( action instanceof DefaultAction ) {

					switch ( AppGuardianConfiguration.DEFAULT_FAIL_ACTION) {
						case AppGuardianConfiguration.BLOCK:
							return;

						case AppGuardianConfiguration.REDIRECT:
							sendRedirect(response, httpResponse);
							return;
					}
				}
			}
		}

		/*
		 * In between stages 2 and 3 is the application's processing of the input.
		 */
		logger.debug(">> Calling the FilterChain: " + chain );
		chain.doFilter(request, response != null ? response : httpResponse);

		/*
		 * Stage 3: Before the response has been sent back to the user.
		 */
		logger.debug(">> Starting Stage 3" );

		rules = this.appGuardConfig.getBeforeResponseRules();

		for(int i=0;i<rules.size();i++) {

			Rule rule = rules.get(i);
			logger.debug( "  Applying AFTER CHAIN rule:  " + rule.getClass().getName() );

			/*
			 * The rules execute in check(). The check() method will also log. All we have
			 * to do is decide what other actions to take.
			 */
			Action action = rule.check(request, response, httpResponse);

			if ( action.isActionNecessary() ) {

				if ( action instanceof BlockAction ) {
					return;

				} else if ( action instanceof RedirectAction ) {
					sendRedirect(response, httpResponse, ((RedirectAction)action).getRedirectURL());
					return;

				} else if ( action instanceof DefaultAction ) {

					switch ( AppGuardianConfiguration.DEFAULT_FAIL_ACTION) {
						case AppGuardianConfiguration.BLOCK:
							return;

						case AppGuardianConfiguration.REDIRECT:
							sendRedirect(response, httpResponse);
							return;
					}
				}
			}
		}

		/*
		 * Now that we've run our last set of rules we can allow the response to go through if
		 * we were intercepting.
		 */
		
		if ( response != null ) {
			logger.debug(">>> committing reponse" );
			response.commit();
		}
	}

	/*
	 * Utility method to send HTTP redirects that automatically determines which response class to use.
	 */
	private void sendRedirect(InterceptingHTTPServletResponse response,
			HttpServletResponse httpResponse, String redirectURL) throws IOException {
		
		if ( response != null ) { // if we've been buffering everything we clean it all out before sending back.
			response.reset();
			response.resetBuffer();
			response.sendRedirect(redirectURL);
			response.commit();
		} else {
			httpResponse.sendRedirect(redirectURL);
		}
		
	}

	/**
	 * Remove a browser cookie in an app-server-neutral way.
	 * @param sessionCookieName The name of the cookie to kill on the client side.
	 * @param request The request to get the context path from.
	 * @param response The response to clear the cookie on.
	 */
	private void killCookie(String cookieName,
			HttpServletRequest request,
			InterceptingHTTPServletResponse response) {

		Cookie cookie = new Cookie(cookieName, null);
        cookie.setPath( request.getContextPath() );
        cookie.setMaxAge(-1);
        response.addCookie(cookie, false);
	}

	public void destroy() {
		/*
		 * Any cleanup necessary?
		 */
	}

	
	private void sendRedirect(InterceptingHTTPServletResponse response, HttpServletResponse httpResponse) throws IOException {
		String finalJavaScript = AppGuardianConfiguration.JAVASCRIPT_REDIRECT;
		finalJavaScript = finalJavaScript.replaceAll(AppGuardianConfiguration.JAVASCRIPT_TARGET_TOKEN, appGuardConfig.getDefaultErrorPage());

		if ( response != null ) {
			response.reset();
			response.resetBuffer();
			/*
			response.setStatus(appGuardConfig.getDefaultResponseCode());
			response.getOutputStream().write(finalJavaScript.getBytes());
			*/
			response.sendRedirect(appGuardConfig.getDefaultErrorPage());
			
		} else {
			if ( ! httpResponse.isCommitted() ) {
				httpResponse.sendRedirect(appGuardConfig.getDefaultErrorPage());
			} else {
				/*
				 * Can't send redirect because response is already committed. I'm not sure 
				 * how this could happen, but I didn't want to cause IOExceptions in case
				 * if it ever does. 
				 */
			}
			
		}
	}
	
}
