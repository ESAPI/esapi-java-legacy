package org.owasp.esapi.waf;

import java.io.File;
import java.io.IOException;
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
 * Entry point for the ESAPI's web application firewall (codename AppGuard?).
 */
public class ESAPIWebApplicationFirewallFilter implements Filter {

	private AppGuardianConfiguration appGuardConfig;

	private static final String CONFIGURATION_FILE_PARAM = "configuration";
	private static final String LOGGING_FILE_PARAM = "log_settings";

	private String configurationFilename = null;

	private String logSettingsFilename = null;

	private static final String SESSION_COOKIE_NAME = "JSESSIONID";
	private static final String FAUX_SESSION_COOKIE = "self_monster";
	private static final String SESSION_COOKIE_CANARY = "sid_canary";

	private static Logger logger = Logger.getLogger(ESAPIWebApplicationFirewallFilter.class);

	public void init(FilterConfig fc) throws ServletException {

		logger.info( ">> Initializing WAF" );
		/*
		 * Pull logging file.
		 */

		logSettingsFilename = fc.getInitParameter(LOGGING_FILE_PARAM);

		String realLogSettingsFilename = fc.getServletContext().getRealPath(logSettingsFilename);

		if ( ! new File(realLogSettingsFilename).exists() ) {
			throw new ServletException("[AppGuard] Could not find log file at resolved path: " + realLogSettingsFilename);
		}

		/*
		 * Pull main configuration file.
		 */

		configurationFilename = fc.getInitParameter(CONFIGURATION_FILE_PARAM);

		String realConfigFilename = fc.getServletContext().getRealPath(configurationFilename);

		if ( ! new File(realConfigFilename).exists() ) {
			throw new ServletException("[AppGuard] Could not find configuration file at resolved path: " + realConfigFilename);
		}

		/*
		 * Open up configuration file and populate the AppGuardian configuration object.
		 */

		try {

			appGuardConfig = ConfigurationParser.readConfigurationFile(new File(realConfigFilename));

			DOMConfigurator.configure(realLogSettingsFilename);

		} catch (ConfigurationException e) {
			throw new ServletException(e);
		}

	}

	/*
	 * Entry point for every request - this piece must be extremely efficient.
	 */
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
			FilterChain chain) throws IOException, ServletException {

		logger.info(">>In WAF doFilter");

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
		 * 1st arg = the response to base this on
		 * 2nd arg = should we bother intercepting the egress response?
		 * 3rd arg = cookie rules cuz thats where they mostly get acted on
		 */

		response = new InterceptingHTTPServletResponse(httpResponse, true, appGuardConfig.getCookieRules());

		/*
		 * Stage 0: Apply any cookie rules for incoming requests that don't yet have
		 * sessions.
		 */

		logger.info(">> Starting Stage 0" );

		if ( httpRequest.getSession(false) == null && ( AppGuardianConfiguration.FORCE_SECURE_FLAG_TO_SESSION ||
				 AppGuardianConfiguration.FORCE_HTTP_ONLY_FLAG_TO_SESSION ) ) {

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
		logger.info(">> Starting stage 1" );

		List<Rule> rules = this.appGuardConfig.getBeforeBodyRules();

		for(int i=0;i<rules.size();i++) {

			Rule rule = rules.get(i);

			/*
			 * The rules execute in check(). The check() method will also log. All we have
			 * to do is decide what other actions to take.
			 */
			Action action = rule.check(httpRequest, response);

			if ( action.isActionNecessary() ) {

				if ( action instanceof BlockAction ) {
					return;

				} else if ( action instanceof RedirectAction ) {
					response.sendRedirect(((RedirectAction)action).getRedirectURL());
					return;

				} else if ( action instanceof DefaultAction ) {

					switch ( AppGuardianConfiguration.DEFAULT_FAIL_ACTION) {
						case AppGuardianConfiguration.BLOCK:
							return;

						case AppGuardianConfiguration.REDIRECT:
							response.sendRedirect(appGuardConfig.getDefaultErrorPage());
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
		logger.info(">> Starting Stage 2" );

		rules = this.appGuardConfig.getAfterBodyRules();

		for(int i=0;i<rules.size();i++) {

			Rule rule = rules.get(i);

			/*
			 * The rules execute in check(). The check() method will also log. All we have
			 * to do is decide what other actions to take.
			 */
			Action action = rule.check(request, response);

			if ( action.isActionNecessary() ) {

				if ( action instanceof BlockAction ) {
					return;

				} else if ( action instanceof RedirectAction ) {
					response.sendRedirect(((RedirectAction)action).getRedirectURL());
					return;

				} else if ( action instanceof DefaultAction ) {

					switch ( AppGuardianConfiguration.DEFAULT_FAIL_ACTION) {
						case AppGuardianConfiguration.BLOCK:
							return;

						case AppGuardianConfiguration.REDIRECT:
							response.sendRedirect(appGuardConfig.getDefaultErrorPage());
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
		 * In between stages 2 and 3 is the application's processing of the input.
		 */
		logger.info(">> Calling the FilterChain: " + chain );
		chain.doFilter(request, response);

		/*
		 * Stage 3: Before the response has been sent back to the user.
		 */
		logger.info(">> Starting Stage 3" );
		
		rules = this.appGuardConfig.getBeforeResponseRules();

		for(int i=0;i<rules.size();i++) {

			Rule rule = rules.get(i);

			/*
			 * The rules execute in check(). The check() method will also log. All we have
			 * to do is decide what other actions to take.
			 */
			Action action = rule.check(request, response);

			if ( action.isActionNecessary() ) {

				if ( action instanceof BlockAction ) {
					return;

				} else if ( action instanceof RedirectAction ) {
					response.sendRedirect(((RedirectAction)action).getRedirectURL());
					return;

				} else if ( action instanceof DefaultAction ) {

					switch ( AppGuardianConfiguration.DEFAULT_FAIL_ACTION) {
						case AppGuardianConfiguration.BLOCK:
							return;

						case AppGuardianConfiguration.REDIRECT:
							response.sendRedirect(appGuardConfig.getDefaultErrorPage());
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
		 * Now that we've run our last set of rules we can allow the response to go through if
		 * we were intercepting.
		 */
		if ( appGuardConfig.getBeforeResponseRules().size() + appGuardConfig.getCookieRules().size() > 0 ) {
			System.out.println( ">>> committing reponse" );
			response.commit();
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


}
