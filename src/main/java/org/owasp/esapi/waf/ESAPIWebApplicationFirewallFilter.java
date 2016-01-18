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
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.fileupload.FileUploadException;
import org.apache.log4j.xml.DOMConfigurator;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
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
 * This is the main class for the ESAPI Web Application Firewall (WAF). It is a
 * standard J2EE servlet filter that, in different methods, invokes the reading
 * of the configuration file and handles the runtime processing and enforcing of
 * the developer-specified rules.
 * 
 * Ideally the filter should be configured to catch all requests (/*) in
 * web.xml. If there are URL segments that need to be extremely fast and don't
 * require any protection, the pattern may be modified with extreme caution.
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

	private long pollingTime;

	private long lastConfigReadTime;

	// private static final String FAUX_SESSION_COOKIE = "FAUXSC";
	// private static final String SESSION_COOKIE_CANARY =
	// "org.owasp.esapi.waf.canary";

	private FilterConfig fc;

	private final Logger logger = ESAPI.getLogger(ESAPIWebApplicationFirewallFilter.class);

	/**
	 * This function is used in testing to dynamically alter the configuration.
	 * 
	 * @param policyFilePath
	 *            The path to the policy file
	 * @param webRootDir
	 *            The root directory of the web application.
	 * @throws FileNotFoundException
	 *             if the policy file cannot be located
	 */
	public void setConfiguration(String policyFilePath, String webRootDir) throws FileNotFoundException {

		FileInputStream inputStream = null;

		try {
			inputStream = new FileInputStream(new File(policyFilePath));
			appGuardConfig = ConfigurationParser.readConfigurationFile(inputStream, webRootDir);
			lastConfigReadTime = System.currentTimeMillis();
			configurationFilename = policyFilePath;
		} catch (ConfigurationException e) {
			// TODO: It would be ideal if this method through the
			// ConfigurationException rather than catching it and
			// writing the error to the console.
			e.printStackTrace();
		} finally {
			if (inputStream != null) {
				try {
					inputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	public AppGuardianConfiguration getConfiguration() {
		return appGuardConfig;
	}

	/**
	 * 
	 * This function is invoked at application startup and when the
	 * configuration file polling period has elapsed and a change in the
	 * configuration file has been detected.
	 * 
	 * It's main purpose is to read the configuration file and establish the
	 * configuration object model for use at runtime during the
	 * <code>doFilter()</code> method.
	 */
	public void init(FilterConfig fc) throws ServletException {

		/*
		 * This variable is saved so that we can retrieve it later to re-invoke
		 * this function.
		 */
		this.fc = fc;

		logger.debug(Logger.EVENT_SUCCESS, ">> Initializing WAF");
		/*
		 * Pull logging file.
		 */

		// Demoted scope to a local since this is the only place it is
		// referenced
		String logSettingsFilename = fc.getInitParameter(LOGGING_FILE_PARAM);

		String realLogSettingsFilename = fc.getServletContext().getRealPath(logSettingsFilename);

		if (realLogSettingsFilename == null || (!new File(realLogSettingsFilename).exists())) {
			throw new ServletException(
					"[ESAPI WAF] Could not find log file at resolved path: " + realLogSettingsFilename);
		}

		/*
		 * Pull main configuration file.
		 */

		configurationFilename = fc.getInitParameter(CONFIGURATION_FILE_PARAM);

		configurationFilename = fc.getServletContext().getRealPath(configurationFilename);

		if (configurationFilename == null || !new File(configurationFilename).exists()) {
			throw new ServletException(
					"[ESAPI WAF] Could not find configuration file at resolved path: " + configurationFilename);
		}

		/*
		 * Find out polling time from a parameter. If none is provided, use the
		 * default (10 seconds).
		 */

		String sPollingTime = fc.getInitParameter(POLLING_TIME_PARAM);

		if (sPollingTime != null) {
			pollingTime = Long.parseLong(sPollingTime);
		} else {
			pollingTime = DEFAULT_POLLING_TIME;
		}

		/*
		 * Open up configuration file and populate the AppGuardian configuration
		 * object.
		 */

		FileInputStream inputStream = null;

		try {
			String webRootDir = fc.getServletContext().getRealPath("/");
			inputStream = new FileInputStream(configurationFilename);
			appGuardConfig = ConfigurationParser.readConfigurationFile(inputStream, webRootDir);
			DOMConfigurator.configure(realLogSettingsFilename);
			lastConfigReadTime = System.currentTimeMillis();
		} catch (FileNotFoundException e) {
			throw new ServletException(e);
		} catch (ConfigurationException e) {
			throw new ServletException(e);
		} finally {
			if (inputStream != null) {
				try {
					inputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	/**
	 * This is the where the main interception and rule-checking logic of the
	 * WAF resides.
	 */
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
			throws IOException, ServletException {

		/*
		 * Check to see if polling time has elapsed. If it has, that means we
		 * should check to see if the config file has been changed. If it has,
		 * then re-read it.
		 *
		 * // TODO: Any reason this logic shouldn't be moved into a polling
		 * thread class?
		 */

		if ((System.currentTimeMillis() - lastConfigReadTime) > pollingTime) {
			File f = new File(configurationFilename);
			long lastModified = f.lastModified();
			if (lastModified > lastConfigReadTime) {
				/*
				 * The file has been altered since it was read in the last time.
				 * Must re-read it.
				 */
				logger.debug(Logger.EVENT_SUCCESS, ">> Re-reading WAF policy");
				init(fc);
			}
		}

		logger.debug(Logger.EVENT_SUCCESS, ">>In WAF doFilter");

		HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
		HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;

		InterceptingHTTPServletRequest request = null;
		InterceptingHTTPServletResponse response = null;

		/*
		 * First thing to do is create the InterceptingHTTPServletResponse,
		 * since we'll need that possibly before the
		 * InterceptingHTTPServletRequest.
		 *
		 * The normal HttpRequest-type objects will suffice us until we get to
		 * stage 2.
		 *
		 * 1st argument = the response to base the instance on 2nd argument =
		 * should we bother intercepting the egress response? 3rd argument =
		 * cookie rules because thats where they mostly get acted on
		 */

		if (appGuardConfig.getCookieRules().size() + appGuardConfig.getBeforeResponseRules().size() > 0) {
			response = new InterceptingHTTPServletResponse(httpResponse, true, appGuardConfig.getCookieRules());
		}

		/*
		 * Stage 1: Rules that do not need the request body.
		 */
		logger.debug(Logger.EVENT_SUCCESS, ">> Starting stage 1");

		List<Rule> rules = this.appGuardConfig.getBeforeBodyRules();

		for (int i = 0; i < rules.size(); i++) {

			Rule rule = rules.get(i);
			logger.debug(Logger.EVENT_SUCCESS, "  Applying BEFORE rule:  " + rule.getClass().getName());

			/*
			 * The rules execute in check(). The check() method will also log.
			 * All we have to do is decide what other actions to take.
			 */
			Action action = rule.check(httpRequest, response, httpResponse);

			if (action.isActionNecessary()) {

				if (action instanceof BlockAction) {
					if (response != null) {
						response.setStatus(appGuardConfig.getDefaultResponseCode());
					} else {
						httpResponse.setStatus(appGuardConfig.getDefaultResponseCode());
					}
					return;

				} else if (action instanceof RedirectAction) {
					sendRedirect(response, httpResponse, ((RedirectAction) action).getRedirectURL());
					return;

				} else if (action instanceof DefaultAction) {

					switch (AppGuardianConfiguration.DEFAULT_FAIL_ACTION) {
					case AppGuardianConfiguration.BLOCK:
						if (response != null) {
							response.setStatus(appGuardConfig.getDefaultResponseCode());
						} else {
							httpResponse.setStatus(appGuardConfig.getDefaultResponseCode());
						}
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
			request = new InterceptingHTTPServletRequest((HttpServletRequest) servletRequest);
		} catch (FileUploadException fue) {
			logger.error(Logger.EVENT_SUCCESS, "Error Wrapping Request", fue);
		}

		/*
		 * Stage 2: After the body has been read, but before the the application
		 * has gotten it.
		 */
		logger.debug(Logger.EVENT_SUCCESS, ">> Starting Stage 2");

		rules = this.appGuardConfig.getAfterBodyRules();

		for (int i = 0; i < rules.size(); i++) {

			Rule rule = rules.get(i);
			logger.debug(Logger.EVENT_SUCCESS, "  Applying BEFORE CHAIN rule:  " + rule.getClass().getName());

			/*
			 * The rules execute in check(). The check() method will take care
			 * of logging. All we have to do is decide what other actions to
			 * take.
			 */
			Action action = rule.check(request, response, httpResponse);

			if (action.isActionNecessary()) {

				if (action instanceof BlockAction) {
					if (response != null) {
						response.setStatus(appGuardConfig.getDefaultResponseCode());
					} else {
						httpResponse.setStatus(appGuardConfig.getDefaultResponseCode());
					}
					return;

				} else if (action instanceof RedirectAction) {
					sendRedirect(response, httpResponse, ((RedirectAction) action).getRedirectURL());
					return;

				} else if (action instanceof DefaultAction) {

					switch (AppGuardianConfiguration.DEFAULT_FAIL_ACTION) {
					case AppGuardianConfiguration.BLOCK:
						if (response != null) {
							response.setStatus(appGuardConfig.getDefaultResponseCode());
						} else {
							httpResponse.setStatus(appGuardConfig.getDefaultResponseCode());
						}
						return;

					case AppGuardianConfiguration.REDIRECT:
						sendRedirect(response, httpResponse);
						return;
					}
				}
			}
		}

		/*
		 * In between stages 2 and 3 is the application's processing of the
		 * input.
		 */
		logger.debug(Logger.EVENT_SUCCESS, ">> Calling the FilterChain: " + chain);
		chain.doFilter(request, response != null ? response : httpResponse);

		/*
		 * Stage 3: Before the response has been sent back to the user.
		 */
		logger.debug(Logger.EVENT_SUCCESS, ">> Starting Stage 3");

		rules = this.appGuardConfig.getBeforeResponseRules();

		for (int i = 0; i < rules.size(); i++) {

			Rule rule = rules.get(i);
			logger.debug(Logger.EVENT_SUCCESS, "  Applying AFTER CHAIN rule:  " + rule.getClass().getName());

			/*
			 * The rules execute in check(). The check() method will also log.
			 * All we have to do is decide what other actions to take.
			 */
			Action action = rule.check(request, response, httpResponse);

			if (action.isActionNecessary()) {

				if (action instanceof BlockAction) {
					if (response != null) {
						response.setStatus(appGuardConfig.getDefaultResponseCode());
					} else {
						httpResponse.setStatus(appGuardConfig.getDefaultResponseCode());
					}
					return;

				} else if (action instanceof RedirectAction) {
					sendRedirect(response, httpResponse, ((RedirectAction) action).getRedirectURL());
					return;

				} else if (action instanceof DefaultAction) {

					switch (AppGuardianConfiguration.DEFAULT_FAIL_ACTION) {
					case AppGuardianConfiguration.BLOCK:
						if (response != null) {
							response.setStatus(appGuardConfig.getDefaultResponseCode());
						} else {
							httpResponse.setStatus(appGuardConfig.getDefaultResponseCode());
						}
						return;

					case AppGuardianConfiguration.REDIRECT:
						sendRedirect(response, httpResponse);
						return;
					}
				}
			}
		}

		/*
		 * Now that we've run our last set of rules we can allow the response to
		 * go through if we were intercepting.
		 */

		if (response != null) {
			logger.debug(Logger.EVENT_SUCCESS, ">>> committing reponse");
			response.commit();
		}
	}

	/*
	 * Utility method to send HTTP redirects that automatically determines which
	 * response class to use.
	 */
	private void sendRedirect(InterceptingHTTPServletResponse response, HttpServletResponse httpResponse,
			String redirectURL) throws IOException {

		if (response != null) { // if we've been buffering everything we clean
								// it all out before sending back.
			response.reset();
			response.resetBuffer();
			response.sendRedirect(redirectURL);
			response.commit();
		} else {
			httpResponse.sendRedirect(redirectURL);
		}

	}

	public void destroy() {
		/*
		 * Any cleanup necessary?
		 */
	}

	private void sendRedirect(InterceptingHTTPServletResponse response, HttpServletResponse httpResponse)
			throws IOException {
		/*
		 * [chrisisbeef] - commented out as this is not currently used. Minor
		 * performance tweak. String finalJavaScript =
		 * AppGuardianConfiguration.JAVASCRIPT_REDIRECT; finalJavaScript =
		 * finalJavaScript.replaceAll(AppGuardianConfiguration.
		 * JAVASCRIPT_TARGET_TOKEN, appGuardConfig.getDefaultErrorPage());
		 */

		if (response != null) {
			response.reset();
			response.resetBuffer();
			/*
			 * response.setStatus(appGuardConfig.getDefaultResponseCode());
			 * response.getOutputStream().write(finalJavaScript.getBytes());
			 */
			response.sendRedirect(appGuardConfig.getDefaultErrorPage());

		} else {
			if (!httpResponse.isCommitted()) {
				httpResponse.sendRedirect(appGuardConfig.getDefaultErrorPage());
			} else {
				/*
				 * Can't send redirect because response is already committed.
				 * I'm not sure how this could happen, but I didn't want to
				 * cause IOExceptions in case if it ever does.
				 */
			}

		}
	}

}
