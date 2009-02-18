package org.owasp.esapi.filters.waf;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.fileupload.FileUploadException;
import org.owasp.esapi.filters.waf.configuration.AppGuardianConfiguration;
import org.owasp.esapi.filters.waf.configuration.ConfigurationParser;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;
import org.owasp.esapi.filters.waf.rules.DetectOutboundContentRule;
import org.owasp.esapi.filters.waf.rules.IPRule;
import org.owasp.esapi.filters.waf.rules.Rule;
import org.owasp.esapi.filters.waf.rules.SimpleVirtualPatchRule;

/**
 * Entry point for the ESAPI's web application firewall (codename AppGuard?).
 */
public class ESAPIWebApplicationFirewallFilter implements Filter {

	private AppGuardianConfiguration appGuardConfig;

	private static final String CONFIGURATION_FILE_PARAM = "configuration";

	private String configurationFilename = null;

	public void init(FilterConfig fc) throws ServletException {

		/*
		 * Pull main configuration file.
		 */
		configurationFilename = fc.getInitParameter(CONFIGURATION_FILE_PARAM);

		String realFilename = fc.getServletContext().getRealPath(configurationFilename);

		if ( ! new File(realFilename).exists() ) {
			throw new ServletException("[AppGuard] Could not find configuration file at resolved path: " + realFilename);
		}

		/*
		 * Open up configuration file and populate the AppGuardian configuration object.
		 */
		try {
			appGuardConfig = ConfigurationParser.readConfigurationFile(new File(realFilename));
		} catch (ConfigurationException e) {
			throw new ServletException(e);
		}


		Pattern path = Pattern.compile(".*");
		Pattern param = Pattern.compile("^b0mb$");
		Pattern signature = Pattern.compile("[0-9a-zA-Z]+");
		Pattern patternTextHTML = Pattern.compile("^text/html.*");
		Pattern patternBadness = Pattern.compile(".*404.*");
		List<Pattern> listBadness = new ArrayList<Pattern>();
		listBadness.add(patternBadness);

		appGuardConfig.addBeforeBodyRule(new SimpleVirtualPatchRule(path, param, null, signature));
		appGuardConfig.addBeforeResponseRule(new DetectOutboundContentRule(patternTextHTML, listBadness));

	}

	/*
	 * Entry point for every request - this piece must be extremely efficient.
	 */
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
			FilterChain chain) throws IOException, ServletException {

		/*
		 * Stage 1: Request has been received, but the body has not been read.
		 */
		InterceptingHTTPServletRequest request = null;
		InterceptingHTTPServletResponse response = null;

		try {
			request = new InterceptingHTTPServletRequest((HttpServletRequest)servletRequest);
		} catch (UploadTooLargeException utle) {
			utle.printStackTrace();
		} catch (FileUploadException fue) {
			fue.printStackTrace();
		}

		/*
		 * 2nd arg = should we bother intercepting the egress response?
		 * 3rd arg = if 2nd arg = true, should we buffer the response?
		 */
		response = new InterceptingHTTPServletResponse((HttpServletResponse)servletResponse, true, true);

		List<Rule> rules = this.appGuardConfig.getBeforeBodyRules();

		for(int i=0;i<rules.size();i++) {
			Rule rule = rules.get(i);

			if ( ! rule.check(request, response) ) {
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "You failed the rule in stage 1: " + rule.getClass());
				return;
			}
		}

		/*
		 * Stage 2: After the body has been read, but before the the application has gotten it.
		 */

		rules = this.appGuardConfig.getAfterBodyRules();

		for(int i=0;i<rules.size();i++) {
			Rule rule = rules.get(i);

			if ( ! rule.check(request, response) ) {
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "You failed the rule in stage 2: " + rule.getClass());
				return;
			}
		}

		/*
		 * In between stages 2 and 3 is the application's processing of the input.
		 */

		chain.doFilter(request, response);

		/*
		 * Stage 3: Before the response has been sent back to the user.
		 */
		rules = this.appGuardConfig.getBeforeResponseRules();

		for(int i=0;i<rules.size();i++) {
			Rule rule = rules.get(i);

			if ( ! rule.check(request, response) ) {
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "You failed the rule in stage 3: " + rule.getClass());
				return;
			}
		}
	}



	public void destroy() {
		/*
		 * Any cleanup necessary?
		 */
	}


}
