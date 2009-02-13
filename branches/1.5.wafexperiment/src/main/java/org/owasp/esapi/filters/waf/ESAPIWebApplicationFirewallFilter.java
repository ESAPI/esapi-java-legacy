package org.owasp.esapi.filters.waf;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
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
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;
import org.owasp.esapi.filters.waf.rules.ConfigurationParser;
import org.owasp.esapi.filters.waf.rules.Rule;

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
		appGuardConfig = ConfigurationParser.readConfigurationFile(new File(realFilename));
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

		response = new InterceptingHTTPServletResponse((HttpServletResponse)servletResponse);

		List<Rule> rules = this.appGuardConfig.getBeforeBodyRules();

		for(int i=0;i<rules.size();i++) {
			Rule rule = rules.get(i);

			if ( ! rule.check(request, response) ) {
				// they failed this rule.
			}
		}

		/*
		 * Stage 2: After the body has been read, but before the the application has gotten it.
		 */

		rules = this.appGuardConfig.getAfterBodyRules();

		for(int i=0;i<rules.size();i++) {
			Rule rule = rules.get(i);

			if ( ! rule.check(request, response) ) {
				// they failed this rule.
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
				// they failed this rule.
			}
		}
	}



	public void destroy() {
		/*
		 * Any cleanup necessary?
		 */
	}


}
