package org.owasp.esapi.waf.rules;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.configuration.AppGuardianConfiguration;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

public class ReplaceContentRule extends Rule {

	private Pattern pattern;
	private String replacement;

	public ReplaceContentRule(String id, Pattern pattern, String replacement) {
		this.pattern = pattern;
		this.replacement = replacement;
		setId(id);
	}

	/*
	 * Use regular expressions with capturing parentheses to perform replacement.
	 */

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response) {

		byte[] bytes = response.getInterceptingServletOutputStream().getResponseBytes();

		/*
		 * First thing to decide is if the content type is one we'd like to search for output patterns.
		 */

		try {

			String s = new String(bytes,response.getCharacterEncoding());

			Matcher m = pattern.matcher(s);
			m.replaceAll(replacement);

			try {
				response.getInterceptingServletOutputStream().setResponseBytes(s.getBytes(response.getCharacterEncoding()));

				logger.log(AppGuardianConfiguration.LOG_LEVEL, "Successfully replaced pattern '" + pattern.pattern() + "' on response to URL '" + request.getRequestURL() + "'");

			} catch (IOException ioe) {
				logger.log(AppGuardianConfiguration.LOG_LEVEL, "Failed to replace pattern '" + pattern.pattern() + "' on response to URL '" + request.getRequestURL() + "' due to [" + ioe.getMessage() + "]");
			}

		} catch(UnsupportedEncodingException uee) {
			logger.log(AppGuardianConfiguration.LOG_LEVEL, "Failed to replace pattern '" + pattern.pattern() + "' on response to URL '" + request.getRequestURL() + "' due to [" + uee.getMessage() + "]");
		}

		return new DoNothingAction();
	}

}
