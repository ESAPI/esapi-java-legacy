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
package org.owasp.esapi.waf.rules;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		byte[] bytes = response.getInterceptingServletOutputStream().getResponseBytes();

		/*
		 * First thing to decide is if the content type is one we'd like to search for output patterns.
		 */
		
		try {

			String s = new String(bytes,response.getCharacterEncoding());

			Matcher m = pattern.matcher(s);
			String canary = m.replaceAll(replacement);
			
			try {
				
				if ( ! s.equals(canary) ) {
					response.getInterceptingServletOutputStream().setResponseBytes(canary.getBytes(response.getCharacterEncoding()));
					logger.log(AppGuardianConfiguration.LOG_LEVEL, "Successfully replaced pattern '" + pattern.pattern() + "' on response to URL '" + request.getRequestURL() + "'");
				}
				
			} catch (IOException ioe) {
				logger.log(AppGuardianConfiguration.LOG_LEVEL, "Failed to replace pattern '" + pattern.pattern() + "' on response to URL '" + request.getRequestURL() + "' due to [" + ioe.getMessage() + "]");
			}

		} catch(UnsupportedEncodingException uee) {
			logger.log(AppGuardianConfiguration.LOG_LEVEL, "Failed to replace pattern '" + pattern.pattern() + "' on response to URL '" + request.getRequestURL() + "' due to [" + uee.getMessage() + "]");
		}

		return new DoNothingAction();
	}

}
