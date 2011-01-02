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

import org.owasp.esapi.Logger;
import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.configuration.AppGuardianConfiguration;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

/**
 * This is the Rule subclass executed for &lt;dynamic-insertion&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
public class ReplaceContentRule extends Rule {

	private Pattern pattern;
	private String replacement;
	private Pattern contentType;
	private Pattern path;
	
	public ReplaceContentRule(String id, Pattern pattern, String replacement, Pattern contentType, Pattern path) {
		this.pattern = pattern;
		this.replacement = replacement;
		this.path = path;
		this.contentType = contentType;
		setId(id);
	}

	/*
	 * Use regular expressions with capturing parentheses to perform replacement.
	 */

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		/*
		 * First early fail: if the URI doesn't match the paths we're interested in.
		 */
		String uri = request.getRequestURI();
		if ( path != null && ! path.matcher(uri).matches() ) {
			return new DoNothingAction();
		}
		
		/*
		 * Second early fail: if the content type is one we'd like to search for output patterns.
		 */

		if ( contentType != null ) {
			if ( response.getContentType() != null && ! contentType.matcher(response.getContentType()).matches() ) {
				return new DoNothingAction();
			}
		}

		byte[] bytes = null;

		try {
			bytes = response.getInterceptingServletOutputStream().getResponseBytes();
		} catch (IOException ioe) {
			log(request,"Error matching pattern '" + pattern.pattern() + "', IOException encountered (possibly too large?): " + ioe.getMessage() + " (in response to URL: '" + request.getRequestURL() + "')");
			return new DoNothingAction(); // yes this is a fail open!
		}

		
		try {

			String s = new String(bytes,response.getCharacterEncoding());

			Matcher m = pattern.matcher(s);
			String canary = m.replaceAll(replacement);
			
			try {
				
				if ( ! s.equals(canary) ) {
					response.getInterceptingServletOutputStream().setResponseBytes(canary.getBytes(response.getCharacterEncoding()));
					logger.debug(Logger.SECURITY_SUCCESS, "Successfully replaced pattern '" + pattern.pattern() + "' on response to URL '" + request.getRequestURL() + "'");
				}
				
			} catch (IOException ioe) {
				logger.error(Logger.SECURITY_FAILURE, "Failed to replace pattern '" + pattern.pattern() + "' on response to URL '" + request.getRequestURL() + "' due to [" + ioe.getMessage() + "]");
			}

		} catch(UnsupportedEncodingException uee) {
			logger.error(Logger.SECURITY_FAILURE, "Failed to replace pattern '" + pattern.pattern() + "' on response to URL '" + request.getRequestURL() + "' due to [" + uee.getMessage() + "]");
		}

		return new DoNothingAction();
	}

}
