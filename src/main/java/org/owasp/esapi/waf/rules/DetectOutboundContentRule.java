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

import java.io.UnsupportedEncodingException;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.configuration.AppGuardianConfiguration;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

public class DetectOutboundContentRule extends Rule {

	private Pattern contentType;
	private Pattern pattern;

	public DetectOutboundContentRule(String id, Pattern contentType, Pattern pattern) {
		this.contentType = contentType;
		this.pattern = pattern;
		setId(id);
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response) {

		byte[] bytes = response.getInterceptingServletOutputStream().getResponseBytes();

		/*
		 * First thing to decide is if the content type is one we'd like to search for output patterns.
		 */

		if ( response.getContentType() == null ) {
			response.setContentType(AppGuardianConfiguration.DEFAULT_CONTENT_TYPE);
		}

		if ( contentType.matcher(response.getContentType()).matches() ) {
			/*
			 * Depending on the encoding, search through the bytes
			 * for the pattern.
			 */
			try {

				String s = new String(bytes,response.getCharacterEncoding());

				if ( pattern.matcher(s).matches() ) {

					log(request,"Content pattern '" + pattern.pattern() + "' was found in response to URL: '" + request.getRequestURL() + "'");
					return new DefaultAction();

				}

			} catch (UnsupportedEncodingException uee) {
				log(request,"Content pattern '" + pattern.pattern() + "' could not be found due to encoding error: " + uee.getMessage());
			}
		}

		return new DoNothingAction();

	}

}
