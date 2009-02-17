package org.owasp.esapi.filters.waf.rules;

import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.filters.waf.AppGuardianConfiguration;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class DetectOutboundContentRule extends Rule {

	private Pattern contentTypesPattern;
	private List<Pattern> patterns;

	public DetectOutboundContentRule(Pattern contentTypesPattern, List<Pattern> patterns) {
		this.contentTypesPattern = contentTypesPattern;
		this.patterns = patterns;
	}

	public boolean check(InterceptingHTTPServletRequest request,
			InterceptingHTTPServletResponse response) {

		byte[] bytes = response.getInterceptingServletOutputStream().getResponseBytes();

		/*
		 * First thing to decide is if the content type is one we'd like to search for output patterns.
		 */

		if ( response.getContentType() == null ) {
			response.setContentType(AppGuardianConfiguration.DEFAULT_CONTENT_TYPE);
		}

		System.out.println(response.getContentType());

		if ( contentTypesPattern.matcher(response.getContentType()).matches() ) {
			/*
			 * Depending on the encoding, search through the bytes
			 * for the patterns. If they all match, return a FAIL!
			 */
			try {

				String s = new String(bytes,response.getCharacterEncoding());

				for(int i=0;i<patterns.size();i++) {
					if ( patterns.get(i).matcher(s).matches() ) {
						return false;
					}
				}

			} catch (UnsupportedEncodingException uee) {
				uee.printStackTrace();
			}
		}

		return true;

	}

}
