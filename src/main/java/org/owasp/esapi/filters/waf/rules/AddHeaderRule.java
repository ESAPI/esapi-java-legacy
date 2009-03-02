package org.owasp.esapi.filters.waf.rules;

import java.util.List;
import java.util.regex.Pattern;

import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class AddHeaderRule extends Rule {

	private String header;
	private String value;
	private Pattern path;
	private List<Object> exceptions;

	public AddHeaderRule(String header, String value, Pattern path, List<Object> exceptions) {
		this.header = header;
		this.value = value;
		this.path = path;
		this.exceptions = exceptions;
	}

	public boolean check(InterceptingHTTPServletRequest request, InterceptingHTTPServletResponse response) {

		if ( path.matcher(request.getRequestURI()).matches() ) {

			for(int i=0;i<exceptions.size();i++) {

				Object o = exceptions.get(i);

				if ( o instanceof String ) {
					if ( request.getRequestURI().equals((String)o)) {
						return true;
					}
				} else if ( o instanceof Pattern ) {
					if ( ((Pattern)o).matcher(request.getRequestURI()).matches() ) {
						return true;
					}
				}

			}

			response.setHeader(header, value);

		}

		return true;
	}

}
