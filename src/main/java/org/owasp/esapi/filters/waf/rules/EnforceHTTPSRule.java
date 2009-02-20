package org.owasp.esapi.filters.waf.rules;

import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class EnforceHTTPSRule extends Rule {

	private Pattern path;
	private List<Object> exceptions;

	public EnforceHTTPSRule(Pattern path, List<Object> exceptions) {
		this.path = path;
		this.exceptions = exceptions;
	}

	public boolean check(InterceptingHTTPServletRequest request,
			InterceptingHTTPServletResponse response) {

		if ( path.matcher(request.getRequestURI()).matches() ) {

			Iterator it = exceptions.iterator();

			while(it.hasNext()){
				Object o = it.next();

				if ( o instanceof String ) {
					if ( ((String)o).equalsIgnoreCase(request.getRequestURI()) ) {
						return true;
					}
				} else if ( o instanceof Pattern ) {
					if ( ((Pattern)o).matcher(request.getRequestURI()).matches() ) {
						return true;
					}
				}
			}
		}

		return false;
	}

}
