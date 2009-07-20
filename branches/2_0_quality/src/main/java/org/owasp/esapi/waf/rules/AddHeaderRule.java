package org.owasp.esapi.waf.rules;

import java.util.List;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

public class AddHeaderRule extends Rule {

	private String header;
	private String value;
	private Pattern path;
	private List<Object> exceptions;

	public AddHeaderRule(String id, String header, String value, Pattern path, List<Object> exceptions) {
		setId(id);
		this.header = header;
		this.value = value;
		this.path = path;
		this.exceptions = exceptions;
	}

	public Action check(HttpServletRequest request, InterceptingHTTPServletResponse response) {

		DoNothingAction action = new DoNothingAction();

		if ( path.matcher(request.getRequestURI()).matches() ) {

			for(int i=0;i<exceptions.size();i++) {

				Object o = exceptions.get(i);

				if ( o instanceof String ) {
					if ( request.getRequestURI().equals((String)o)) {
						action.setFailed(false);
						action.setActionNecessary(false);
						return action;
					}
				} else if ( o instanceof Pattern ) {
					if ( ((Pattern)o).matcher(request.getRequestURI()).matches() ) {
						action.setFailed(false);
						action.setActionNecessary(false);
						return action;					}
				}

			}


			action.setFailed(true);
			action.setActionNecessary(false);

			response.setHeader(header, value);

		}

		return action;
	}

}
