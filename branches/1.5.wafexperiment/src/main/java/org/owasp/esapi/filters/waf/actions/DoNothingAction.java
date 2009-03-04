package org.owasp.esapi.filters.waf.actions;

import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;
import org.owasp.esapi.filters.waf.rules.Rule;

public class DoNothingAction extends Action {


	public boolean failedRule() {

		return this.failed;
	}


	public boolean isActionNecessary() {

		return false;
	}


}
