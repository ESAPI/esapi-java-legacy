package org.owasp.esapi.waf.actions;

public class DefaultAction extends Action {

	public boolean failedRule() {
		return true;
	}

	public boolean isActionNecessary() {
		return true;
	}

}
