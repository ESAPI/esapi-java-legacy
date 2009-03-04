package org.owasp.esapi.filters.waf.actions;

public class BlockAction extends Action {

	public boolean failedRule() {

		return true;
	}


	public boolean isActionNecessary() {

		return true;
	}

}
