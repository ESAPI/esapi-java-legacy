package org.owasp.esapi.waf.actions;

public class BlockAction extends Action {

	public boolean failedRule() {
		return true;
	}


	public boolean isActionNecessary() {
		return true;
	}

}
