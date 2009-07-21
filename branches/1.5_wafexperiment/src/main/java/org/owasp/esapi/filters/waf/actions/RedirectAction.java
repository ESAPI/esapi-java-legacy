package org.owasp.esapi.waf.actions;

public class RedirectAction extends Action {

	private String url = null;

	/*
	 * Setting this overrides the default value read in the config file.
	 */
	public void setRedirectURL(String s) {
		this.url = s;
	}

	public String getRedirectURL() {
		return this.url;
	}

	public boolean failedRule() {

		return false;
	}

	public boolean isActionNecessary() {

		return false;
	}


}
