package org.owasp.esapi.waf.actions;

public abstract class Action {

	protected boolean failed = true;
	protected boolean actionNecessary = false;

	public void setFailed(boolean didFail) {
		failed = didFail;
	}

	public boolean failedRule() {
		return failed;
	}

	public boolean isActionNecessary() {
		return actionNecessary;
	}

	public void setActionNecessary(boolean b) {
		this.actionNecessary = b;

	}
}
