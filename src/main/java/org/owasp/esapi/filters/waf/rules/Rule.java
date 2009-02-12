package org.owasp.esapi.filters.waf.rules;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public abstract class Rule {

	public abstract boolean check(
			HttpServletRequest request,
			HttpServletResponse response);

	private int guid;
	private int state;

	public int getGuid() {
		return guid;
	}

	public void setGuid(int guid) {
		this.guid = guid;
	}

	public int getState() {
		return state;
	}

	public void setState(int state) {
		this.state = state;
	}

}
