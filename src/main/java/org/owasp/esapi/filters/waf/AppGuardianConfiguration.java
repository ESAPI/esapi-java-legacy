package org.owasp.esapi.filters.waf;

import java.util.ArrayList;
import java.util.List;

import org.owasp.esapi.filters.waf.rules.Rule;

public class AppGuardianConfiguration {

	/*
	 * Each stage has an associated set of rules.
	 */

	public static final int DONT_BLOCK = 0;
	public static final int BLOCK = 1;

	private int defaultFailAction = DONT_BLOCK;

	public static int MAX_FILE_SIZE = Integer.MAX_VALUE;

	private List<Rule> beforeBodyRules;
	private List<Rule> afterBodyRules;
	private List<Rule> beforeResponseRules;

	private List<String> allowedMethods;

	public AppGuardianConfiguration() {
		beforeBodyRules = new ArrayList<Rule>();
		afterBodyRules = new ArrayList<Rule>();
		beforeResponseRules = new ArrayList<Rule>();
	}

	public void setDefaultFailRule(int defaultFailAction) {
		this.defaultFailAction = defaultFailAction;
	}

	public int getDefaultFailRule() {
		return defaultFailAction;
	}

	public List<Rule> getBeforeBodyRules() {
		return beforeBodyRules;
	}

	public List<Rule> getAfterBodyRules() {
		return beforeBodyRules;
	}

	public List<Rule> getBeforeResponseRules() {
		return beforeBodyRules;
	}


	public void setAllowedHTTPMethods(List<String> allowedMethods) {
		this.allowedMethods = allowedMethods;
	}

	public void addRule(Rule r) {

		switch(r.getState()) {

			case HTTPState.ID_STATE_BEFORE_BODY:
				beforeBodyRules.add(r);
				break;

			case HTTPState.ID_STATE_AFTER_BODY:
				afterBodyRules.add(r);
				break;

			case HTTPState.ID_STATE_BEFORE_RESPONSE:
				beforeResponseRules.add(r);
				break;

			default:
		}

	}

}
