package org.owasp.esapi.filters.waf.configuration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.log4j.Level;
import org.owasp.esapi.filters.waf.rules.Rule;

public class AppGuardianConfiguration {

	/*
	 * Fail modes (BLOCK blocks and logs the request, DONT_BLOCK simply logs)
	 */
	public static final int DONT_BLOCK = 0;
	public static final int BLOCK = 1;

	/*
	 * The operators.
	 */
	public static final int OPERATOR_EQ = 0;
	public static final int OPERATOR_CONTAINS = 1;
	public static final int OPERATOR_IN_LIST = 2;
	public static final int OPERATOR_EXISTS = 3;


	/*
	 * Default settings.
	 */
	private int defaultFailAction = DONT_BLOCK;

	public static int MAX_FILE_SIZE = Integer.MAX_VALUE;

	public static String DEFAULT_CHARACTER_ENCODING = "ISO-8859-1";
	public static String DEFAULT_CONTENT_TYPE = "text/html; charset=" + DEFAULT_CHARACTER_ENCODING;

	/*
	 * The aliases declared in the beginning of the config file.
	 */
	private HashMap<String,Object> aliases;

	/*
	 * Fail response settings.
	 */
	private String defaultErrorPage;
	private int defaultResponseCode;

	/*
	 * Logging settings.
	 */
	private String logDirectory;
	private Level logLevel;

	/*
	 * The object-level rules encapsulated by the stage in which they are executed.
	 */
	private List<Rule> beforeBodyRules;
	private List<Rule> afterBodyRules;
	private List<Rule> beforeResponseRules;

	public AppGuardianConfiguration() {
		beforeBodyRules = new ArrayList<Rule>();
		afterBodyRules = new ArrayList<Rule>();
		beforeResponseRules = new ArrayList<Rule>();

		aliases = new HashMap<String,Object>();
	}

	public String getLogDirectory() {
		return logDirectory;
	}

	public void setLogDirectory(String logDirectory) {
		this.logDirectory = logDirectory;
	}

	public Level getLogLevel() {
		return logLevel;
	}

	public void setLogLevel(Level logLevel) {
		this.logLevel = logLevel;
	}

	public String getDefaultErrorPage() {
		return defaultErrorPage;
	}

	public void setDefaultErrorPage(String defaultErrorPage) {
		this.defaultErrorPage = defaultErrorPage;
	}

	public int getDefaultResponseCode() {
		return defaultResponseCode;
	}

	public void setDefaultResponseCode(int defaultResponseCode) {
		this.defaultResponseCode = defaultResponseCode;
	}

	public void addAlias(String key, Object obj) {
		aliases.put(key, obj);
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
		return afterBodyRules;
	}

	public List<Rule> getBeforeResponseRules() {
		return beforeResponseRules;
	}

	public void addBeforeBodyRule(Rule r) {
		beforeBodyRules.add(r);
	}

	public void addAfterBodyRule(Rule r) {
		afterBodyRules.add(r);
	}

	public void addBeforeResponseRule(Rule r) {
		beforeResponseRules.add(r);
	}

}
