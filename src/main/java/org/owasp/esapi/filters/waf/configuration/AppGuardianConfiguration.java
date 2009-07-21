package org.owasp.esapi.waf.configuration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.log4j.Level;
import org.owasp.esapi.waf.rules.Rule;

public class AppGuardianConfiguration {

	/*
	 * Fail modes (BLOCK blocks and logs the request, DONT_BLOCK simply logs)
	 */
	public static final int LOG = 0;
	public static final int REDIRECT = 1;
	public static final int BLOCK = 2;

	/*
	 * The operators.
	 */
	public static final int OPERATOR_EQ = 0;
	public static final int OPERATOR_CONTAINS = 1;
	public static final int OPERATOR_IN_LIST = 2;
	public static final int OPERATOR_EXISTS = 3;

	/*
	 * Logging settings.
	 */
	public static Level LOG_LEVEL = Level.INFO;
	public static String LOG_DIRECTORY = "/WEB-INF/logs";


	/*
	 * Default settings.
	 */
	public static int DEFAULT_FAIL_ACTION = LOG;

	public static int MAX_FILE_SIZE = Integer.MAX_VALUE;

	// TODO: use UTF-8
	public static String DEFAULT_CHARACTER_ENCODING = "ISO-8859-1";
	public static String DEFAULT_CONTENT_TYPE = "text/html; charset=" + DEFAULT_CHARACTER_ENCODING;

	public static boolean FORCE_HTTP_ONLY_FLAG_TO_SESSION = false;
	public static boolean FORCE_SECURE_FLAG_TO_SESSION = false;

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
	 * The object-level rules encapsulated by the stage in which they are executed.
	 */
	private List<Rule> beforeBodyRules;
	private List<Rule> afterBodyRules;
	private List<Rule> beforeResponseRules;
	private List<Rule> cookieRules;

	public AppGuardianConfiguration() {
		beforeBodyRules = new ArrayList<Rule>();
		afterBodyRules = new ArrayList<Rule>();
		beforeResponseRules = new ArrayList<Rule>();
		cookieRules = new ArrayList<Rule>();

		aliases = new HashMap<String,Object>();
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

	public List<Rule> getBeforeBodyRules() {
		return beforeBodyRules;
	}

	public List<Rule> getAfterBodyRules() {
		return afterBodyRules;
	}

	public List<Rule> getBeforeResponseRules() {
		return beforeResponseRules;
	}

	public List<Rule> getCookieRules() {
		return cookieRules;
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

	public void addCookieRule(Rule r) {
		cookieRules.add(r);
	}

	public void applyHTTPOnlyFlagToSessionCookie() {
		FORCE_HTTP_ONLY_FLAG_TO_SESSION = true;
	}

	public void applySecureFlagToSessionCookie() {
		FORCE_SECURE_FLAG_TO_SESSION = true;
	}

}
