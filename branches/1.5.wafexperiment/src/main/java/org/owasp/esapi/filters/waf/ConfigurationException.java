package org.owasp.esapi.filters.waf;

public class ConfigurationException extends Exception {

	public ConfigurationException(Exception e) {
		super(e);
	}

	public ConfigurationException(String s) {
		super(s);
	}

}
