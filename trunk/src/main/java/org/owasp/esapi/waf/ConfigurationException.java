package org.owasp.esapi.waf;

public class ConfigurationException extends Exception {

	protected static final long serialVersionUID = 1L;

	public ConfigurationException(Exception e) {
		super(e);
	}

	public ConfigurationException(String s) {
		super(s);
	}

}
