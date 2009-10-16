package org.owasp.esapi.errors;

/**
 * A {@code ConfigurationException} should be thrown when a problem arises because of
 * a problem in one of ESAPI's configuration files, such as a missing required
 * property or invalid setting of a property, or missing or unreadable
 * configuration file, etc.
 * <p>
 * A {@code ConfigurationException} is a {@code RuntimeException}
 * because 1) configuration properties can, for the most part, only be checked
 * at run-time, and 2) we want this to be an unchecked exception to make ESAPI
 * easy to use and not cluttered with catching a bunch of try/catch blocks.
 * </p>
 */
public class ConfigurationException extends RuntimeException {

	protected static final long serialVersionUID = 1L;

	public ConfigurationException(Exception e) {
		super(e);
	}

	public ConfigurationException(String s) {
		super(s);
	}
	
	public ConfigurationException(String s, Throwable cause) {
		super(s, cause);
	}
	
	public ConfigurationException(Throwable cause) {
		super(cause);
	}
}
