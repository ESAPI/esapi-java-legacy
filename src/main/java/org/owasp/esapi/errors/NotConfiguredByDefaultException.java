package org.owasp.esapi.errors;

/**
 * A {@code NotConfiguredByDefaultException} should be thrown when a method that
 * is disabled by default is invoked.
 * </p><p>

 * See the ESAPI properties "<b>ESAPI.dangerouslyAllowUnsafeMethods.methodNames</b>"
 * and "<b>ESAPI.dangerouslyAllowUnsafeMethods.justification</b>" in the
 * <b>ESAPI.properties</b> file for additional details.
 * </p>
 */
public class NotConfiguredByDefaultException extends ConfigurationException {

    protected static final long serialVersionUID = 1L;
    private static final String defaultMsg = "Unknown unsafe ESAPI method invoked without being explicitly allowed. " +
                                             "Check exception stack trace for method name.";

    public NotConfiguredByDefaultException(Exception e) {
        super(e);
    }

    public NotConfiguredByDefaultException(String s) {
        super( (s == null || s.trim().isEmpty()) ? defaultMsg : s);
    }

    public NotConfiguredByDefaultException(String s, Throwable cause) {
        super( (s == null || s.trim().isEmpty()) ? defaultMsg : s, cause);
    }

    public NotConfiguredByDefaultException(Throwable cause) {
        super(defaultMsg, cause);
    }
}
