package org.owasp.esapi.errors;

/**
 * A {@code NotConfiguredByDefaultException} should be thrown when a method that
 * is disabled by default is invoked,
 * </p><p>
 * See the ESAPI properties "ESAPI.enableLegCannonModeAndGetMyAssFired.methodNames" and
 * "ESAPI,enableLegCannonModeAndGetMyAssFired,justification" in the
 * <b>ESAPI.properties</b> file for additional details.
 * </p>
 */
public class NotConfiguredByDefaultException extends ConfigurationException {

    protected static final long serialVersionUID = 1L;

    public NotConfiguredByDefaultException(Exception e) {
        super(e);
    }

    public NotConfiguredByDefaultException(String s) {
        super(s);
    }

    public NotConfiguredByDefaultException(String s, Throwable cause) {
        super(s, cause);
    }

    public NotConfiguredByDefaultException(Throwable cause) {
        super(cause);
    }
}
