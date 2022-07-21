/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi.errors;

/**
 * An AvailabilityException should be thrown when the availability of a limited
 * resource is in jeopardy. For example, if a database connection pool runs out
 * of connections, an availability exception should be thrown.
 *
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class AvailabilityException extends EnterpriseSecurityException {

    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = 1L;

    /**
     * Instantiates a new availability exception.
     */
    protected AvailabilityException() {
        // hidden
    }

    /**
     * Creates a new instance of AvailabilityException.
     *
     * @param userMessage the message displayed to the user
     * @param logMessage the message logged
     */
    public AvailabilityException(String userMessage, String logMessage) {
        super(userMessage, logMessage);
    }

    /**
     * Instantiates a new AvailabilityException.
     *
     * @param userMessage the message displayed to the user
     * @param logMessage the message logged
     * @param cause the cause
     */
    public AvailabilityException(String userMessage, String logMessage, Throwable cause) {
        super(userMessage, logMessage, cause);
    }
}
