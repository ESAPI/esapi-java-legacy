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
 * An AuthenticationException should be thrown when anything goes wrong during
 * login or logout. They are also appropriate for any problems related to
 * identity management.
 *
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class AuthenticationAccountsException extends AuthenticationException {

    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = 1L;

    /**
     * Instantiates a new authentication exception.
     */
    protected AuthenticationAccountsException() {
        // hidden
    }

    /**
     * Creates a new instance of {@code AuthenticationAccountsException}.
     *
     * @param userMessage the message displayed to the user
     * @param logMessage the message logged
     *
     */
    public AuthenticationAccountsException(String userMessage, String logMessage) {
        super(userMessage, logMessage);
    }

    /**
     * Instantiates a new authentication exception.
     *
     * @param userMessage the message displayed to the user
     * @param logMessage the message logged
     * @param cause the root cause
     */
    public AuthenticationAccountsException(String userMessage, String logMessage, Throwable cause) {
        super(userMessage, logMessage, cause);
    }

}
