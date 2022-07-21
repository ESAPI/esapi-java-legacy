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

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;

/**
 * An IntrusionException should be thrown anytime an error condition arises that is likely to be the result of an attack
 * in progress. IntrusionExceptions are handled specially by the IntrusionDetector, which is equipped to respond by
 * either specially logging the event, logging out the current user, or invalidating the current user's account.
 * <P>
 * Unlike other exceptions in the ESAPI, the IntrusionException is a RuntimeException so that it can be thrown from
 * anywhere and will not require a lot of special exception handling.
 *
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class IntrusionException extends EnterpriseSecurityRuntimeException {

    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = 1L;

    /** The logger. */
    protected final transient Logger logger = ESAPI.getLogger("IntrusionException");

    /**
     *
     */
    protected String logMessage = null;

    /**
     * Creates a new instance of IntrusionException.
     *
     * @param userMessage
     *            the message to display to users
     * @param logMessage
     *               the message logged
     */
    public IntrusionException(String userMessage, String logMessage) {
        super(userMessage);
        this.logMessage = logMessage;
        logger.error(Logger.SECURITY_FAILURE, "INTRUSION - " + logMessage);
    }

    /**
     * Instantiates a new intrusion exception.
     *
     * @param userMessage
     *            the message to display to users
     * @param logMessage
     *               the message logged
     * @param cause
     *              the cause
     */
    public IntrusionException(String userMessage, String logMessage, Throwable cause) {
        super(userMessage, cause);
        this.logMessage = logMessage;
        logger.error(Logger.SECURITY_FAILURE, "INTRUSION - " + logMessage, cause);
    }

    /**
     * Returns a String containing a message that is safe to display to users
     *
     * @return a String containing a message that is safe to display to users
     */
    public String getUserMessage() {
        return getMessage();
    }

    /**
     * Returns a String that is safe to display in logs, but probably not to users
     *
     * @return a String containing a message that is safe to display in logs, but probably not to users
     */
    public String getLogMessage() {
        return logMessage;
    }

}
