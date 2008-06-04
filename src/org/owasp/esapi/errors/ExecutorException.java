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
 * An ExecutorException should be thrown for any problems that arise during the
 * execution of a system executable.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class ExecutorException extends EnterpriseSecurityException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new ExecutorException.
	 */
	protected ExecutorException() {
		// hidden
	}

    /**
     * Creates a new instance of ExecutorException.
     * 
     * @param message
     *            the message
     */
    public ExecutorException(String userMessage, String logMessage) {
        super(userMessage, logMessage);
    }

    /**
     * Instantiates a new ExecutorException.
     * 
     * @param message
     *            the message
     * @param cause
     *            the cause
     */
    public ExecutorException(String userMessage, String logMessage, Throwable cause) {
        super(userMessage, logMessage, cause);
    }

}
