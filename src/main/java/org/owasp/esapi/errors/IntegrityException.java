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
 * An IntegrityException should be thrown when a problem with the integrity of data
 * has been detected. For example, if a financial account cannot be reconciled after
 * a transaction has been performed, an integrity exception should be thrown.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class IntegrityException extends EnterpriseSecurityException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new availability exception.
	 */
	protected IntegrityException() {
		// hidden
	}

    /**
     * Creates a new instance of IntegrityException.
     * 
     * @param userMessage
     *            the message to display to users
     * @param logMessage
	 * 			  the message logged
     */
    public IntegrityException(String userMessage, String logMessage) {
        super(userMessage, logMessage);
    }

    /**
     * Instantiates a new IntegrityException.
     * 
     * @param userMessage
     *            the message to display to users
     * @param logMessage
	 * 			  the message logged
     * @param cause
     *            the cause
     */
    public IntegrityException(String userMessage, String logMessage, Throwable cause) {
        super(userMessage, logMessage, cause);
    }
}
