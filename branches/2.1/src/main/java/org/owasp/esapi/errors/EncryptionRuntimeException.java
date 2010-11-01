/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2010 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi.errors;

/**
 * An EncryptionRuntimeException should be thrown for any problems related to
 * encryption, hashing, or digital signatures.
 * 
 * @author August Detlefsen (augustd at codemagi dot com)
 *         <a href="http://www.codemagi.com">CodeMagi, Inc.</a>
 * @since October 8, 2010
 */
public class EncryptionRuntimeException extends EnterpriseSecurityRuntimeException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new EncryptionException.
	 */
	protected EncryptionRuntimeException() {
		// hidden
	}

    /**
     * Creates a new instance of EncryptionException.
     * 
     * @param userMessage
     *            the message displayed to the user
     * @param logMessage
	 * 			  the message logged
     */
    public EncryptionRuntimeException(String userMessage, String logMessage) {
        super(userMessage, logMessage);
    }

    /**
     * Instantiates a new EncryptionException.
     * 
     * @param userMessage
     *            the message displayed to the user
     * @param logMessage
	 * 			  the message logged
     * @param cause
     *            the cause
     */
    public EncryptionRuntimeException(String userMessage, String logMessage, Throwable cause) {
        super(userMessage, logMessage, cause);
    }
}
