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
 * An EncryptionException should be thrown for any problems related to
 * encryption, hashing, or digital signatures.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class EncryptionException extends EnterpriseSecurityException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new EncryptionException.
	 */
	protected EncryptionException() {
		// hidden
	}

    /**
     * Creates a new instance of EncryptionException.
     * 
     * @param message
     *            the message
     */
    public EncryptionException(String userMessage, String logMessage) {
        super(userMessage, logMessage);
    }

    /**
     * Instantiates a new EncryptionException.
     * 
     * @param message
     *            the message
     * @param cause
     *            the cause
     */
    public EncryptionException(String userMessage, String logMessage, Throwable cause) {
        super(userMessage, logMessage, cause);
    }
}
