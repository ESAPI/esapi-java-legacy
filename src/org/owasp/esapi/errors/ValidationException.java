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
 * A ValidationException should be thrown to indicate that the data provided by
 * the user or from some other external source does not match the validation
 * rules that have been specified for that data.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class ValidationException extends EnterpriseSecurityException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;
	
	/** The UI reference that caused this ValidationException */
	private String context;

	public static long getSerialVersionUID() {
		return serialVersionUID;
	}

	/**
	 * Instantiates a new validation exception.
	 */
	protected ValidationException() {
		// hidden
	}

    /**
     * Creates a new instance of ValidationException.
     * 
     * @param message
     *            the message
     */
    public ValidationException(String userMessage, String logMessage) {
        super(userMessage, logMessage);
    }

    /**
     * Instantiates a new ValidationException.
     * 
     * @param message
     *            the message
     * @param cause
     *            the cause
     */
    public ValidationException(String userMessage, String logMessage, Throwable cause) {
        super(userMessage, logMessage, cause);
    }
    
    /**
     * Creates a new instance of ValidationException.
     * 
     * @param message
     *            the message
    * @param context
     *            the source that caused this exception
     */
    public ValidationException(String userMessage, String logMessage, String context) {
        super(userMessage, logMessage);
        setContext(context);
    }
    
    /**
     * Instantiates a new ValidationException.
     * 
     * @param message
     *            the message
     * @param cause
     *            the cause
     * @param context
     *            the source that caused this exception
     */
    public ValidationException(String userMessage, String logMessage, Throwable cause, String context) {
        super(userMessage, logMessage, cause);
    	setContext(context);
    }
    
	/**
	 * Returns the UI reference that caused this ValidationException
	 *  
	 * @return
	 */
	public String getContext() {
		return context;
	}

	/**
	 * Set's the UI reference that caused this ValidationException
	 *  
	 * @param cause
	 */
	public void setContext(String context) {
		this.context = context;
	}
}
