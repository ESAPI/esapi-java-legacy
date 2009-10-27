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
 * EnterpriseSecurityException is the base class for all security related exceptions. You should pass in the root cause
 * exception where possible. Constructors for classes extending EnterpriseSecurityException should be sure to call the
 * appropriate super() method in order to ensure that logging and intrusion detection occur properly.
 * <P>
 * All EnterpriseSecurityExceptions have two messages, one for the user and one for the log file. This way, a message
 * can be shown to the user that doesn't contain sensitive information or unnecessary implementation details. Meanwhile,
 * all the critical information can be included in the exception so that it gets logged.
 * <P>
 * Note that the "logMessage" for ALL EnterpriseSecurityExceptions is logged in the log file. This feature should be
 * used extensively throughout ESAPI implementations and the result is a fairly complete set of security log records.
 * ALL EnterpriseSecurityExceptions are also sent to the IntrusionDetector for use in detecting anomolous patterns of
 * application usage.
 * <P>
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class EnterpriseSecurityException extends Exception {

    protected static final long serialVersionUID = 1L;

    /** The logger. */
    protected final Logger logger = ESAPI.getLogger("EnterpriseSecurityException");

    /**
     *
     */
    protected String logMessage = null;

    /**
     * Instantiates a new security exception.
     */
    protected EnterpriseSecurityException() {
        // hidden
    }

    /**
     * Creates a new instance of EnterpriseSecurityException. This exception is automatically logged, so that simply by
     * using this API, applications will generate an extensive security log. In addition, this exception is
     * automatically registered with the IntrusionDetector, so that quotas can be checked.
     *
     * It should be noted that messages that are intended to be displayed to the user should be safe for display. In
     * other words, don't pass in unsanitized data here. Also could hold true for the logging message depending on the
     * context of the exception.
     * 
     * @param userMessage 
     * 			  the message displayed to the user
     * @param logMessage
	 * 			  the message logged
     */
    public EnterpriseSecurityException(String userMessage, String logMessage) {
    	super(userMessage);
        this.logMessage = logMessage;
        ESAPI.intrusionDetector().addException(this);
    }

    /**
     * Creates a new instance of EnterpriseSecurityException that includes a root cause Throwable.
     * 
     * It should be noted that messages that are intended to be displayed to the user should be safe for display. In
     * other words, don't pass in unsanitized data here. Also could hold true for the logging message depending on the
     * context of the exception.
     *
     * @param userMessage
     * 			  the message displayed to the user
     * @param logMessage
	 * 			  the message logged
     * @param cause the cause
     */
    public EnterpriseSecurityException(String userMessage, String logMessage, Throwable cause) {
        super(userMessage, cause);
        this.logMessage = logMessage;
        ESAPI.intrusionDetector().addException(this);
    }
    
    /**
     * Returns message meant for display to users
     *
     * Note that if you are unsure of what set this message, it would probably be a good idea to encode this message
     * before displaying it to the end user.
     * 
     * @return a String containing a message that is safe to display to users
     */
    public String getUserMessage() {
        return getMessage();
    }

    /**
     * Returns a message that is safe to display in logs, but probably not to users
     * 
     * @return a String containing a message that is safe to display in logs, but probably not to users
     */
    public String getLogMessage() {
        return logMessage;
    }

}
