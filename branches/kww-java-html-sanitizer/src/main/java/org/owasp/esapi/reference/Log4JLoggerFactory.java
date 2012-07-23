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
package org.owasp.esapi.reference;

import org.apache.log4j.spi.LoggerFactory;

/**
 * Implementation of the LoggerFactory interface. This implementation has been 
 * overridden to return instances of org.owasp.esapi.reference.Log4JLogger.
 *
 * @author August Detlefsen (augustd at codemagi dot com)
 *         <a href="http://www.codemagi.com">CodeMagi, Inc.</a>
 * @since October 15, 2010
 * @see org.owasp.esapi.reference.Log4JLogFactory
 * @see org.owasp.esapi.reference.Log4JLogger
 */
public class Log4JLoggerFactory implements LoggerFactory {

	/**
	 * This constructor must be public so it can be accessed from within log4j
	 */
	public Log4JLoggerFactory() {}

	/**
	 * Overridden to return instances of org.owasp.esapi.reference.Log4JLogger.
	 * 
	 * @param name The class name to return a logger for.
	 * @return org.owasp.esapi.reference.Log4JLogger
	 */
	public org.apache.log4j.Logger makeNewLoggerInstance(String name) {
		return new Log4JLogger(name);
	}
	
}
