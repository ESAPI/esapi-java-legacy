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
 * @author Rogan Dawes<a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2008
 */
package org.owasp.esapi;

/**
 * The LogFactory interface is intended to allow substitution of various logging packages, while providing
 * a common interface to access them.
 * 
 * In the default implementation, JavaLogFactory.java implements this interface.  JavaLogFactory.java also contains an 
 * inner class called JavaLogger which implements Logger.java and uses the Java logging package to log events. 
 * 
 * @see org.owasp.esapi.ESAPI
 * 
 * @author rdawes
 *
 */
public interface LogFactory {
	
	Logger getLogger(String name);
	
	Logger getLogger(Class clazz);
	
}
