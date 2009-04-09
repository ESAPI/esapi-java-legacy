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
 * In the reference implementation, JavaLogFactory.java implements this interface.  JavaLogFactory.java also contains an 
 * inner class called JavaLogger which implements Logger.java and uses the Java logging package to log events. 
 * 
 * @see org.owasp.esapi.ESAPI
 * 
 * @author rdawes
 *
 */
public interface LogFactory {
	
	/**
	 * Gets the logger associated with the specified module name. The module name is used by the logger to log which 
	 * module is generating the log events. The implementation of this method should return any preexisting Logger 
	 * associated with this module name, rather than creating a new Logger.
	 * <br><br>
	 * The JavaLogFactory reference implementation meets these requirements.
	 * 
	 * @param moduleName
	 * 			The name of the module requesting the logger.
	 * @return
	 * 			The Logger associated with this module.
	 */
	Logger getLogger(String moduleName);
	
	/**
	 * Gets the logger associated with the specified class. The class is used by the logger to log which 
	 * class is generating the log events. The implementation of this method should return any preexisting Logger 
	 * associated with this class name, rather than creating a new Logger.
	 * <br><br>
	 * The JavaLogFactory reference implementation meets these requirements.
	 * 
	 * @param clazz
	 * 			The name of the class requesting the logger.
	 * @return
	 * 			The Logger associated with this class.
	 */
	Logger getLogger(Class clazz);
	
	/**
	 * This is needed to allow for null argument construction of log factories.
	 * 
	 * @param applicationName
	 * 			A unique name to identify the application being logged.
	 */
	void setApplicationName(String applicationName);
	
}
