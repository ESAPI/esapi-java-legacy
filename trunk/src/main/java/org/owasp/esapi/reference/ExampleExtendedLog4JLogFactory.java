package org.owasp.esapi.reference;

import org.owasp.esapi.Logger;

/**
 * This class demonstrates how to override the ESAPI Log4JLogFactory user-specific message so implementors can utilize 
 * their individual user object implementations. Please copy this code, rename and repackage it, and change 
 * 
 * 	public String getUserInfo() {
 *		return "-EXTENDEDUSERINFO-";
 *	}
 *
 * .. so that is uses your own user implementation. Account name, IP address, and a "safe" version of the session ID should be considered.
 *
 * This implementation uses the Apache Log4J package. At class initialization time, the file log4j.properties or log4j.xml file will be
 * loaded from the classpath. This configuration file is fundamental to make log4j work for you. 
 * Please see http://logging.apache.org/log4j/1.2/manual.html for more information. 
 * 
 * @author Jim Manico (jim@manico.net) <a href="http://www.manico.net">manico.net</a>
 * @see org.owasp.esapi.LogFactory
 * @see org.owasp.esapi.reference.Log4JLogFactory
 */
public class ExampleExtendedLog4JLogFactory extends org.owasp.esapi.reference.Log4JLogFactory {

	protected static class ExampleExtendedLog4JLogger extends org.owasp.esapi.reference.Log4JLogFactory.Log4JLogger {
	
		protected ExampleExtendedLog4JLogger(String moduleName) {
			super(moduleName);
		}
			
		/**
		 * Please replace this function with your own. 
		 * 
		 * The reference implementation includes the users account name, last host
		 * address, and a secure replacement for the session id. 
		 * 
		 **/
		public String getUserInfo() {
			return "-EXTENDEDUSERINFO-";
		}
	}
	
    /**
	* {@inheritDoc}
	*/
	public Logger getLogger(String moduleName) {
		
		// If a logger for this module already exists, we return the same one, otherwise we create a new one.
		Logger moduleLogger = (Logger) loggersMap.get(moduleName);
			
		if (moduleLogger == null) {
			moduleLogger = new ExampleExtendedLog4JLogger(moduleName);
			loggersMap.put(moduleName, moduleLogger);    		
		}
		
		return moduleLogger;
	}
}