package org.owasp.esapi.reference;

import org.owasp.esapi.Logger;

/**
 * 
 * This class demonstrates how to extend the Log4JLogFactory. 
 * 
 * @author jmanico
 *
 */
public class ExampleExtendedLog4JLogFactory extends Log4JLogFactory {

	protected static class ExampleExtendedLog4JLogger extends Log4JLogger {
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
