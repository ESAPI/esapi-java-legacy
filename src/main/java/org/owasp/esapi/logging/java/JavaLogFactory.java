package org.owasp.esapi.logging.java;

import java.io.Serializable;
import java.util.HashMap;

import org.owasp.esapi.LogFactory;
import org.owasp.esapi.Logger;

/**
 * Reference implementation of the LogFactory and Logger interfaces. This implementation uses the Java logging package, and marks each
 * log message with the currently logged in user and the word "SECURITY" for security related events. See the 
 * <a href="JavaLogFactory.JavaLogger.html">JavaLogFactory.JavaLogger</a> Javadocs for the details on the JavaLogger reference implementation.
 * 
 * @author Mike Fauzy (mike.fauzy@aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.LogFactory
 * @see org.owasp.esapi.logging.java.JavaLogFactory.JavaLogger
 */
public class JavaLogFactory implements LogFactory {
	private static volatile LogFactory singletonInstance;

    public static LogFactory getInstance() {
        if ( singletonInstance == null ) {
            synchronized ( JavaLogFactory.class ) {
                if ( singletonInstance == null ) {
                    singletonInstance = new JavaLogFactory();
                }
            }
        }
        return singletonInstance;
    }

	private HashMap<Serializable, Logger> loggersMap = new HashMap<Serializable, Logger>();
	
	/**
	* Null argument constructor for this implementation of the LogFactory interface
	* needed for dynamic configuration.
	*/
	public JavaLogFactory() {}
	
	/**
	* {@inheritDoc}
	*/
	public Logger getLogger(Class clazz) {
	    return getLogger(clazz.getName());
    }

    /**
	* {@inheritDoc}
	*/
    public Logger getLogger(String moduleName) {
    	
        synchronized (loggersMap) {
            // If a logger for this module already exists, we return the same one, otherwise we create a new one.
            Logger moduleLogger = loggersMap.get(moduleName);

            if (moduleLogger == null) {
                moduleLogger = new JavaLogger(moduleName);
                loggersMap.put(moduleName, moduleLogger);    		
            }
            return moduleLogger;
        }
    }


  

}
