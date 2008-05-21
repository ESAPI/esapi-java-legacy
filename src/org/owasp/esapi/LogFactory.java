/**
 * 
 */
package org.owasp.esapi;

/**
 * @author rdawes
 *
 */
public interface LogFactory {
	
	Logger getLogger(String name);
	
	Logger getLogger(Class clazz);
	
}
