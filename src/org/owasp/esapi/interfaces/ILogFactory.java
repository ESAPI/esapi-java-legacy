/**
 * 
 */
package org.owasp.esapi.interfaces;

/**
 * @author rdawes
 *
 */
public interface ILogFactory {
	
	ILogger getLogger(String name);
	
	ILogger getLogger(Class clazz);
	
}
