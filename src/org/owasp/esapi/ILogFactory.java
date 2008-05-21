/**
 * 
 */
package org.owasp.esapi;

/**
 * @author rdawes
 *
 */
public interface ILogFactory {
	
	ILogger getLogger(String name);
	
	ILogger getLogger(Class clazz);
	
}
