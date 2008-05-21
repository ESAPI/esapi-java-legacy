/**
 * 
 */
package org.owasp.esapi.reference;

import org.owasp.esapi.LogFactory;
import org.owasp.esapi.Logger;

/**
 * @author rdawes
 *
 */
public class JavaLogFactory implements LogFactory {

	private String applicationName;
	
	public JavaLogFactory(String applicationName) {
		this.applicationName = applicationName;
	}
	
	/* (non-Javadoc)
     * @see org.owasp.esapi.interfaces.ILogFactory#getLogger(java.lang.Class)
     */
    public Logger getLogger(Class clazz) {
	    return new JavaLogger(applicationName, clazz.getName());
    }

	/* (non-Javadoc)
     * @see org.owasp.esapi.interfaces.ILogFactory#getLogger(java.lang.String)
     */
    public Logger getLogger(String name) {
    	return new JavaLogger(applicationName, name);
    }

}
