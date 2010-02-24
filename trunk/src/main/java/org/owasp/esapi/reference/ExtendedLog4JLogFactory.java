package org.owasp.esapi.reference;

public class ExtendedLog4JLogFactory extends Log4JLogFactory {
	
	/**
	 * In the Javadoc for this getUserInfo() method (or whatever you call it, can you explain everything that we include, user, 
	 * source host:port, dest IP port, target URL], and indicate they might want to add or subtract from this in their version.
	 * 
	 * @return
	 */
    public String getUserInfo() {
		return "JIMINFOTEST";
    }
}
