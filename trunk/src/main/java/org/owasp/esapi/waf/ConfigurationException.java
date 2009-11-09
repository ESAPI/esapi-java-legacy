/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Arshan Dabirsiaghi <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2009
 */
package org.owasp.esapi.waf;

/**
 * The Exception to be thrown when there is an error parsing a policy file.
 * 
 * @author Arshan Dabirsiaghi
 * @see org.owasp.esapi.configuration.ConfigurationParser
 *
 */
public class ConfigurationException extends Exception {

	protected static final long serialVersionUID = 1L;

	public ConfigurationException(Exception e) {
		super(e);
	}

	public ConfigurationException(String s) {
		super(s);
	}

}
