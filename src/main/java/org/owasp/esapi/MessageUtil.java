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
 * @author Pawan Singh (pawan.singh@owasp.org) <a href="www.owasp.org">OWASP</a>
 * @created 2009
 */
package org.owasp.esapi;

public interface MessageUtil {
	public String getMessage(String msgKey, Object[] arguments);

}
