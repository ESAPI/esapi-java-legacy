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
package org.owasp.esapi.waf.actions;

/**
 * The base class indicating what is to be done after a rule executes.
 * 
 * @author Arshan Dabirsiaghi
 * @see org.owasp.esapi.waf.rules.Rule
 */
public abstract class Action {

	protected boolean failed = true;
	protected boolean actionNecessary = false;

	public void setFailed(boolean didFail) {
		failed = didFail;
	}

	public boolean failedRule() {
		return failed;
	}

	public boolean isActionNecessary() {
		return actionNecessary;
	}

	public void setActionNecessary(boolean b) {
		this.actionNecessary = b;

	}
}
