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
 * The class that indicates the user should be redirected to another location.
 * 
 * @author Arshan Dabirsiaghi
 */
public class RedirectAction extends Action {

	private String url = null;

	/*
	 * Setting this overrides the default value read in the config file.
	 */
	public void setRedirectURL(String s) {
		this.url = s;
	}

	public String getRedirectURL() {
		return this.url;
	}

	public boolean failedRule() {

		return false;
	}

	public boolean isActionNecessary() {

		return false;
	}


}
