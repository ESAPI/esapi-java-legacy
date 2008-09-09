/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/esapi.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the LGPL. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;

import java.util.List;

/**
 * The threshold class simply models the data for a basic threshold with a name,
 * elapsed time, counter, and a set of actions to take.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public class Threshold {
	public String name = null;
	public int count = 0;
	public long interval = 0;
	public List actions = null;

	public Threshold(String name, int count, long interval, List actions) {
		this.name = name;
		this.count = count;
		this.interval = interval;
		this.actions = actions;
	}
}
