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
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * The Class ExecutorTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class ESAPITest extends TestCase {

	/**
	 * Instantiates a new executor test.
	 * 
	 * @param testName
	 *            the test name
	 */
	public ESAPITest(String testName) {
		super(testName);
	}

	/**
     * {@inheritDoc}
     *
     * @throws Exception
     */
	protected void setUp() throws Exception {
		// none
	}

	/**
     * {@inheritDoc}
     *
     * @throws Exception
     */
	protected void tearDown() throws Exception {
		// none
	}

	/**
	 * Suite.
	 * 
	 * @return the test
	 */
	public static Test suite() {
		TestSuite suite = new TestSuite(ESAPITest.class);
		return suite;
	}

	/**
	 * Test of all the ESAPI setter methods
	 * 
	 * @throws Exception
	 *             the exception
	 */
	public void testSetters() throws Exception {
		System.out.println("testSetters");
		ESAPI.setAccessController(ESAPI.accessController());
		ESAPI.setAuthenticator(ESAPI.authenticator());
		ESAPI.setEncoder(ESAPI.encoder());
		ESAPI.setEncryptor(ESAPI.encryptor());
		ESAPI.setExecutor(ESAPI.executor());
		ESAPI.setHttpUtilities(ESAPI.httpUtilities());
		ESAPI.setIntrusionDetector(ESAPI.intrusionDetector());
		ESAPI.setRandomizer(ESAPI.randomizer());
		ESAPI.setSecurityConfiguration(ESAPI.securityConfiguration());
		ESAPI.setValidator(ESAPI.validator());
	}

}
