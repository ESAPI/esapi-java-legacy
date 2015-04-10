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
 * @author Ben Sleek <a href="http://www.spartasystems.com">Sparta Systems</a>
 * @created 2015
 */
package org.owasp.esapi.reference.validation;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.Encoder;
import org.owasp.esapi.errors.ValidationException;

public class BaseValidationRuleTest extends TestCase {

	/**
	 * Instantiates a new base validation rule test.
	 * 
	 * @param testName
	 *            the test name
	 */
	public BaseValidationRuleTest(String testName) {
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
		TestSuite suite = new TestSuite(BaseValidationRuleTest.class);
		return suite;
	}

	/**
	 * Verifies assertValid throws ValidationException on invalid input
	 * Validates fix for Google issue #195
	 * 
	 * @throws ValidationException
	 */
	public void testAssertValid() throws ValidationException {
		SampleValidationRule rule = new SampleValidationRule("UnitTest");
		try {
			rule.assertValid("testcontext", "badinput");
			fail();
		} catch (ValidationException e) {
			// success
		}
	}

	public class SampleValidationRule extends BaseValidationRule {

		public SampleValidationRule(String typeName, Encoder encoder) {
			super(typeName, encoder);
		}

		public SampleValidationRule(String typeName) {
			super(typeName);
		}

		@Override
		protected Object sanitize(String context, String input) {
			return null;
		}

		public Object getValid(String context, String input) throws ValidationException {
			throw new ValidationException("Demonstration Exception", "Demonstration Exception");
		}

	}
}
