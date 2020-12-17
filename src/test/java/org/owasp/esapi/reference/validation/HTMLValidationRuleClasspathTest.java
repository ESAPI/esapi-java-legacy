/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2019 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author kevin.w.wall@gmail.com
 * @since 2019
 */
package org.owasp.esapi.reference.validation;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.SecurityConfigurationWrapper;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.ValidationRule;
import org.owasp.esapi.Validator;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.reference.validation.HTMLValidationRule;

import org.junit.Test;
import org.junit.Before;
import org.junit.After;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import static org.junit.Assert.*;

/**
 * The Class HTMLValidationRuleThrowsTest.
 *
 * Based on original test cases, testGetValidSafeHTML() and
 * testIsValidSafeHTML() from ValidatorTest by
 *      Mike Fauzy (mike.fauzy@aspectsecurity.com) and
 *      Jeff Williams (jeff.williams@aspectsecurity.com)
 * that were originally part of src/test/java/org/owasp/esapi/reference/ValidatorTest.java.
 *
 * This class tests the cases where the new ESAPI.property
 *      Validator.HtmlValidationAction
 * is set to "throw", which causes certain calls to
 * ESAPI.validator().getValidSafeHTML() or ESAPI.validator().isValidSafeHTML()
 * to throw a ValidationException rather than simply logging a warning and returning
 * the cleansed (sanitizied) output when certain unsafe input is encountered.
 */
public class HTMLValidationRuleClasspathTest {
	private static class ConfOverride extends SecurityConfigurationWrapper {
        private String desiredReturnAction = "clean";
        private String desiredReturnConfigurationFile = "antisamy-esapi.xml";

		ConfOverride(SecurityConfiguration orig, String desiredReturnAction, String desiredReturnConfigurationFile) {
			super(orig);
            this.desiredReturnAction = desiredReturnAction;
			this.desiredReturnConfigurationFile = desiredReturnConfigurationFile;
		}

		@Override
		public String getStringProp(String propName) {
            // Would it be better making this file a static import?
			if ( propName.equals( org.owasp.esapi.reference.DefaultSecurityConfiguration.VALIDATOR_HTML_VALIDATION_ACTION ) ) {
                return desiredReturnAction;
            } else if ( propName.equals( org.owasp.esapi.reference.DefaultSecurityConfiguration.VALIDATOR_HTML_VALIDATION_CONFIGURATION_FILE ) ) {
                return desiredReturnConfigurationFile;
            } else {
                return super.getStringProp( propName );
            }
        }
    }

    // Must be public!
    @Rule
    public ExpectedException thrownEx = ExpectedException.none();

    @After
    public void tearDown() throws Exception {
        ESAPI.override(null);
        thrownEx = ExpectedException.none();
    }

	@Before
    public void setUp() throws Exception {
		ESAPI.override(
			new ConfOverride( ESAPI.securityConfiguration(), "throw", "antisamy-esapi-CP.xml" )
		);

    }

    @Test
    public void testGetValid() throws Exception {
        System.out.println("getValidCP");
        Validator instance = ESAPI.validator();
        HTMLValidationRule rule = new HTMLValidationRule("testCP");
        ESAPI.validator().addRule(rule);

        thrownEx.expect(ValidationException.class);
        thrownEx.expectMessage("test: Invalid HTML input");

        instance.getRule("testCP").getValid("test", "Test. <script>alert(document.cookie)</script>");
    }

    @Test
    public void testGetValidSafeHTML() throws Exception {
        System.out.println("getValidSafeHTML");
        Validator instance = ESAPI.validator();

        HTMLValidationRule rule = new HTMLValidationRule("test");
        ESAPI.validator().addRule(rule);

        String[] testInput = {
                                // These first two don't cause AntiSamy to throw.
                        // "Test. <a href=\"http://www.aspectsecurity.com\">Aspect Security</a>",
                        // "Test. <<div on<script></script>load=alert()",
                        "Test. <script>alert(document.cookie)</script>",
                        "Test. <script>alert(document.cookie)</script>",
                        "Test. <div style={xss:expression(xss)}>b</div>",
                        "Test. <s%00cript>alert(document.cookie)</script>",
                        "Test. <s\tcript>alert(document.cookie)</script>",
                        "Test. <s\tcript>alert(document.cookie)</script>"
        };

        int errors = 0;
        for( int i = 0; i < testInput.length; i++ ) {
            try {
                String result = instance.getValidSafeHTML("test", testInput[i], 100, false);
                errors++;
                System.out.println("testGetValidSafeHTML(): testInput '" + testInput[i] + "' failed to throw.");
            }
            catch( ValidationException vex ) {
                System.out.println("testGetValidSafeHTML(): testInput '" + testInput[i] + "' returned:");
                System.out.println("\t" + i + ": logMsg =" + vex.getLogMessage());
                assertEquals( vex.getUserMessage(), "test: Invalid HTML input");
            }
            catch( Exception ex ) {
                errors++;
                System.out.println("testGetValidSafeHTML(): testInput '" + testInput[i] +
                                   "' threw wrong exception type: " + ex.getClass().getName() );
            }
        }

        if ( errors > 0 ) {
            fail("testGetValidSafeHTML() encountered " + errors + " failures.");
        }
    }

    @Test
    public void testIsValidSafeHTML() {
        System.out.println("isValidSafeHTML");
        Validator instance = ESAPI.validator();
        thrownEx = ExpectedException.none();    // Not expecting any exceptions here.

        assertTrue(instance.isValidSafeHTML("test", "<b>Jeff</b>", 100, false));
        assertTrue(instance.isValidSafeHTML("test", "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>", 100, false));
        assertFalse(instance.isValidSafeHTML("test", "Test. <script>alert(document.cookie)</script>", 100, false));
        assertFalse(instance.isValidSafeHTML("test", "Test. <div style={xss:expression(xss)}>", 100, false));
        assertFalse(instance.isValidSafeHTML("test", "Test. <s%00cript>alert(document.cookie)</script>", 100, false));
        assertFalse(instance.isValidSafeHTML("test", "Test. <s\tcript>alert(document.cookie)</script>", 100, false));
        assertFalse(instance.isValidSafeHTML("test", "Test. <s\r\n\0cript>alert(document.cookie)</script>", 100, false));

        ValidationErrorList errors = new ValidationErrorList();
        assertFalse(instance.isValidSafeHTML("test1", "Test. <script>alert(document.cookie)</script>", 100, false, errors));
        assertFalse(instance.isValidSafeHTML("test2", "Test. <div style={xss:expression(xss)}>", 100, false, errors));
        assertFalse(instance.isValidSafeHTML("test3", "Test. <s%00cript>alert(document.cookie)</script>", 100, false, errors));
        assertFalse(instance.isValidSafeHTML("test4", "Test. <s\tcript>alert(document.cookie)</script>", 100, false, errors));
        assertFalse(instance.isValidSafeHTML("test5", "Test. <s\r\n\0cript>alert(document.cookie)</script>", 100, false, errors));
        assertTrue( errors.size() == 5 );
    }
}
