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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.SecurityConfigurationWrapper;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.Validator;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.validator.html.PolicyException;
import static org.owasp.esapi.PropNames.VALIDATOR_HTML_VALIDATION_ACTION;
import static org.owasp.esapi.PropNames.VALIDATOR_HTML_VALIDATION_CONFIGURATION_FILE;

/**
 * The class {@code HTMLValidationRuleClasspathTest} is used to test ESAPI where
 * the AntiSamy policy file is located in a non-standard place. It is based
 * on te original test cases, testGetValidSafeHTML() and
 * testIsValidSafeHTML() from the file {@code ValidatorTest} originally written
 * by
 *      Mike Fauzy (mike.fauzy@aspectsecurity.com) and
 *      Jeff Williams (jeff.williams@aspectsecurity.com)
 * that were originally part of "src/test/java/org/owasp/esapi/reference/ValidatorTest.java".
 *
 * This class tests the case of a non-standard AntiSamy policy file along with
 * the case where the new ESAPI.property
 *      {@code Validator.HtmlValidationAction}
 * is set to "throw", which causes certain calls to
 * ESAPI.validator().getValidSafeHTML() or ESAPI.validator().isValidSafeHTML()
 * to throw a ValidationException rather than simply logging a warning and returning
 * the cleansed (sanitizied) output when certain unsafe input is encountered.
 *
 * It should be noted that several of the tests in this file are deprecated because
 * they use {@code Validator.isValidSafeHTML} which is deprecated. See the
 * deprecation warnings for those methods respective Javadoc for further
 * details.
 */
public class HTMLValidationRuleClasspathTest {
    /** The intentionally non-compliant (to the AntiSamy XSD) AntiSamy policy file. We don't intend to
     * actually <i>use</i> it for anything other than to test that we report
     * non-compliant AntiSamy policy files in a sane manner.
     */
    private static final String INVALID_ANTISAMY_POLICY_FILE = "antisamy-InvalidPolicy.xml";

    /** A compliant AntiSamy policy file that is just located in a non-standard
     * place. We don't intend to * actually <i>use</i> it for anything other
     * than testing. Otherwise, it's mostly identical to the AntiSamy policy
     * file "src/test/resources/esapi/antisamy-esapi.xml".
     */
    private static final String ANTISAMY_POLICY_FILE_NONSTANDARD_LOCATION = "antisamy-esapi-CP.xml";

    private static class ConfOverride extends SecurityConfigurationWrapper {
        private String desiredReturnAction = "clean";
        private String desiredReturnConfigurationFile = null;

        ConfOverride(SecurityConfiguration orig, String desiredReturnAction, String desiredReturnConfigurationFile) {
            super(orig);
            this.desiredReturnAction = desiredReturnAction;
            this.desiredReturnConfigurationFile = desiredReturnConfigurationFile;
        }

        @Override
        public String getStringProp(String propName) {
            // Would it be better making this file a static import?
            if ( propName.equals( VALIDATOR_HTML_VALIDATION_ACTION ) ) {
                return desiredReturnAction;
            } else if ( propName.equals( VALIDATOR_HTML_VALIDATION_CONFIGURATION_FILE ) ) {
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
    }

    @Before
    public void setUp() throws Exception {
        ESAPI.override(
            new ConfOverride( ESAPI.securityConfiguration(), "throw", ANTISAMY_POLICY_FILE_NONSTANDARD_LOCATION )
        );
    }


    @Test
    public void checkPolicyExceptionWithBadConfig() throws Exception {
        ESAPI.override(null);
        thrownEx.expect(PolicyException.class);
        HTMLValidationRule.loadAntisamyPolicy(INVALID_ANTISAMY_POLICY_FILE);
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
                                // They are only listed here for completeness.
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

    /**
     * @deprecated because Validator.isValidSafeHTML is deprecated.
     * @see org.owasp.esapi.Validator#isValidSafeHTML(String,String,int,boolean)
     * @see org.owasp.esapi.Validator#isValidSafeHTML(String,String,int,boolean,org.owasp.esapi.ValidationErrorList)
     */
    @Deprecated
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
