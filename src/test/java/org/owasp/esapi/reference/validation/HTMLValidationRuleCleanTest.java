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
import org.owasp.esapi.EncoderConstants;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.SecurityConfigurationWrapper;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.ValidationRule;
import org.owasp.esapi.Validator;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.filters.SecurityWrapperRequest;
import org.owasp.esapi.reference.validation.HTMLValidationRule;

import org.junit.Test;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.After;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import static org.junit.Assert.*;

/**
 * The Class HTMLValidationRuleCleanTest.
 *
 * Based on original test cases, testGetValidSafeHTML() and
 * testIsValidSafeHTML() from ValidatorTest by
 *      Mike Fauzy (mike.fauzy@aspectsecurity.com) and
 *      Jeff Williams (jeff.williams@aspectsecurity.com)
 * that were originally part of src/test/java/org/owasp/esapi/reference/ValidatorTest.java.
 *
 * This class tests the cases where the new ESAPI.property
 *      Validator.HtmlValidationAction
 * is set to "clean", which causes certain calls to
 * ESAPI.validator().getValidSafeHTML() or ESAPI.validator().isValidSafeHTML()
 * to simply log a warning and return the cleansed (sanitizied) output rather
 * than throwing a ValidationException when certain unsafe input is
 * encountered.
 */
public class HTMLValidationRuleCleanTest {

	private static class ConfOverride extends SecurityConfigurationWrapper {
        private String desiredReturn = "clean";

		ConfOverride(SecurityConfiguration orig, String desiredReturn) {
			super(orig);
            this.desiredReturn = desiredReturn;
		}

		@Override
		public String getStringProp(String propName) {
            // Would it be better making this file a static import?
			if ( propName.equals( org.owasp.esapi.reference.DefaultSecurityConfiguration.VALIDATOR_HTML_VALIDATION_ACTION ) ) {
                return desiredReturn;
            } else {
                return super.getStringProp( propName );
            }
        }
    }


    /**
     * Default construstor that instantiates a new {@code HTMLValidationRule} test.
     */
    public HTMLValidationRuleCleanTest() {
    }

    @After
    public void tearDown() throws Exception {
        ESAPI.override(null);
    }

	@Before
    public void setUp() throws Exception {
		ESAPI.override(
			new ConfOverride( ESAPI.securityConfiguration(), "clean" )
		);

    }

    @Test
    public void testGetValidSafeHTML() throws Exception {
        System.out.println("getValidSafeHTML");
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();

        HTMLValidationRule rule = new HTMLValidationRule("test");
        ESAPI.validator().addRule(rule);

        assertEquals("Test.", ESAPI.validator().getRule("test").getValid("test", "Test. <script>alert(document.cookie)</script>"));

        String test1 = "<b>Jeff</b>";
        String result1 = instance.getValidSafeHTML("test", test1, 100, false, errors);
        assertEquals(test1, result1);

        String test2 = "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>";
        String result2 = instance.getValidSafeHTML("test", test2, 100, false, errors);
        assertEquals(test2, result2);

        String test3 = "Test. <script>alert(document.cookie)</script> Cookie :-)";
        assertEquals("Test.  Cookie :-)", rule.getSafe("test", test3));

        assertEquals("Test. &lt;<div>load=alert()</div>", rule.getSafe("test", "Test. <<div on<script></script>load=alert()"));
        assertEquals("Test. <div>b</div>", rule.getSafe("test", "Test. <div style={xss:expression(xss)}>b</div>"));
        assertEquals("Test. alert(document.cookie)", rule.getSafe("test", "Test. <s%00cript>alert(document.cookie)</script>"));
        assertEquals("Test. alert(document.cookie)", rule.getSafe("test", "Test. <s\tcript>alert(document.cookie)</script>"));
        assertEquals("Test. alert(document.cookie)", rule.getSafe("test", "Test. <s\tcript>alert(document.cookie)</script>"));
        // TODO: ENHANCE waiting for a way to validate text headed for an attribute for scripts
        // This would be nice to catch, but just looks like text to AntiSamy
        // assertFalse(instance.isValidSafeHTML("test", "\" onload=\"alert(document.cookie)\" "));
        // String result4 = instance.getValidSafeHTML("test", test4);
        // assertEquals("", result4);
    }

    // FIXME: Update CVE once we have a number for this.
    // Test to confirm that CVE-2022-xxxxx (TBD) is fixed. The cause of this was
    // from a subtle botched regex for 'onsiteURL' in all the versions of
    // antsamy-esapi.xml that had been there as far back as ESAPI 1.4!
    @Test
    public void testJavaScriptURL() throws Exception {
        System.out.println("testJavaScriptURL");

        String expectedSafeText = "This is safe from XSS. Trust us!";
        String badVoodoo = "<a href=\"javascript:alert(1)\">" + expectedSafeText + "</a>";
        Validator instance = ESAPI.validator();
        ValidationErrorList errorList = new ValidationErrorList();
        String result = instance.getValidSafeHTML("test", badVoodoo, 100, false, errorList);
        assertEquals( expectedSafeText, result );
    }

    // To confirm fix for CVE-2021-35043 in AntiSamy 1.6.5 and later. Actually,
    // it was never really "broken" in ESAPI's "default configuration" because it is
    // triggers an Intrusion Detection when it is checking the canonicalization.
    // This test assumes a standard default ESAPI.properties file. In
    // particular, the Intrusion Detector must be enabled (the default) and
    // Validator.HtmlValidationAction should be set to "throw" rather than "clean"
    @Test(expected=IntrusionException.class)
    public void testAntiSamyCVE_2021_35043Fixed() {
        System.out.println("testAntiSamyCVE_2021_35043Fixed");

        String expectedSafeText = "This is safe from XSS. Trust us!";

            // Translates to '<a href="javascript:x=1,alert("boom")".
        String badVoodoo = "<a href=\"javascript&#00058alert('boom')>" + expectedSafeText + "</a>";
        String result = null;
        Validator instance = ESAPI.validator();
        ValidationErrorList errorList = new ValidationErrorList();
        result = instance.getValidSafeHTML("test", badVoodoo, 200, false, errorList); // 
        assertEquals( expectedSafeText, result );
    }

    @Test
    public void testIsValidSafeHTML() {
        System.out.println("isValidSafeHTML");
        Validator instance = ESAPI.validator();

        assertTrue(instance.isValidSafeHTML("test", "<b>Jeff</b>", 100, false));
        assertTrue(instance.isValidSafeHTML("test", "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>", 100, false));
        assertTrue(instance.isValidSafeHTML("test", "Test. <script>alert(document.cookie)</script>", 100, false));
        assertTrue(instance.isValidSafeHTML("test", "Test. <div style={xss:expression(xss)}>", 100, false));
        assertTrue(instance.isValidSafeHTML("test", "Test. <s%00cript>alert(document.cookie)</script>", 100, false));
        assertTrue(instance.isValidSafeHTML("test", "Test. <s\tcript>alert(document.cookie)</script>", 100, false));
        assertTrue(instance.isValidSafeHTML("test", "Test. <s\r\n\0cript>alert(document.cookie)</script>", 100, false));

        // TODO: waiting for a way to validate text headed for an attribute for scripts
        // This would be nice to catch, but just looks like text to AntiSamy
        // assertFalse(instance.isValidSafeHTML("test", "\" onload=\"alert(document.cookie)\" "));
        ValidationErrorList errors = new ValidationErrorList();
        assertTrue(instance.isValidSafeHTML("test1", "<b>Jeff</b>", 100, false, errors));
        assertTrue(instance.isValidSafeHTML("test2", "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>", 100, false, errors));
        assertTrue(instance.isValidSafeHTML("test3", "Test. <script>alert(document.cookie)</script>", 100, false, errors));
        assertTrue(instance.isValidSafeHTML("test4", "Test. <div style={xss:expression(xss)}>", 100, false, errors));
        assertTrue(instance.isValidSafeHTML("test5", "Test. <s%00cript>alert(document.cookie)</script>", 100, false, errors));
        assertTrue(instance.isValidSafeHTML("test6", "Test. <s\tcript>alert(document.cookie)</script>", 100, false, errors));
        assertTrue(instance.isValidSafeHTML("test7", "Test. <s\r\n\0cript>alert(document.cookie)</script>", 100, false, errors));
        assertTrue(errors.size() == 0);

    }
    
    @Test
    public void testAntiSamyRegressionCDATAWithJavascriptURL() throws Exception {
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        String input = "<style/>b<![cdata[</style><a href=javascript:alert(1)>test";
		assertTrue(instance.isValidSafeHTML("test8", input, 100, false, errors));
		String expected = "b&lt;/style&gt;&lt;a href=javascript:alert(1)&gt;test";
		String output = instance.getValidSafeHTML("javascript Link", input, 250, false);
		assertEquals(expected, output);
		assertTrue(errors.size() == 0);
    }

    @Test
    public void testScriptTagAfterStyleClosing() throws Exception {
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        String input = "<select<style/>W<xmp<script>alert(1)</script>";
		assertTrue(instance.isValidSafeHTML("test9", input, 100, false, errors));
		String expected = "W&lt;script&gt;alert(1)&lt;/script&gt;";
		String output = instance.getValidSafeHTML("escaping style tag attack with script tag", input, 250, false);
		assertEquals(expected, output);
		assertTrue(errors.size() == 0);
    }

    @Test
    public void testOnfocusAfterStyleClosing() throws Exception {
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        String input = "<select<style/>k<input<</>input/onfocus=alert(1)>";
		assertTrue(instance.isValidSafeHTML("test10", input, 100, false, errors));
		String expected = "k&lt;input/onfocus=alert(1)&gt;";	// Suspicious??? Doesn't agree w/ AntiSamy test. FIXME?
		String output = instance.getValidSafeHTML("escaping style tag attack with onfocus attribute", input, 250, false);
		assertEquals(expected, output);
		assertTrue(errors.size() == 0);
    }

    // FIXME: This problem is a DoS issue that lies within Neko that is only available for Java 8 and later.
    // However, the latest version that is available for Java 7 is Neko 2.24. It is fixed in later versions
    // that are not available for JDK 7 though. The fix will just start using the one the latest Java 8 version
    // of AntiSamy is using and remove our <exclusion> and specific 2.24 dependency from our pom.xml and use whatever
    // AntiSamy provides. All we should need to do is that and remove the @Ignore annotation here.
    @Test
    @Ignore
    public void testNekoDOSWithAnHTMLComment() throws Exception {
    	/**
    	 * FIXME:  This unit test needs to pass before the next ESAPI release once ESAPI starts using JDK 8 as min JDK.
    	 */
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        String input = "<!--><?a/";
		assertTrue(instance.isValidSafeHTML("test11", input, 100, false, errors));
		String expected = "&#x3C;!--&#x3E;&#x3C;?a/";
		String output = instance.getValidSafeHTML("escaping style tag attack", input, 250, false);
		assertEquals(expected, output);
		assertTrue(errors.size() == 0);
    }
}
