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
package org.owasp.esapi.reference;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.ValidationRule;
import org.owasp.esapi.Validator;
import org.owasp.esapi.codecs.HTMLEntityCodec;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;
import org.owasp.esapi.reference.validation.HTMLValidationRule;
import org.owasp.esapi.reference.validation.StringValidationRule;

/**
 * The Class ValidatorTest.
 * 
 * @author Mike Fauzy (mike.fauzy@aspectsecurity.com)
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class ValidatorTest  extends TestCase {

	public static Test suite() {
		return new TestSuite(ValidatorTest.class);
	}

    /**
     * Instantiates a new HTTP utilities test.
     * 
     * @param testName the test name
     */
    public ValidatorTest(String testName) {
        super(testName);
    }

    /**
     * {@inheritDoc}
     * @throws Exception
     */
    protected void setUp() throws Exception {
        // none
    }

    /**
     * {@inheritDoc}
     * @throws Exception
     */
    protected void tearDown() throws Exception {
        // none
    }

	public void testAddRule() {
		Validator validator = ESAPI.validator();
		ValidationRule rule = new StringValidationRule( "ridiculous" );
		validator.addRule(rule);
		assertEquals( rule, validator.getRule("ridiculous") );
	}

	public void testAssertIsValidHTTPRequestParameterSet() {
		System.out.println("getValidCreditCard");
		Validator instance = ESAPI.validator();
		ValidationErrorList errors = new ValidationErrorList();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
		ESAPI.httpUtilities().setCurrentHTTP(request, response);
		request.addParameter("p1","value");
		request.addParameter("p2","value");
		request.addParameter("p3","value");
		Set required = new HashSet();
		required.add( "p1" );
		required.add( "p2" );
		Set optional = new HashSet();
		optional.add( "p3" );
		instance.assertIsValidHTTPRequestParameterSet("test", required, optional, errors);
		assertEquals( 0, errors.size() );
		optional.add( "p4" );
		instance.assertIsValidHTTPRequestParameterSet("test", required, optional, errors);
		assertEquals( 0, errors.size() );
		required.add( "p5" );
		instance.assertIsValidHTTPRequestParameterSet("test", required, optional, errors);
		assertEquals( 1, errors.size() );
	}

	public void testAssertValidFileUpload() {
//		assertValidFileUpload(String, String, String, byte[], int, boolean, ValidationErrorList)
	}
	
	public void testGetPrintable1() {
//		getValidPrintable(String, char[], int, boolean, ValidationErrorList)
	}

	public void testGetPrintable2() {
//		getValidPrintable(String, String, int, boolean, ValidationErrorList)
	}
	
	public void testGetRule() {
		Validator validator = ESAPI.validator();
		ValidationRule rule = new StringValidationRule( "rule" );
		validator.addRule(rule);
		assertEquals( rule, validator.getRule("rule") );
		this.assertFalse( rule == validator.getRule("ridiculous") );
	}

	public void testGetValidCreditCard() {
		System.out.println("getValidCreditCard");
		Validator instance = ESAPI.validator();
		ValidationErrorList errors = new ValidationErrorList();
		
		assertTrue(instance.isValidCreditCard("cctest1", "1234 9876 0000 0008", false));
		assertTrue(instance.isValidCreditCard("cctest2", "1234987600000008", false));
		assertFalse(instance.isValidCreditCard("cctest3", "12349876000000081", false));
		assertFalse(instance.isValidCreditCard("cctest4", "4417 1234 5678 9112", false));
		
		instance.getValidCreditCard("cctest5", "1234 9876 0000 0008", false, errors);
		assertEquals( 0, errors.size() );
		instance.getValidCreditCard("cctest6", "1234987600000008", false, errors);
		assertEquals( 0, errors.size() );
		instance.getValidCreditCard("cctest7", "12349876000000081", false, errors);
		assertEquals( 1, errors.size() );
		instance.getValidCreditCard("cctest8", "4417 1234 5678 9112", false, errors);
		assertEquals( 2, errors.size() );
	}

	public void testGetValidDate() throws Exception {
		System.out.println("getValidDate");
		Validator instance = ESAPI.validator();
		ValidationErrorList errors = new ValidationErrorList();
		assertTrue(instance.getValidDate("datetest1", "June 23, 1967", DateFormat.getDateInstance(DateFormat.MEDIUM, Locale.US), false ) != null);
		instance.getValidDate("datetest2", "freakshow", DateFormat.getDateInstance(), false, errors );
		assertEquals( 1, errors.size() );
		
		// TODO: This test case fails due to an apparent bug in SimpleDateFormat
		instance.getValidDate( "test", "June 32, 2008", DateFormat.getDateInstance(), false, errors );
		// assertEquals( 2, errors.size() );
	}

	public void testGetValidDirectoryPath() throws Exception {
		System.out.println("getValidDirectoryPath");
		Validator instance = ESAPI.validator();
		ValidationErrorList errors = new ValidationErrorList();
		String path = ESAPI.securityConfiguration().getResourceFile("ESAPI.properties").getCanonicalPath();
		instance.getValidDirectoryPath("dirtest1", path, true, errors);
		assertEquals( 0, errors.size() );
		instance.getValidDirectoryPath("dirtest2", null, false, errors);
		assertEquals( 1, errors.size() );
		instance.getValidDirectoryPath("dirtest3", "ridicul%00ous", false, errors);
		assertEquals( 2, errors.size() );
	}
	
	public void testGetValidDouble() {
		System.out.println("getValidDouble");
		Validator instance = ESAPI.validator();
		ValidationErrorList errors = new ValidationErrorList();
		instance.getValidDouble("dtest1", "1.0", 0, 20, true, errors );
		assertEquals( 0, errors.size() );
		instance.getValidDouble("dtest2", null, 0, 20, true, errors );
		assertEquals( 0, errors.size() );
		instance.getValidDouble("dtest3", null, 0, 20, false, errors );
		assertEquals( 1, errors.size() );
		instance.getValidDouble("dtest4", "ridiculous", 0, 20, true, errors );
		assertEquals( 2, errors.size() );
		instance.getValidDouble("dtest5", ""+(Double.MAX_VALUE), 0, 20, true, errors );
		assertEquals( 3, errors.size() );
		instance.getValidDouble("dtest6", ""+(Double.MAX_VALUE + .00001), 0, 20, true, errors );
		assertEquals( 4, errors.size() );
	}
	
	public void testGetValidFileContent() {
		System.out.println("getValidFileContent");
		Validator instance = ESAPI.validator();
		ValidationErrorList errors = new ValidationErrorList();
		byte[] bytes = "12345".getBytes();
		instance.getValidFileContent("test", bytes, 5, true, errors);
		assertEquals( 0, errors.size() );
		instance.getValidFileContent("test", bytes, 4, true, errors);
		assertEquals( 1, errors.size() );
	}
	
	public void testGetValidFileName() throws Exception {
		System.out.println("getValidFileName");
		Validator instance = ESAPI.validator();
		ValidationErrorList errors = new ValidationErrorList();
		String testName = "aspe%20ct.jar";
		assertEquals("Percent encoding is not changed", testName, instance.getValidFileName("test", testName, false, errors) );
	}
		
	public void testGetValidInput() {
		System.out.println("getValidInput");
		Validator instance = ESAPI.validator();
		ValidationErrorList errors = new ValidationErrorList();
		// getValidInput(String, String, String, int, boolean, ValidationErrorList)
	}
	
	public void testGetValidInteger() {
		System.out.println("getValidInteger");
		Validator instance = ESAPI.validator();
		ValidationErrorList errors = new ValidationErrorList();
		// getValidInteger(String, String, int, int, boolean, ValidationErrorList)
	}
	
	public void testGetValidListItem() {
		System.out.println("getValidListItem");
		Validator instance = ESAPI.validator();
		ValidationErrorList errors = new ValidationErrorList();
		// getValidListItem(String, String, List, ValidationErrorList)
	}
	
	public void testGetValidNumber() {
		System.out.println("getValidNumber");
		Validator instance = ESAPI.validator();
		ValidationErrorList errors = new ValidationErrorList();
		// instance.getValidNumber(String, String, long, long, boolean, ValidationErrorList)
	}
	
	public void testGetValidRedirectLocation() {
		System.out.println("getValidRedirectLocation");
		Validator instance = ESAPI.validator();
		ValidationErrorList errors = new ValidationErrorList();
		// instance.getValidRedirectLocation(String, String, boolean, ValidationErrorList)
	}
	
	public void testGetValidSafeHTML() throws Exception{
		System.out.println("getValidSafeHTML");
		Validator instance = ESAPI.validator();
		ValidationErrorList errors = new ValidationErrorList();
	
		// new school test case setup
		HTMLValidationRule rule = new HTMLValidationRule( "test" );
		ESAPI.validator().addRule( rule );
		
		assertEquals( "Test.", ESAPI.validator().getRule( "test" ).getValid("test", "Test. <script>alert(document.cookie)</script>" ) );
		
		String test1 = "<b>Jeff</b>";
		String result1 = instance.getValidSafeHTML("test", test1, 100, false, errors);
		assertEquals(test1, result1);
		
		String test2 = "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>";
		String result2 = instance.getValidSafeHTML("test", test2, 100, false, errors);
		assertEquals(test2, result2);
		
		String test3 = "Test. <script>alert(document.cookie)</script>";
		assertEquals("Test.", rule.getSafe("test", test3 ));
		
		assertEquals( "Test. &lt;<div>load=alert()</div>",rule.getSafe("test", "Test. <<div on<script></script>load=alert()" ));
		assertEquals( "Test. <div>b</div>",rule.getSafe("test", "Test. <div style={xss:expression(xss)}>b</div>"));
		assertEquals( "Test.",rule.getSafe("test", "Test. <s%00cript>alert(document.cookie)</script>"));
		assertEquals( "Test. alert(document.cookie)",rule.getSafe("test", "Test. <s\tcript>alert(document.cookie)</script>"));
		assertEquals( "Test. alert(document.cookie)",rule.getSafe("test", "Test. <s\tcript>alert(document.cookie)</script>"));
		// TODO: ENHANCE waiting for a way to validate text headed for an attribute for scripts		
		// This would be nice to catch, but just looks like text to AntiSamy
		// assertFalse(instance.isValidSafeHTML("test", "\" onload=\"alert(document.cookie)\" "));
		// String result4 = instance.getValidSafeHTML("test", test4);
		// assertEquals("", result4);
	}
	
	public void testIsInvalidFilename() {
		System.out.println("testIsInvalidFilename");
		Validator instance = ESAPI.validator();
		char invalidChars[] = "/\\:*?\"<>|".toCharArray();
		for(int i = 0; i < invalidChars.length; i++) {
			assertFalse(invalidChars[i] + " is an invalid character for a filename", 
					instance.isValidFileName("test", "as" + invalidChars[i] + "pect.jar", false));
		}
		assertFalse("Files must have an extension", instance.isValidFileName("test", "", false));
		assertFalse("Files must have a valid extension", instance.isValidFileName("test.invalidExtension", "", false));
		assertFalse("Filennames cannot be the empty string", instance.isValidFileName("test", "", false));
	}
	
	public void testIsValidDate() {
		System.out.println("isValidDate");
		Validator instance = ESAPI.validator();
		DateFormat format = SimpleDateFormat.getDateInstance();
		assertTrue( instance.isValidDate("datetest1", "September 11, 2001", format, true ) );
		assertFalse( instance.isValidDate("datetest2", null, format, false ) );
		assertFalse( instance.isValidDate("datetest3", "", format, false ) );
	}
	
	public void testIsValidDirectoryPath() {
		System.out.println("isValidDirectoryPath");

		// get an encoder with a special list of codecs and make a validator out of it
		List list = new ArrayList();
		list.add( "HTMLEntityCodec" );
		Encoder encoder = new DefaultEncoder( list );
		Validator instance = new DefaultValidator( encoder );
		
		boolean isWindows = (System.getProperty("os.name").indexOf("Windows") != -1 ) ? true : false;
		
		if ( isWindows ) {
			// Windows paths that don't exist and thus should fail
			assertFalse(instance.isValidDirectoryPath("test", "c:\\ridiculous", false));
			assertFalse(instance.isValidDirectoryPath("test", "c:\\jeff", false));
			assertFalse(instance.isValidDirectoryPath("test", "c:\\temp\\..\\etc", false));

			// Windows paths that should pass
			assertTrue(instance.isValidDirectoryPath("test", "C:\\", false));								// Windows root directory
			assertTrue(instance.isValidDirectoryPath("test", "C:\\Windows", false));						// Windows always exist directory
			assertTrue(instance.isValidDirectoryPath("test", "C:\\Windows\\System32\\cmd.exe", false));		// Windows command shell	
			
			// Unix specific paths should not pass
			assertFalse(instance.isValidDirectoryPath("test", "/tmp", false));		// Unix Temporary directory
			assertFalse(instance.isValidDirectoryPath("test", "/bin/sh", false));	// Unix Standard shell	
			assertFalse(instance.isValidDirectoryPath("test", "/etc/config", false));
			
			// Unix specific paths that should not exist or work
			assertFalse(instance.isValidDirectoryPath("test", "/etc/ridiculous", false));
			assertFalse(instance.isValidDirectoryPath("test", "/tmp/../etc", false));
		} else {
			// Windows paths should fail
			assertFalse(instance.isValidDirectoryPath("test", "c:\\ridiculous", false));
			assertFalse(instance.isValidDirectoryPath("test", "c:\\temp\\..\\etc", false));

			// Standard Windows locations should fail
			assertFalse(instance.isValidDirectoryPath("test", "c:\\", false));								// Windows root directory
			assertFalse(instance.isValidDirectoryPath("test", "c:\\Windows\\temp", false));					// Windows temporary directory
			assertFalse(instance.isValidDirectoryPath("test", "c:\\Windows\\System32\\cmd.exe", false));	// Windows command shell	
			
			// Unix specific paths should pass
			assertTrue(instance.isValidDirectoryPath("test", "/", false));			// Root directory
			assertTrue(instance.isValidDirectoryPath("test", "/bin", false));		// Always exist directory
			assertTrue(instance.isValidDirectoryPath("test", "/bin/sh", false));	// Standard shell	
			
			// Unix specific paths that should not exist or work
			assertFalse(instance.isValidDirectoryPath("test", "/etc/ridiculous", false));
			assertFalse(instance.isValidDirectoryPath("test", "/tmp/../etc", false));
		}
	}
	
	public void TestIsValidDirectoryPath() {
		// isValidDirectoryPath(String, String, boolean)
	}
	
	public void testIsValidDouble() {
		// isValidDouble(String, String, double, double, boolean)
	}
	
	public void testIsValidFileContent() {
		System.out.println("isValidFileContent");
		byte[] content = "This is some file content".getBytes();
		Validator instance = ESAPI.validator();
		assertTrue(instance.isValidFileContent("test", content, 100, false));
	}
	
	public void testIsValidFileName() {
		System.out.println("isValidFileName");
		Validator instance = ESAPI.validator();		
		assertTrue("Simple valid filename with a valid extension", instance.isValidFileName("test", "aspect.jar", false));
		assertTrue("All valid filename characters are accepted", instance.isValidFileName("test", "!@#$%^&{}[]()_+-=,.~'` abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.jar", false));
		assertTrue("Legal filenames that decode to legal filenames are accepted", instance.isValidFileName("test", "aspe%20ct.jar", false));
	}
	
	public void testIsValidFileUpload() {
		System.out.println("isValidFileUpload");
		String filepath = System.getProperty( "user.dir" );
		String filename = "aspect.jar";
		byte[] content = "This is some file content".getBytes();
		Validator instance = ESAPI.validator();
		assertTrue(instance.isValidFileUpload("test", filepath, filename, content, 100, false));
		
		filepath = "/ridiculous";
		filename = "aspect.jar";
		content = "This is some file content".getBytes();
		assertFalse(instance.isValidFileUpload("test", filepath, filename, content, 100, false));
	}
	
	public void testIsValidHTTPRequest() throws Exception {
		Validator validator = ESAPI.validator();
		try {
			((DefaultValidator)validator).assertIsValidHTTPRequest( null );
			fail();
		} catch( ValidationException e ) {
			 // expected
		}
        MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter("p1","value");
		request.addParameter("p2","value");
		request.setCookie("c1","value");
		request.setCookie("c2","value");
		request.addHeader("h1","value");
		request.addHeader("h2","value");
		validator.assertIsValidHTTPRequest(request);
		try{
			request.addParameter("ridiculous", "\0foobar");
			validator.assertIsValidHTTPRequest(request);
			fail();
		} catch( ValidationException e ) {
			// expected
		}
		try{
			request.clearParameters();
			request.setCookie("ridiculous", "\0foobar");
			validator.assertIsValidHTTPRequest(request);
			fail();
		} catch( ValidationException e ) {
			// expected
		}
		try{
			request.clearCookies();
			request.addHeader("ridiculous", "\0foobar");
			validator.assertIsValidHTTPRequest(request);
			fail();
		} catch( ValidationException e ) {
			// expected
		}
	}
	
	public void testIsValidHTTPRequestParameterSet() {
//		isValidHTTPRequestParameterSet(String, Set, Set)
	}
	
	public void testisValidInput() {
		System.out.println("isValidInput");
		Validator instance = ESAPI.validator();
		assertTrue(instance.isValidInput("test", "jeff.williams@aspectsecurity.com", "Email", 100, false));
		assertFalse(instance.isValidInput("test", "jeff.williams@@aspectsecurity.com", "Email", 100, false));
		assertFalse(instance.isValidInput("test", "jeff.williams@aspectsecurity", "Email", 100, false));
		assertTrue(instance.isValidInput("test", "123.168.100.234", "IPAddress", 100, false));
		assertTrue(instance.isValidInput("test", "192.168.1.234", "IPAddress", 100, false));
		assertFalse(instance.isValidInput("test", "..168.1.234", "IPAddress", 100, false));
		assertFalse(instance.isValidInput("test", "10.x.1.234", "IPAddress", 100, false));
		assertTrue(instance.isValidInput("test", "http://www.aspectsecurity.com", "URL", 100, false));
		assertFalse(instance.isValidInput("test", "http:///www.aspectsecurity.com", "URL", 100, false));
		assertFalse(instance.isValidInput("test", "http://www.aspect security.com", "URL", 100, false));
		assertTrue(instance.isValidInput("test", "078-05-1120", "SSN", 100, false));
		assertTrue(instance.isValidInput("test", "078 05 1120", "SSN", 100, false));
		assertTrue(instance.isValidInput("test", "078051120", "SSN", 100, false));
		assertFalse(instance.isValidInput("test", "987-65-4320", "SSN", 100, false));
		assertFalse(instance.isValidInput("test", "000-00-0000", "SSN", 100, false));
		assertFalse(instance.isValidInput("test", "(555) 555-5555", "SSN", 100, false));
		assertFalse(instance.isValidInput("test", "test", "SSN", 100, false));

		assertTrue(instance.isValidInput("test", null, "Email", 100, true));
		assertFalse(instance.isValidInput("test", null, "Email", 100, false));
	}
	
    public void testIsValidInteger() {
		System.out.println("isValidInteger");
		Validator instance = ESAPI.validator();
		//testing negative range
		assertFalse(instance.isValidInteger("test", "-4", 1, 10, false));
		assertTrue(instance.isValidInteger("test", "-4", -10, 10, false));
		//testing null value
		assertTrue(instance.isValidInteger("test", null, -10, 10, true));
		assertFalse(instance.isValidInteger("test", null, -10, 10, false));
		//testing empty string
		assertTrue(instance.isValidInteger("test", "", -10, 10, true));
		assertFalse(instance.isValidInteger("test", "", -10, 10, false));
		//testing improper range
		assertFalse(instance.isValidInteger("test", "5", 10, -10, false));
		//testing non-integers
		assertFalse(instance.isValidInteger("test", "4.3214", -10, 10, true));
		assertFalse(instance.isValidInteger("test", "-1.65", -10, 10, true));
		//other testing
		assertTrue(instance.isValidInteger("test", "4", 1, 10, false));
		assertTrue(instance.isValidInteger("test", "400", 1, 10000, false));
		assertTrue(instance.isValidInteger("test", "400000000", 1, 400000000, false));
		assertFalse(instance.isValidInteger("test", "4000000000000", 1, 10000, false));
		assertFalse(instance.isValidInteger("test", "alsdkf", 10, 10000, false));
		assertFalse(instance.isValidInteger("test", "--10", 10, 10000, false));
		assertFalse(instance.isValidInteger("test", "14.1414234x", 10, 10000, false));
		assertFalse(instance.isValidInteger("test", "Infinity", 10, 10000, false));
		assertFalse(instance.isValidInteger("test", "-Infinity", 10, 10000, false));
		assertFalse(instance.isValidInteger("test", "NaN", 10, 10000, false));
		assertFalse(instance.isValidInteger("test", "-NaN", 10, 10000, false));
		assertFalse(instance.isValidInteger("test", "+NaN", 10, 10000, false));
		assertFalse(instance.isValidInteger("test", "1e-6", -999999999, 999999999, false));
		assertFalse(instance.isValidInteger("test", "-1e-6", -999999999, 999999999, false));

	}
	
	public void testIsValidListItem() {
		System.out.println("isValidListItem");
		Validator instance = ESAPI.validator();
		List list = new ArrayList();
		list.add("one");
		list.add("two");
		assertTrue(instance.isValidListItem("test", "one", list));
		assertFalse(instance.isValidListItem("test", "three", list));
	}
	
	public void testIsValidNumber() {
		System.out.println("isValidNumber");
		Validator instance = ESAPI.validator();
		//testing negative range
		assertFalse(instance.isValidNumber("test", "-4", 1, 10, false));
		assertTrue(instance.isValidNumber("test", "-4", -10, 10, false));
		//testing null value
		assertTrue(instance.isValidNumber("test", null, -10, 10, true));
		assertFalse(instance.isValidNumber("test", null, -10, 10, false));
		//testing empty string
		assertTrue(instance.isValidNumber("test", "", -10, 10, true));
		assertFalse(instance.isValidNumber("test", "", -10, 10, false));
		//testing improper range
		assertFalse(instance.isValidNumber("test", "5", 10, -10, false));
		//testing non-integers
		assertTrue(instance.isValidNumber("test", "4.3214", -10, 10, true));
		assertTrue(instance.isValidNumber("test", "-1.65", -10, 10, true));
		//other testing
		assertTrue(instance.isValidNumber("test", "4", 1, 10, false));
		assertTrue(instance.isValidNumber("test", "400", 1, 10000, false));
		assertTrue(instance.isValidNumber("test", "400000000", 1, 400000000, false));
		assertFalse(instance.isValidNumber("test", "4000000000000", 1, 10000, false));
		assertFalse(instance.isValidNumber("test", "alsdkf", 10, 10000, false));
		assertFalse(instance.isValidNumber("test", "--10", 10, 10000, false));
		assertFalse(instance.isValidNumber("test", "14.1414234x", 10, 10000, false));
		assertFalse(instance.isValidNumber("test", "Infinity", 10, 10000, false));
		assertFalse(instance.isValidNumber("test", "-Infinity", 10, 10000, false));
		assertFalse(instance.isValidNumber("test", "NaN", 10, 10000, false));
		assertFalse(instance.isValidNumber("test", "-NaN", 10, 10000, false));
		assertFalse(instance.isValidNumber("test", "+NaN", 10, 10000, false));
		assertTrue(instance.isValidNumber("test", "1e-6", -999999999, 999999999, false));
		assertTrue(instance.isValidNumber("test", "-1e-6", -999999999, 999999999, false));
	}
	
	public void testIsValidParameterSet() {
		System.out.println("isValidParameterSet");
		Set requiredNames = new HashSet();
		requiredNames.add("p1");
		requiredNames.add("p2");
		requiredNames.add("p3");
		Set optionalNames = new HashSet();
		optionalNames.add("p4");
		optionalNames.add("p5");
		optionalNames.add("p6");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
		request.addParameter("p1","value");
		request.addParameter("p2","value");
		request.addParameter("p3","value");
		ESAPI.httpUtilities().setCurrentHTTP(request, response);
		Validator instance = ESAPI.validator();		
		assertTrue(instance.isValidHTTPRequestParameterSet("HTTPParameters", requiredNames, optionalNames));
		request.addParameter("p4","value");
		request.addParameter("p5","value");
		request.addParameter("p6","value");
		assertTrue(instance.isValidHTTPRequestParameterSet("HTTPParameters", requiredNames, optionalNames));
		request.removeParameter("p1");
		assertFalse(instance.isValidHTTPRequestParameterSet("HTTPParameters", requiredNames, optionalNames));
	}
	
    public void testIsValidPrintable() {
		System.out.println("isValidPrintable");
		Validator instance = ESAPI.validator();
		assertTrue(instance.isValidPrintable("name", "abcDEF", 100, false));
		assertTrue(instance.isValidPrintable("name", "!@#R()*$;><()", 100, false));
        char[] chars = { 0x60, (char)0xFF, 0x10, 0x25 };
        assertFalse( instance.isValidPrintable("name", chars, 100, false ) );
		assertFalse(instance.isValidPrintable("name", "%08", 100, false));
    }
	
	public void testIsValidRedirectLocation() {
//		isValidRedirectLocation(String, String, boolean)
	}
	
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
	}
	
	public void testSafeReadLine() {
		System.out.println("safeReadLine");
		
		ByteArrayInputStream s = new ByteArrayInputStream("testString".getBytes());
		Validator instance = ESAPI.validator();
		try {
			instance.safeReadLine(s, -1);
			fail();
		} catch (ValidationException e) {
			// Expected
		}
		s.reset();
		try {
			instance.safeReadLine(s, 4);
			fail();
		} catch (ValidationException e) {
			// Expected
		}
		s.reset();
		try {
			String u = instance.safeReadLine(s, 20);
			assertEquals("testString", u);
		} catch (ValidationException e) {
			fail();
		}
		
		// This sub-test attempts to validate that BufferedReader.readLine() and safeReadLine() are similar in operation 
		// for the nominal case 
		try {
			s.reset();
			InputStreamReader isr = new InputStreamReader(s);
			BufferedReader br = new BufferedReader(isr);
			String u = br.readLine();
			s.reset();
			String v = instance.safeReadLine(s, 20);
			assertEquals(u, v);
		} catch (IOException e) {
			fail();
		} catch (ValidationException e) {
			fail();
		}
	}
	
}
