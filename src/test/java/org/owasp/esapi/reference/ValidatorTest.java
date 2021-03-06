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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.http.Cookie;

import org.junit.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.EncoderConstants;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.ValidationRule;
import org.owasp.esapi.Validator;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.filters.SecurityWrapperRequest;
import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;
import org.owasp.esapi.reference.validation.StringValidationRule;
import org.owasp.esapi.util.TestUtils;


/**
 * The Class ValidatorTest.
 *
 * @author Mike Fauzy (mike.fauzy@aspectsecurity.com)
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class ValidatorTest {
	
    private static final String PREFERRED_ENCODING = "UTF-8";

    @Test
    public void testAddRule() {
        Validator validator = ESAPI.validator();
        ValidationRule rule = new StringValidationRule("ridiculous");
        validator.addRule(rule);
        assertEquals(rule, validator.getRule("ridiculous"));
    }

    @Test
    public void testAssertValidFileUpload() {
        //		assertValidFileUpload(String, String, String, byte[], int, boolean, ValidationErrorList)
    }

    @Test
    public void testGetPrintable1() {
        //		getValidPrintable(String, char[], int, boolean, ValidationErrorList)
    }

    @Test
    public void testGetPrintable2() {
        //		getValidPrintable(String, String, int, boolean, ValidationErrorList)
    }

    @Test
    public void testGetRule() {
        Validator validator = ESAPI.validator();
        ValidationRule rule = new StringValidationRule("rule");
        validator.addRule(rule);
        assertEquals(rule, validator.getRule("rule"));
        assertFalse(rule == validator.getRule("ridiculous"));
    }

    @Test
    public void testGetValidCreditCard() {
        System.out.println("getValidCreditCard");
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();

        assertTrue(instance.isValidCreditCard("cctest1", "1234 9876 0000 0008", false));
        assertTrue(instance.isValidCreditCard("cctest2", "1234987600000008", false));
        assertFalse(instance.isValidCreditCard("cctest3", "12349876000000081", false));
        assertFalse(instance.isValidCreditCard("cctest4", "4417 1234 5678 9112", false));

        instance.getValidCreditCard("cctest5", "1234 9876 0000 0008", false, errors);
        assertEquals(0, errors.size());
        instance.getValidCreditCard("cctest6", "1234987600000008", false, errors);
        assertEquals(0, errors.size());
        instance.getValidCreditCard("cctest7", "12349876000000081", false, errors);
        assertEquals(1, errors.size());
        instance.getValidCreditCard("cctest8", "4417 1234 5678 9112", false, errors);
        assertEquals(2, errors.size());

        assertTrue(instance.isValidCreditCard("cctest1", "1234 9876 0000 0008", false, errors));
        assertTrue(errors.size()==2);
        assertTrue(instance.isValidCreditCard("cctest2", "1234987600000008", false, errors));
        assertTrue(errors.size()==2);
        assertFalse(instance.isValidCreditCard("cctest3", "12349876000000081", false, errors));
        assertTrue(errors.size()==3);
        assertFalse(instance.isValidCreditCard("cctest4", "4417 1234 5678 9112", false, errors));
        assertTrue(errors.size()==4);
    }

    @Test
    public void testGetValidDirectoryPath() throws Exception {
        System.out.println("getValidDirectoryPath");
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        // find a directory that exists
        File parent = new File("/");
        String path = ESAPI.securityConfiguration().getResourceFile("ESAPI.properties").getParentFile().getCanonicalPath();
        instance.getValidDirectoryPath("dirtest1", path, parent, true, errors);
        assertEquals(0, errors.size());
        instance.getValidDirectoryPath("dirtest2", null, parent, false, errors);
        assertEquals(1, errors.size());
        instance.getValidDirectoryPath("dirtest3", "ridicul%00ous", parent, false, errors);
        assertEquals(2, errors.size());
    }

    @Test
    public void testGetValidDouble() {
        System.out.println("getValidDouble");
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        instance.getValidDouble("dtest1", "1.0", 0, 20, true, errors);
        assertEquals(0, errors.size());
        instance.getValidDouble("dtest2", null, 0, 20, true, errors);
        assertEquals(0, errors.size());
        instance.getValidDouble("dtest3", null, 0, 20, false, errors);
        assertEquals(1, errors.size());
        instance.getValidDouble("dtest4", "ridiculous", 0, 20, true, errors);
        assertEquals(2, errors.size());
        instance.getValidDouble("dtest5", "" + (Double.MAX_VALUE), 0, 20, true, errors);
        assertEquals(3, errors.size());
        instance.getValidDouble("dtest6", "" + (Double.MAX_VALUE + .00001), 0, 20, true, errors);
        assertEquals(4, errors.size());
    }

    @Test
    public void testGetValidFileContent() {
        System.out.println("getValidFileContent");
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        byte[] bytes = null;
        try {
            bytes = "12345".getBytes(PREFERRED_ENCODING);
        }
        catch (UnsupportedEncodingException e) {
            fail(PREFERRED_ENCODING + " not a supported encoding?!?!!");
        }
        instance.getValidFileContent("test", bytes, 5, true, errors);
        assertEquals(0, errors.size());
        instance.getValidFileContent("test", bytes, 4, true, errors);
        assertEquals(1, errors.size());
    }

    @Test
    public void testGetValidFileName() throws Exception {
        System.out.println("getValidFileName");
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        String testName = "aspe%20ct.txt";
        assertEquals("Percent encoding is not changed", testName, instance.getValidFileName("test", testName, ESAPI.securityConfiguration().getAllowedFileExtensions(), false, errors));
    }

    @Test
    public void testGetValidInput(){
        System.out.println("getValidInput");
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        // instance.getValidInput(String, String, String, int, boolean, ValidationErrorList)
    }

    @Test
    public void testGetValidInteger() {
        System.out.println("getValidInteger");
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        // instance.getValidInteger(String, String, int, int, boolean, ValidationErrorList)
    }

    @Test
    public void testGetValidListItem() {
        System.out.println("getValidListItem");
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        // instance.getValidListItem(String, String, List, ValidationErrorList)
    }

    @Test
    public void testGetValidNumber() {
        System.out.println("getValidNumber");
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        // instance.getValidNumber(String, String, long, long, boolean, ValidationErrorList)
    }

    @Test
    public void testGetValidRedirectLocation() {
        System.out.println("getValidRedirectLocation");
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        // instance.getValidRedirectLocation(String, String, boolean, ValidationErrorList)
    }

    //      Test split out and moved to HTMLValidationRuleLogsTest.java & HTMLValidationRuleThrowsTest.java
    // @Test
    // public void testGetValidSafeHTML() throws Exception {

    @Test
    public void testIsInvalidFilename() {
        System.out.println("testIsInvalidFilename");
        Validator instance = ESAPI.validator();
        char invalidChars[] = "/\\:*?\"<>|".toCharArray();
        for (int i = 0; i < invalidChars.length; i++) {
            assertFalse(invalidChars[i] + " is an invalid character for a filename",
                    instance.isValidFileName("test", "as" + invalidChars[i] + "pect.txt", false));
        }
        assertFalse("Files must have an extension", instance.isValidFileName("test", "", false));
        assertFalse("Files must have a valid extension", instance.isValidFileName("test.invalidExtension", "", false));
        assertFalse("Filennames cannot be the empty string", instance.isValidFileName("test", "", false));
    }

    // Reset 'parent' depending on where Windows is installed so running off
    // different drive doesn't break tests in testIsValidDirectoryPath().
    private File resetParentForWindows(String sysRoot) throws IOException {
        if ( sysRoot == null ) {
            return new File("C:\\");
        }
        int bslash = sysRoot.indexOf('\\');
        String winRoot = null;
        if ( bslash == -1 || sysRoot.length() < 4 ) {
            winRoot = "C:\\";   // Well, that's a first. Just pretend it's under C:\.
        } else {
            winRoot = sysRoot.substring(0, bslash + 1);
        }
        return new File( winRoot );
    }

    @Test
    public void testIsValidDirectoryPath() throws IOException {
        System.out.println("isValidDirectoryPath");

        // get an encoder with a special list of codecs and make a validator out of it
        List list = new ArrayList();
        list.add("HTMLEntityCodec");
        Encoder encoder = new DefaultEncoder(list);
        Validator instance = new DefaultValidator(encoder);

        boolean isWindows = (System.getProperty("os.name").indexOf("Windows") != -1) ? true : false;
        File parent = new File("/");

        ValidationErrorList errors = new ValidationErrorList();

        if (isWindows) {
            String sysRoot = new File(System.getenv("SystemRoot")).getCanonicalPath();

            // Reset 'parent' in case running from drive other than where Windows installed.
            parent = resetParentForWindows( sysRoot );

            // Windows paths that don't exist and thus should fail
            assertFalse(instance.isValidDirectoryPath("test", "c:\\ridiculous", parent, false));
            assertFalse(instance.isValidDirectoryPath("test", "c:\\jeff", parent, false));
            assertFalse(instance.isValidDirectoryPath("test", "c:\\temp\\..\\etc", parent, false));

            // Windows paths
            assertTrue(instance.isValidDirectoryPath("test", "C:\\", parent, false));                        // Windows root directory
            assertTrue(instance.isValidDirectoryPath("test", sysRoot, parent, false));                  // Windows always exist directory
            assertFalse(instance.isValidDirectoryPath("test", sysRoot + "\\System32\\cmd.exe", parent, false));      // Windows command shell

            // Unix specific paths should not pass
            assertFalse(instance.isValidDirectoryPath("test", "/tmp", parent, false));      // Unix Temporary directory
            assertFalse(instance.isValidDirectoryPath("test", "/etc", parent, false));   // Unix Standard shell
            assertFalse(instance.isValidDirectoryPath("test", "/etc/config", parent, false));

            // Unix specific paths that should not exist or work
            assertFalse(instance.isValidDirectoryPath("test", "/etc/ridiculous", parent, false));
            assertFalse(instance.isValidDirectoryPath("test", "/tmp/../etc", parent, false));

            assertFalse(instance.isValidDirectoryPath("test1", "c:\\ridiculous", parent, false, errors));
            assertTrue(errors.size()==1);
            assertFalse(instance.isValidDirectoryPath("test2", "c:\\jeff", parent, false, errors));
            assertTrue(errors.size()==2);
            assertFalse(instance.isValidDirectoryPath("test3", "c:\\temp\\..\\etc", parent, false, errors));
            assertTrue(errors.size()==3);

            // Windows paths
            assertTrue(instance.isValidDirectoryPath("test4", "C:\\", parent, false, errors));                        // Windows root directory
            assertTrue(errors.size()==3);
            assertTrue(instance.isValidDirectoryPath("test5", sysRoot, parent, false, errors));                  // Windows always exist directory
            assertTrue(errors.size()==3);
            assertFalse(instance.isValidDirectoryPath("test6", sysRoot + "\\System32\\cmd.exe", parent, false, errors));      // Windows command shell
            assertTrue(errors.size()==4);

            // Unix specific paths should not pass
            assertFalse(instance.isValidDirectoryPath("test7", "/tmp", parent, false, errors));      // Unix Temporary directory
            assertTrue(errors.size()==5);
            assertFalse(instance.isValidDirectoryPath("test8", "/bin/sh", parent, false, errors));   // Unix Standard shell
            assertTrue(errors.size()==6);
            assertFalse(instance.isValidDirectoryPath("test9", "/etc/config", parent, false, errors));
            assertTrue(errors.size()==7);

            // Unix specific paths that should not exist or work
            assertFalse(instance.isValidDirectoryPath("test10", "/etc/ridiculous", parent, false, errors));
            assertTrue(errors.size()==8);
            assertFalse(instance.isValidDirectoryPath("test11", "/tmp/../etc", parent, false, errors));
            assertTrue(errors.size()==9);

        } else {
            // Windows paths should fail
            assertFalse(instance.isValidDirectoryPath("test", "c:\\ridiculous", parent, false));
            assertFalse(instance.isValidDirectoryPath("test", "c:\\temp\\..\\etc", parent, false));

            // Standard Windows locations should fail
            assertFalse(instance.isValidDirectoryPath("test", "c:\\", parent, false));                        // Windows root directory
            assertFalse(instance.isValidDirectoryPath("test", "c:\\Windows\\temp", parent, false));               // Windows temporary directory
            assertFalse(instance.isValidDirectoryPath("test", "c:\\Windows\\System32\\cmd.exe", parent, false));   // Windows command shell

            // Unix specific paths should pass
            assertTrue(instance.isValidDirectoryPath("test", "/", parent, false));         // Root directory
                // Unfortunately, on MacOS both "/etc" and "/var" are symlinks
                // to "/private/etc" and "/private/var" respectively, and "/sbin"
                // and "/bin" sometimes are symlinks on certain *nix OSs, so we need
                // to special case MacOS here.
            boolean isMac = System.getProperty("os.name").toLowerCase().contains("mac");
            String testDirNotSymLink = isMac ? "/private" : "/etc";
            assertTrue(instance.isValidDirectoryPath("test", testDirNotSymLink, parent, false));      // Always exist directory

            // Unix specific paths that should not exist or work
            assertFalse(instance.isValidDirectoryPath("test", "/bin/sh", parent, false));   // Standard shell, not dir
            assertFalse(instance.isValidDirectoryPath("test", "/etc/ridiculous", parent, false));
            assertFalse(instance.isValidDirectoryPath("test", "/tmp/../etc", parent, false));

            // Windows paths should fail
            assertFalse(instance.isValidDirectoryPath("test1", "c:\\ridiculous", parent, false, errors));
            assertTrue(errors.size()==1);
            assertFalse(instance.isValidDirectoryPath("test2", "c:\\temp\\..\\etc", parent, false, errors));
            assertTrue(errors.size()==2);

            // Standard Windows locations should fail
            assertFalse(instance.isValidDirectoryPath("test3", "c:\\", parent, false, errors));                        // Windows root directory
            assertTrue(errors.size()==3);
            assertFalse(instance.isValidDirectoryPath("test4", "c:\\Windows\\temp", parent, false, errors));               // Windows temporary directory
            assertTrue(errors.size()==4);
            assertFalse(instance.isValidDirectoryPath("test5", "c:\\Windows\\System32\\cmd.exe", parent, false, errors));   // Windows command shell
            assertTrue(errors.size()==5);

            // Unix specific paths should pass
            assertTrue(instance.isValidDirectoryPath("test6", "/", parent, false, errors));         // Root directory
            assertTrue(errors.size()==5);
                // Note, we used to say that about '/bin', but Ubuntu 20.x
                // changed '/bin' to a sym link to 'usr/bin'. We can't use '/etc'
                // because under MacOS, that is a sym link to 'private/etc'.
            assertTrue(instance.isValidDirectoryPath("test7", "/dev", parent, false, errors));      // Always exist directory
            assertTrue(errors.size()==5);

            // Unix specific paths that should not exist or work
            assertFalse(instance.isValidDirectoryPath("test8", "/bin/sh", parent, false, errors));   // Standard shell, not dir
            assertTrue(errors.size()==6);
            assertFalse(instance.isValidDirectoryPath("test9", "/etc/ridiculous", parent, false, errors));
            assertTrue(errors.size()==7);
            assertFalse(instance.isValidDirectoryPath("test10", "/tmp/../etc", parent, false, errors));
            assertTrue(errors.size()==8);
        }
    }

    @Test
    public void TestIsValidDirectoryPath() {
        // isValidDirectoryPath(String, String, boolean)
    }

    @Test
    public void testIsValidDouble() {
        // isValidDouble(String, String, double, double, boolean)
    	Validator instance = ESAPI.validator();
    	ValidationErrorList errors = new ValidationErrorList();
    	//testing negative range
        assertFalse(instance.isValidDouble("test1", "-4", 1, 10, false, errors));
        assertTrue(errors.size() == 1);
        assertTrue(instance.isValidDouble("test2", "-4", -10, 10, false, errors));
        assertTrue(errors.size() == 1);
        //testing null value
        assertTrue(instance.isValidDouble("test3", null, -10, 10, true, errors));
        assertTrue(errors.size() == 1);
        assertFalse(instance.isValidDouble("test4", null, -10, 10, false, errors));
        assertTrue(errors.size() == 2);
        //testing empty string
        assertTrue(instance.isValidDouble("test5", "", -10, 10, true, errors));
        assertTrue(errors.size() == 2);
        assertFalse(instance.isValidDouble("test6", "", -10, 10, false, errors));
        assertTrue(errors.size() == 3);
        //testing improper range
        assertFalse(instance.isValidDouble("test7", "50.0", 10, -10, false, errors));
        assertTrue(errors.size() == 4);
        //testing non-integers
        assertTrue(instance.isValidDouble("test8", "4.3214", -10, 10, true, errors));
        assertTrue(errors.size() == 4);
        assertTrue(instance.isValidDouble("test9", "-1.65", -10, 10, true, errors));
        assertTrue(errors.size() == 4);
        //other testing
        assertTrue(instance.isValidDouble("test10", "4", 1, 10, false, errors));
        assertTrue(errors.size() == 4);
        assertTrue(instance.isValidDouble("test11", "400", 1, 10000, false, errors));
        assertTrue(errors.size() == 4);
        assertTrue(instance.isValidDouble("test12", "400000000", 1, 400000000, false, errors));
        assertTrue(errors.size() == 4);
        assertFalse(instance.isValidDouble("test13", "4000000000000", 1, 10000, false, errors));
        assertTrue(errors.size() == 5);
        assertFalse(instance.isValidDouble("test14", "alsdkf", 10, 10000, false, errors));
        assertTrue(errors.size() == 6);
        assertFalse(instance.isValidDouble("test15", "--10", 10, 10000, false, errors));
        assertTrue(errors.size() == 7);
        assertFalse(instance.isValidDouble("test16", "14.1414234x", 10, 10000, false, errors));
        assertTrue(errors.size() == 8);
        assertFalse(instance.isValidDouble("test17", "Infinity", 10, 10000, false, errors));
        assertTrue(errors.size() == 9);
        assertFalse(instance.isValidDouble("test18", "-Infinity", 10, 10000, false, errors));
        assertTrue(errors.size() == 10);
        assertFalse(instance.isValidDouble("test19", "NaN", 10, 10000, false, errors));
        assertTrue(errors.size() == 11);
        assertFalse(instance.isValidDouble("test20", "-NaN", 10, 10000, false, errors));
        assertTrue(errors.size() == 12);
        assertFalse(instance.isValidDouble("test21", "+NaN", 10, 10000, false, errors));
        assertTrue(errors.size() == 13);
        assertTrue(instance.isValidDouble("test22", "1e-6", -999999999, 999999999, false, errors));
        assertTrue(errors.size() == 13);
        assertTrue(instance.isValidDouble("test23", "-1e-6", -999999999, 999999999, false, errors));
        assertTrue(errors.size() == 13);
    }

    @Test
    public void testIsValidFileContent() {
        System.out.println("isValidFileContent");
        byte[] content = null;
        try {
            content = "This is some file content".getBytes(PREFERRED_ENCODING);
        }
        catch (UnsupportedEncodingException e) {
            fail(PREFERRED_ENCODING + " not a supported encoding?!?!!!");
        }
        Validator instance = ESAPI.validator();
        assertTrue(instance.isValidFileContent("test", content, 100, false));
    }

    @Test
    public void testIsValidFileName() {
        System.out.println("isValidFileName");
        Validator instance = ESAPI.validator();
        assertTrue("Simple valid filename with a valid extension", instance.isValidFileName("test", "aspect.txt", false));
        assertTrue("All valid filename characters are accepted", instance.isValidFileName("test", "!@#$%^&{}[]()_+-=,.~'` abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.txt", false));
        assertTrue("Legal filenames that decode to legal filenames are accepted", instance.isValidFileName("test", "aspe%20ct.txt", false));

        ValidationErrorList errors = new ValidationErrorList();
        assertTrue("Simple valid filename with a valid extension", instance.isValidFileName("test", "aspect.txt", false, errors));
        assertTrue("All valid filename characters are accepted", instance.isValidFileName("test", "!@#$%^&{}[]()_+-=,.~'` abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.txt", false, errors));
        assertTrue("Legal filenames that decode to legal filenames are accepted", instance.isValidFileName("test", "aspe%20ct.txt", false, errors));
        assertTrue(errors.size() == 0);
    }

    @Test
    public void testIsValidFileUpload() throws IOException {
        System.out.println("isValidFileUpload");
        String filepath = new File(System.getProperty("user.dir")).getCanonicalPath();
        String filename = "aspect.txt";
        File parent = new File("/").getCanonicalFile();
        ValidationErrorList errors = new ValidationErrorList();
        byte[] content = null;
        try {
            content = "This is some file content".getBytes(PREFERRED_ENCODING);
        }
        catch (UnsupportedEncodingException e) {
            fail(PREFERRED_ENCODING + " not a supported encoding?!?!!!");
        }
        Validator instance = ESAPI.validator();
        assertTrue(instance.isValidFileUpload("test", filepath, filename, parent, content, 100, false));
        assertTrue(instance.isValidFileUpload("test", filepath, filename, parent, content, 100, false, errors));
        assertTrue(errors.size() == 0);

        filepath = "/ridiculous";
        filename = "aspect.txt";
        try {
            content = "This is some file content".getBytes(PREFERRED_ENCODING);
        }
        catch (UnsupportedEncodingException e) {
            fail(PREFERRED_ENCODING + " not a supported encoding?!?!!!");
        }
        assertFalse(instance.isValidFileUpload("test", filepath, filename, parent, content, 100, false));
        assertFalse(instance.isValidFileUpload("test", filepath, filename, parent, content, 100, false, errors));
        assertTrue(errors.size() == 1);
    }

    @Test
    public void testIsValidHTTPRequestParameterSet() throws Exception{
    }

    @Test
    public void testisValidInput() {
        System.out.println("isValidInput");
        Validator instance = ESAPI.validator();
        assertTrue(instance.isValidInput("test", "jeff.williams@aspectsecurity.com", "Email", 100, false));
        assertFalse(instance.isValidInput("test", "jeff.williams@@aspectsecurity.com", "Email", 100, false));
        assertFalse(instance.isValidInput("test", "jeff.williams@aspectsecurity", "Email", 100, false));
        assertTrue(instance.isValidInput("test", "jeff.wil'liams@aspectsecurity.com", "Email", 100, false));
        assertTrue(instance.isValidInput("test", "jeff.wil''liams@aspectsecurity.com", "Email", 100, false));
        assertTrue(instance.isValidInput("test", "123.168.100.234", "IPAddress", 100, false));
        assertTrue(instance.isValidInput("test", "192.168.1.234", "IPAddress", 100, false));
        assertFalse(instance.isValidInput("test", "..168.1.234", "IPAddress", 100, false));
        assertFalse(instance.isValidInput("test", "10.x.1.234", "IPAddress", 100, false));
        assertTrue(instance.isValidInput("test", "http://www.aspectsecurity.com", "URL", 100, false));
        assertTrue(instance.isValidInput("test", "http://www.aspectsecurity.com", "URL", 100, false));
        assertFalse(instance.isValidInput("test", "http://www.aspect security.com", "URL", 100, false));
        assertTrue(instance.isValidInput("test", "078-05-1120", "SSN", 100, false));
        assertTrue(instance.isValidInput("test", "078 05 1120", "SSN", 100, false));
        assertTrue(instance.isValidInput("test", "078051120", "SSN", 100, false));
        assertFalse(instance.isValidInput("test", "987-65-4320", "SSN", 100, false));
        assertFalse(instance.isValidInput("test", "000-00-0000", "SSN", 100, false));
        assertFalse(instance.isValidInput("test", "(555) 555-5555", "SSN", 100, false));
        assertFalse(instance.isValidInput("test", "test", "SSN", 100, false));
        assertTrue(instance.isValidInput("test", "jeffWILLIAMS123", "HTTPParameterValue", 100, false));
        assertTrue(instance.isValidInput("test", "jeff .-/+=@_ WILLIAMS", "HTTPParameterValue", 100, false));
        // Removed per Issue 116 - The '*' character is valid as a parameter character
//        assertFalse(instance.isValidInput("test", "jeff*WILLIAMS", "HTTPParameterValue", 100, false))
        System.err.println(instance.isValidInput("test", "jeff\\WILLIAMS", "HTTPParameterValue", 100, false));;
        assertFalse(instance.isValidInput("test", "jeff^WILLIAMS", "HTTPParameterValue", 100, false));
        assertFalse(instance.isValidInput("test", "jeff\\WILLIAMS", "HTTPParameterValue", 100, false));
        
        assertTrue(instance.isValidInput("test", null, "Email", 100, true));
        assertFalse(instance.isValidInput("test", null, "Email", 100, false));

        ValidationErrorList errors = new ValidationErrorList();

        assertTrue(instance.isValidInput("test1", "jeff.williams@aspectsecurity.com", "Email", 100, false, errors));
        assertTrue(errors.size()==0);
        assertFalse(instance.isValidInput("test2", "jeff.williams@@aspectsecurity.com", "Email", 100, false, errors));
        assertTrue(errors.size()==1);
        assertFalse(instance.isValidInput("test3", "jeff.williams@aspectsecurity", "Email", 100, false, errors));
        assertTrue(errors.size()==2);
        assertTrue(instance.isValidInput("test4", "jeff.wil'liams@aspectsecurity.com", "Email", 100, false, errors));
        assertTrue(errors.size()==2);
        assertTrue(instance.isValidInput("test5", "jeff.wil''liams@aspectsecurity.com", "Email", 100, false, errors));
        assertTrue(errors.size()==2);
        assertTrue(instance.isValidInput("test6", "123.168.100.234", "IPAddress", 100, false, errors));
        assertTrue(errors.size()==2);
        assertTrue(instance.isValidInput("test7", "192.168.1.234", "IPAddress", 100, false, errors));
        assertTrue(errors.size()==2);
        assertFalse(instance.isValidInput("test8", "..168.1.234", "IPAddress", 100, false, errors));
        assertTrue(errors.size()==3);
        assertFalse(instance.isValidInput("test9", "10.x.1.234", "IPAddress", 100, false, errors));
        assertTrue(errors.size()==4);
        assertTrue(instance.isValidInput("test10", "http://www.aspectsecurity.com", "URL", 100, false, errors));
        assertTrue(errors.size()==4);
//        This is getting flipped to true because it is no longer the validator regex's job to enforce URL structure.
        assertTrue(instance.isValidInput("test11", "http:///www.aspectsecurity.com", "URL", 100, false, errors));
        assertTrue(errors.size()==4);
        assertFalse(instance.isValidInput("test12", "http://www.aspect security.com", "URL", 100, false, errors));
        assertTrue(errors.size()==5);
        assertTrue(instance.isValidInput("test13", "078-05-1120", "SSN", 100, false, errors));
        assertTrue(errors.size()==5);
        assertTrue(instance.isValidInput("test14", "078 05 1120", "SSN", 100, false, errors));
        assertTrue(errors.size()==5);
        assertTrue(instance.isValidInput("test15", "078051120", "SSN", 100, false, errors));
        assertTrue(errors.size()==5);
        assertFalse(instance.isValidInput("test16", "987-65-4320", "SSN", 100, false, errors));
        assertTrue(errors.size()==6);
        assertFalse(instance.isValidInput("test17", "000-00-0000", "SSN", 100, false, errors));
        assertTrue(errors.size()==7);
        assertFalse(instance.isValidInput("test18", "(555) 555-5555", "SSN", 100, false, errors));
        assertTrue(errors.size()==8);
        assertFalse(instance.isValidInput("test19", "test", "SSN", 100, false, errors));
        assertTrue(errors.size()==9);
        assertTrue(instance.isValidInput("test20", "jeffWILLIAMS123", "HTTPParameterValue", 100, false, errors));
        assertTrue(errors.size()==9);
        assertTrue(instance.isValidInput("test21", "jeff .-/+=@_ WILLIAMS", "HTTPParameterValue", 100, false, errors));
        assertTrue(errors.size()==9);
        // Removed per Issue 116 - The '*' character is valid as a parameter character
//        assertFalse(instance.isValidInput("test", "jeff*WILLIAMS", "HTTPParameterValue", 100, false));
        assertFalse(instance.isValidInput("test22", "jeff^WILLIAMS", "HTTPParameterValue", 100, false, errors));
        assertTrue(errors.size()==10);
        assertFalse(instance.isValidInput("test23", "jeff\\WILLIAMS", "HTTPParameterValue", 100, false, errors));
        assertTrue(errors.size()==11);

        assertTrue(instance.isValidInput("test", null, "Email", 100, true, errors));
        assertFalse(instance.isValidInput("test", null, "Email", 100, false, errors));
    }

    @Test
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
        assertFalse(instance.isValidInteger("test", "50", 10, -10, false));
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

        ValidationErrorList errors = new ValidationErrorList();
        //testing negative range
        assertFalse(instance.isValidInteger("test1", "-4", 1, 10, false, errors));
        assertTrue(errors.size() == 1);
        assertTrue(instance.isValidInteger("test2", "-4", -10, 10, false, errors));
        assertTrue(errors.size() == 1);
        //testing null value
        assertTrue(instance.isValidInteger("test3", null, -10, 10, true, errors));
        assertTrue(errors.size() == 1);
        assertFalse(instance.isValidInteger("test4", null, -10, 10, false, errors));
        assertTrue(errors.size() == 2);
        //testing empty string
        assertTrue(instance.isValidInteger("test5", "", -10, 10, true, errors));
        assertTrue(errors.size() == 2);
        assertFalse(instance.isValidInteger("test6", "", -10, 10, false, errors));
        assertTrue(errors.size() == 3);
        //testing improper range
        assertFalse(instance.isValidInteger("test7", "50", 10, -10, false, errors));
        assertTrue(errors.size() == 4);
        //testing non-integers
        assertFalse(instance.isValidInteger("test8", "4.3214", -10, 10, true, errors));
        assertTrue(errors.size() == 5);
        assertFalse(instance.isValidInteger("test9", "-1.65", -10, 10, true, errors));
        assertTrue(errors.size() == 6);
        //other testing
        assertTrue(instance.isValidInteger("test10", "4", 1, 10, false, errors));
        assertTrue(errors.size() == 6);
        assertTrue(instance.isValidInteger("test11", "400", 1, 10000, false, errors));
        assertTrue(errors.size() == 6);
        assertTrue(instance.isValidInteger("test12", "400000000", 1, 400000000, false, errors));
        assertTrue(errors.size() == 6);
        assertFalse(instance.isValidInteger("test13", "4000000000000", 1, 10000, false, errors));
        assertTrue(errors.size() == 7);
        assertFalse(instance.isValidInteger("test14", "alsdkf", 10, 10000, false, errors));
        assertTrue(errors.size() == 8);
        assertFalse(instance.isValidInteger("test15", "--10", 10, 10000, false, errors));
        assertTrue(errors.size() == 9);
        assertFalse(instance.isValidInteger("test16", "14.1414234x", 10, 10000, false, errors));
        assertTrue(errors.size() == 10);
        assertFalse(instance.isValidInteger("test17", "Infinity", 10, 10000, false, errors));
        assertTrue(errors.size() == 11);
        assertFalse(instance.isValidInteger("test18", "-Infinity", 10, 10000, false, errors));
        assertTrue(errors.size() == 12);
        assertFalse(instance.isValidInteger("test19", "NaN", 10, 10000, false, errors));
        assertTrue(errors.size() == 13);
        assertFalse(instance.isValidInteger("test20", "-NaN", 10, 10000, false, errors));
        assertTrue(errors.size() == 14);
        assertFalse(instance.isValidInteger("test21", "+NaN", 10, 10000, false, errors));
        assertTrue(errors.size() == 15);
        assertFalse(instance.isValidInteger("test22", "1e-6", -999999999, 999999999, false, errors));
        assertTrue(errors.size() == 16);
        assertFalse(instance.isValidInteger("test23", "-1e-6", -999999999, 999999999, false, errors));
        assertTrue(errors.size() == 17);

    }

    @Test
    public void testIsValidListItem() {
        System.out.println("isValidListItem");
        Validator instance = ESAPI.validator();
        List list = new ArrayList();
        list.add("one");
        list.add("two");
        assertTrue(instance.isValidListItem("test", "one", list));
        assertFalse(instance.isValidListItem("test", "three", list));

        ValidationErrorList errors = new ValidationErrorList();
        assertTrue(instance.isValidListItem("test1", "one", list, errors));
        assertTrue(errors.size()==0);
        assertFalse(instance.isValidListItem("test2", "three", list, errors));
        assertTrue(errors.size()==1);
    }

    @Test
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

        ValidationErrorList errors = new ValidationErrorList();
      //testing negative range
        assertFalse(instance.isValidNumber("test1", "-4", 1, 10, false, errors));
        assertTrue(errors.size()==1);
        assertTrue(instance.isValidNumber("test2", "-4", -10, 10, false, errors));
        assertTrue(errors.size()==1);
        //testing null value
        assertTrue(instance.isValidNumber("test3", null, -10, 10, true, errors));
        assertTrue(errors.size()==1);
        assertFalse(instance.isValidNumber("test4", null, -10, 10, false, errors));
        assertTrue(errors.size()==2);
        //testing empty string
        assertTrue(instance.isValidNumber("test5", "", -10, 10, true, errors));
        assertTrue(errors.size()==2);
        assertFalse(instance.isValidNumber("test6", "", -10, 10, false, errors));
        assertTrue(errors.size()==3);
        //testing improper range
        assertFalse(instance.isValidNumber("test7", "5", 10, -10, false, errors));
        assertTrue(errors.size()==4);
        //testing non-integers
        assertTrue(instance.isValidNumber("test8", "4.3214", -10, 10, true, errors));
        assertTrue(errors.size()==4);
        assertTrue(instance.isValidNumber("test9", "-1.65", -10, 10, true, errors));
        assertTrue(errors.size()==4);
        //other testing
        assertTrue(instance.isValidNumber("test10", "4", 1, 10, false, errors));
        assertTrue(errors.size()==4);
        assertTrue(instance.isValidNumber("test11", "400", 1, 10000, false, errors));
        assertTrue(errors.size()==4);
        assertTrue(instance.isValidNumber("test12", "400000000", 1, 400000000, false, errors));
        assertTrue(errors.size()==4);
        assertFalse(instance.isValidNumber("test13", "4000000000000", 1, 10000, false, errors));
        assertTrue(errors.size()==5);
        assertFalse(instance.isValidNumber("test14", "alsdkf", 10, 10000, false, errors));
        assertTrue(errors.size()==6);
        assertFalse(instance.isValidNumber("test15", "--10", 10, 10000, false, errors));
        assertTrue(errors.size()==7);
        assertFalse(instance.isValidNumber("test16", "14.1414234x", 10, 10000, false, errors));
        assertTrue(errors.size()==8);
        assertFalse(instance.isValidNumber("test17", "Infinity", 10, 10000, false, errors));
        assertTrue(errors.size()==9);
        assertFalse(instance.isValidNumber("test18", "-Infinity", 10, 10000, false, errors));
        assertTrue(errors.size()==10);
        assertFalse(instance.isValidNumber("test19", "NaN", 10, 10000, false, errors));
        assertTrue(errors.size()==11);
        assertFalse(instance.isValidNumber("test20", "-NaN", 10, 10000, false, errors));
        assertTrue(errors.size()==12);
        assertFalse(instance.isValidNumber("test21", "+NaN", 10, 10000, false, errors));
        assertTrue(errors.size()==13);
        assertTrue(instance.isValidNumber("test22", "1e-6", -999999999, 999999999, false, errors));
        assertTrue(errors.size()==13);
        assertTrue(instance.isValidNumber("test23", "-1e-6", -999999999, 999999999, false, errors));
        assertTrue(errors.size()==13);
    }

    @Test
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
        request.addParameter("p1", "value");
        request.addParameter("p2", "value");
        request.addParameter("p3", "value");
        ESAPI.httpUtilities().setCurrentHTTP(request, response);
        Validator instance = ESAPI.validator();
        ValidationErrorList errors = new ValidationErrorList();
        assertTrue(instance.isValidHTTPRequestParameterSet("HTTPParameters", request, requiredNames, optionalNames));
        assertTrue(instance.isValidHTTPRequestParameterSet("HTTPParameters", request, requiredNames, optionalNames,errors));
        assertTrue(errors.size()==0);
        request.addParameter("p4", "value");
        request.addParameter("p5", "value");
        request.addParameter("p6", "value");
        assertTrue(instance.isValidHTTPRequestParameterSet("HTTPParameters", request, requiredNames, optionalNames));
        assertTrue(instance.isValidHTTPRequestParameterSet("HTTPParameters", request, requiredNames, optionalNames, errors));
        assertTrue(errors.size()==0);
        request.removeParameter("p1");
        assertFalse(instance.isValidHTTPRequestParameterSet("HTTPParameters", request, requiredNames, optionalNames));
        assertFalse(instance.isValidHTTPRequestParameterSet("HTTPParameters", request, requiredNames, optionalNames, errors));
        assertTrue(errors.size() ==1);
    }

    @Test
    public void testIsValidPrintable() {
        System.out.println("isValidPrintable");
        Validator instance = ESAPI.validator();
        assertTrue(instance.isValidPrintable("name", "abcDEF", 100, false));
        assertTrue(instance.isValidPrintable("name", "!@#R()*$;><()", 100, false));
        char[] chars = {0x60, (char) 0xFF, 0x10, 0x25};
        assertFalse(instance.isValidPrintable("name", chars, 100, false));
        assertFalse(instance.isValidPrintable("name", "%08", 100, false));

        ValidationErrorList errors = new ValidationErrorList();
        assertTrue(instance.isValidPrintable("name1", "abcDEF", 100, false, errors));
        assertTrue(errors.size()==0);
        assertTrue(instance.isValidPrintable("name2", "!@#R()*$;><()", 100, false, errors));
        assertTrue(errors.size()==0);
        assertFalse(instance.isValidPrintable("name3", chars, 100, false, errors));
        assertTrue(errors.size()==1);
        assertFalse(instance.isValidPrintable("name4", "%08", 100, false, errors));
        assertTrue(errors.size()==2);

    }

    @Test
    public void testIsValidRedirectLocation() {
        //		isValidRedirectLocation(String, String, boolean)
    }

    //      Test split out and moved to HTMLValidationRuleLogsTest.java & HTMLValidationRuleThrowsTest.java
    // @Test
    //public void testIsValidSafeHTML() {

    @Test
    public void testSafeReadLine() {
        System.out.println("safeReadLine");

        byte[] bytes = null;
        try {
            bytes = "testString".getBytes(PREFERRED_ENCODING);
        }
        catch (UnsupportedEncodingException e1) {
            fail(PREFERRED_ENCODING + " not a supported encoding?!?!!!");
        }
        ByteArrayInputStream s = new ByteArrayInputStream(bytes);
        Validator instance = ESAPI.validator();
        try {
            instance.safeReadLine(s, -1);
            fail();
        }
        catch (ValidationException e) {
            // Expected
        }
        s.reset();
        try {
            instance.safeReadLine(s, 4);
            fail();
        }
        catch (ValidationException e) {
            // Expected
        }
        s.reset();
        try {
            String u = instance.safeReadLine(s, 20);
            assertEquals("testString", u);
        }
        catch (ValidationException e) {
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
        }
        catch (IOException e) {
            fail();
        }
        catch (ValidationException e) {
            fail();
        }
    }

    @Test
    public void testIssue82_SafeString_Bad_Regex() {
        Validator instance = ESAPI.validator();
        try {
            instance.getValidInput("address", "55 main st. pasadena ak", "SafeString", 512, false);
        }
        catch (ValidationException e) {
            fail(e.getLogMessage());
        }
    }

    @Test
    public void testGetParameterMap() {
//testing Validator.HTTPParameterName and Validator.HTTPParameterValue
        MockHttpServletRequest request = new MockHttpServletRequest();
        SecurityWrapperRequest safeRequest = new SecurityWrapperRequest(request);
//an example of a parameter from displaytag, should pass
        request.addParameter("d-49653-p", "pass");
        request.addParameter("<img ", "fail");
        request.addParameter(TestUtils.generateStringOfLength(32), "pass");
        request.addParameter(TestUtils.generateStringOfLength(33), "fail");
        assertEquals(safeRequest.getParameterMap().size(), 2);
        assertNull(safeRequest.getParameterMap().get("<img"));
        assertNull(safeRequest.getParameterMap().get(TestUtils.generateStringOfLength(33)));
    }

    @Test
    public void testGetParameterNames() {
//testing Validator.HTTPParameterName
        MockHttpServletRequest request = new MockHttpServletRequest();
        SecurityWrapperRequest safeRequest = new SecurityWrapperRequest(request);
//an example of a parameter from displaytag, should pass
        request.addParameter("d-49653-p", "pass");
        request.addParameter("<img ", "fail");
        request.addParameter(TestUtils.generateStringOfLength(32), "pass");
        request.addParameter(TestUtils.generateStringOfLength(33), "fail");
        assertEquals(Collections.list(safeRequest.getParameterNames()).size(), 2);
    }

    @Test
    public void testGetParameter() {
//testing Validator.HTTPParameterValue
        MockHttpServletRequest request = new MockHttpServletRequest();
        SecurityWrapperRequest safeRequest = new SecurityWrapperRequest(request);
        request.addParameter("p1", "Alice");
        request.addParameter("p2", "bob@alice.com");//mail-address from a submit-form
        request.addParameter("p3", ESAPI.authenticator().generateStrongPassword());
        request.addParameter("p4", new String(EncoderConstants.CHAR_PASSWORD_SPECIALS));
        //TODO - I think this should fair request.addParameter("p5", "�������?����"); //some special characters from european languages;
        request.addParameter("f1", "<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>");
        request.addParameter("f2", "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>");
        request.addParameter("f3", "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>");
        for (int i = 1; i <= 4; i++) {
            assertTrue(safeRequest.getParameter("p" + i).equals(request.getParameter("p" + i)));
        }
        for (int i = 1; i <= 2; i++) {
        	boolean testResult = false;
        	try {
        		testResult = safeRequest.getParameter("f" + i).equals(request.getParameter("f" + i));
        	} catch (NullPointerException npe) {
        		//the test is this block SHOULD fail. a NPE is an acceptable failure state
        		testResult = false; //redundant, just being descriptive here
        	}
        	assertFalse(testResult);
        }
        assertNull(safeRequest.getParameter("e1"));

        //This is revealing problems with Jeff's original SafeRequest
        //mishandling of the AllowNull parameter. I'm adding a new Google code
        //bug to track this.
        //
        //assertNotNull(safeRequest.getParameter("e1", false));
    }

    @Test
    public void testGetCookies() {
//testing Validator.HTTPCookieName and Validator.HTTPCookieValue
        MockHttpServletRequest request = new MockHttpServletRequest();
        SecurityWrapperRequest safeRequest = new SecurityWrapperRequest(request);
//should support a base64-encode value
        request.setCookie("p1", "34=VJhjv7jiDu7tsdLrQQ2KcUwpfWUM2_mBae6UA8ttk4wBHdxxQ-1IBxyCOn3LWE08SDhpnBcJ7N5Vze48F2t8a1R_hXt7PX1BvgTM0pn-T4JkqGTm_tlmV4RmU3GT-dgn");
        request.setCookie("f1", "<A HREF=\"http://66.102.7.147/\">XSS</A>");
        request.setCookie("load-balancing", "pass");
        request.setCookie("'bypass", "fail");
        Cookie[] cookies = safeRequest.getCookies();
        assertEquals(cookies[0].getValue(), request.getCookies()[0].getValue());
        assertEquals(cookies[1].getName(), request.getCookies()[2].getName());
        assertTrue(cookies.length == 2);
    }

    @Test
    public void testGetHeader() {
//testing Validator.HTTPHeaderValue
        MockHttpServletRequest request = new MockHttpServletRequest();
        SecurityWrapperRequest safeRequest = new SecurityWrapperRequest(request);
        request.addHeader("p1", "login");
        request.addHeader("f1", "<A HREF=\"http://0x42.0x0000066.0x7.0x93/\">XSS</A>");
        request.addHeader("p2", TestUtils.generateStringOfLength(200));   // Upper limit increased from 150 -> 200, GitHub issue #351
        request.addHeader("f2", TestUtils.generateStringOfLength(4097));
        assertEquals(safeRequest.getHeader("p1"), request.getHeader("p1"));
        assertEquals(safeRequest.getHeader("p2"), request.getHeader("p2"));
        assertFalse(safeRequest.getHeader("f1").equals(request.getHeader("f1")));
        assertFalse(safeRequest.getHeader("f2").equals(request.getHeader("f2")));
        assertNull(safeRequest.getHeader("p3"));
    }
    
    @Test
    public void testHeaderLengthChecks(){
    	Validator v = ESAPI.validator();
    	SecurityConfiguration sc = ESAPI.securityConfiguration();
    	assertFalse(v.isValidInput("addHeader", TestUtils.generateStringOfLength(257), "HTTPHeaderName", sc.getIntProp("HttpUtilities.MaxHeaderNameSize"), false));
    	assertFalse(v.isValidInput("addHeader", TestUtils.generateStringOfLength(4097), "HTTPHeaderValue", sc.getIntProp("HttpUtilities.MaxHeaderValueSize"), false));
    }

    @Test
    public void testGetHeaderNames() {
//testing Validator.HTTPHeaderName
        MockHttpServletRequest request = new MockHttpServletRequest();
        SecurityWrapperRequest safeRequest = new SecurityWrapperRequest(request);
        request.addHeader("d-49653-p", "pass");
        request.addHeader("<img ", "fail");
            // Note: Max length in ESAPI.properties as per
            // Validator.HTTPHeaderName regex is 256, but upper
            // bound is configurable by the property HttpUtilities.MaxHeaderNameSize
        SecurityConfiguration sc = ESAPI.securityConfiguration();
        request.addHeader(TestUtils.generateStringOfLength(255), "pass");
        request.addHeader(TestUtils.generateStringOfLength(257), "fail");
        assertEquals(2, Collections.list(safeRequest.getHeaderNames()).size());
    }

    @Test
    public void testGetQueryString() {
//testing Validator.HTTPQueryString
        MockHttpServletRequest request = new MockHttpServletRequest();
        SecurityWrapperRequest safeRequest = new SecurityWrapperRequest(request);
        request.setQueryString("mail=bob@alice.com&passwd=" + new String(EncoderConstants.CHAR_PASSWORD_SPECIALS));// TODO, fix this + "&special=�����");
        assertEquals(safeRequest.getQueryString(), request.getQueryString());
        request.setQueryString("mail=<IMG SRC=\"jav\tascript:alert('XSS');\">");
        assertFalse(safeRequest.getQueryString().equals(request.getQueryString()));
        request.setQueryString("mail=bob@alice.com-passwd=johny");
        assertTrue(safeRequest.getQueryString().equals(request.getQueryString()));
        request.setQueryString("mail=bob@alice.com-passwd=johny&special"); //= is missing!
        assertFalse(safeRequest.getQueryString().equals(request.getQueryString()));
    }

    @Test
    public void testGetRequestURI() {
//testing Validator.HTTPURI
        MockHttpServletRequest request = new MockHttpServletRequest();
        SecurityWrapperRequest safeRequest = new SecurityWrapperRequest(request);
        try {
            request.setRequestURI("/app/page.jsp");
        } catch (UnsupportedEncodingException ignored) {
        }
        assertEquals(safeRequest.getRequestURI(), request.getRequestURI());
    }

    @Test
    public void testGetContextPath() {
        // Root Context Path ("")
        assertTrue(ESAPI.validator().isValidInput("HTTPContextPath", "", "HTTPContextPath", 512, true));
        // Deployed Context Path ("/context")
        assertTrue(ESAPI.validator().isValidInput("HTTPContextPath", "/context", "HTTPContextPath", 512, true));
        // Fail-case - URL Splitting
        assertFalse(ESAPI.validator().isValidInput("HTTPContextPath", "/\\nGET http://evil.com", "HTTPContextPath", 512, true));
    }
    
    @Test
    public void testGmailEmailAddress(){
    	Validator v = ESAPI.validator();
    	assertTrue(v.isValidInput("Gmail", "Darth+Sidious@gmail.com", "Gmail", 512, false));
    	assertTrue(v.isValidInput("Gmail", "Darth.Sidious@gmail.com", "Gmail", 512, false));
    }
    
    @Test
    public void testGetValidUri(){
    	Validator v = ESAPI.validator();
    	assertFalse(v.isValidURI("test", "http://core-jenkins.scansafe.cisco.com/佐贺诺伦-^ńörén.jpg", false));
    }
    
    @Test
    public void testGetValidUriNullInput(){
    	Validator v = ESAPI.validator();
    	boolean isValid = v.isValidURI("test", null, true);
    	assertTrue(isValid);
    }
    
    @Test
    public void testRegex(){
    	Validator v = ESAPI.validator();
    	boolean isValid = v.isValidInput("RegexString", "%2d%2d%3e%3c%2f%73%43%72%49%70%54%3e%3c%73%43%72%49%70%54%3e%61%6c%65%72%74%28%31%36%35%38%38%29%3c%2f%73%43%72%49%70%54%3e", "RegexString", 30000, true);
    	assertFalse(isValid);
    }
    
    @Test(expected = ValidationException.class)
    public void testRegexWithGetValid() throws IntrusionException, ValidationException {
    	Validator v = ESAPI.validator();
    	String foo = v.getValidInput("RegexString", "%2d%2d%3e%3c%2f%73%43%72%49%70%54%3e%3c%73%43%72%49%70%54%3e%61%6c%65%72%74%28%31%36%35%38%38%29%3c%2f%73%43%72%49%70%54%3e", "RegexString", 30000, true);
    }
    
    @Test
    public void testavaloqLooseSafeString(){
    	Validator v = ESAPI.validator();
    	boolean isValid = v.isValidInput("RegexString", "&quot;test&quot;", "avaloqLooseSafeString", 2147483647, true, true);
    	assertFalse(isValid);
    }
}

