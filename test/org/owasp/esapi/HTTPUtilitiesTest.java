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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.http.Cookie;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.EnterpriseSecurityException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.http.TestHttpServletRequest;
import org.owasp.esapi.http.TestHttpServletResponse;
import org.owasp.esapi.http.TestHttpSession;
import org.owasp.esapi.interfaces.IAuthenticator;
import org.owasp.esapi.interfaces.IHTTPUtilities;

/**
 * The Class HTTPUtilitiesTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class HTTPUtilitiesTest extends TestCase {

    /**
     * Suite.
     * 
     * @return the test
     */
    public static Test suite() {
        TestSuite suite = new TestSuite(HTTPUtilitiesTest.class);
        return suite;
    }

    /**
     * Instantiates a new HTTP utilities test.
     * 
     * @param testName the test name
     */
    public HTTPUtilitiesTest(String testName) {
        super(testName);
    }

    /*
     * (non-Javadoc)
     * 
     * @see junit.framework.TestCase#setUp()
     */
    protected void setUp() throws Exception {
        // none
    }

    /*
     * (non-Javadoc)
     * 
     * @see junit.framework.TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        // none
    }

    /**
     * Test of addCSRFToken method, of class org.owasp.esapi.HTTPUtilities.
     * @throws AuthenticationException 
     */
    public void testAddCSRFToken() throws AuthenticationException {
        IAuthenticator instance = ESAPI.authenticator();
		String username = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
		User user = instance.createUser(username, "addCSRFToken", "addCSRFToken");
		instance.setCurrentUser( user );

		System.out.println("addCSRFToken");
        String csrf1=ESAPI.httpUtilities().addCSRFToken("/test1");
        System.out.println( "CSRF1:" + csrf1);
        assertTrue(csrf1.indexOf("?") > -1);
        
        String csrf2=ESAPI.httpUtilities().addCSRFToken("/test1?one=two");
        System.out.println( "CSRF1:" + csrf1);
        assertTrue(csrf2.indexOf("&") > -1);
    }

    /**
     * Test of sendRedirect method, of class org.owasp.esapi.HTTPUtilities.
     * 
     * @throws ValidationException the validation exception
     * @throws IOException Signals that an I/O exception has occurred.
     * @throws AuthenticationException the authentication exception
     */
    public void testChangeSessionIdentifier() throws EnterpriseSecurityException {
        System.out.println("changeSessionIdentifier");
        TestHttpServletRequest request = new TestHttpServletRequest();
        TestHttpServletResponse response = new TestHttpServletResponse();
        TestHttpSession session = (TestHttpSession) request.getSession();
        Authenticator instance = (Authenticator)ESAPI.authenticator();
        instance.setCurrentHTTP(request, response);
        session.setAttribute("one", "one");
        session.setAttribute("two", "two");
        session.setAttribute("three", "three");
        String id1 = session.getId();
        session = (TestHttpSession) ESAPI.httpUtilities().changeSessionIdentifier();
        String id2 = session.getId();
        assertTrue(!id1.equals(id2));
        assertEquals("one", (String) session.getAttribute("one"));
    }

    /**
     * Test of formatHttpRequestForLog method, of class org.owasp.esapi.HTTPUtilities.
     * @throws IOException 
     */
    public void testGetFileUploads() throws IOException {
        System.out.println("getFileUploads");
        File home = ((SecurityConfiguration)ESAPI.securityConfiguration()).getResourceDirectory();
        byte[] bytes = getBytesFromFile(new File(home, "multipart.txt"));
        System.out.println( "===========\n" + new String( bytes ) + "\n===========" );
        TestHttpServletRequest request = new TestHttpServletRequest("/test", bytes);
        TestHttpServletResponse response = new TestHttpServletResponse();
        Authenticator instance = (Authenticator)ESAPI.authenticator();
        instance.setCurrentHTTP(request, response);
        try {
            ESAPI.httpUtilities().getSafeFileUploads(home, home);
        } catch (ValidationException e) {
            fail();
        }
    }

    private byte[] getBytesFromFile(File file) throws IOException {
        InputStream is = new FileInputStream(file);
        long length = file.length();
        byte[] bytes = new byte[(int) length];

        int offset = 0;
        int numRead = 0;
        while (offset < bytes.length && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
            offset += numRead;
        }

        if (offset < bytes.length) {
            throw new IOException("Could not completely read file " + file.getName());
        }
        is.close();
        return bytes;
    }

    /**
     * Test of isValidHTTPRequest method, of class org.owasp.esapi.HTTPUtilities.
     */
    public void testIsValidHTTPRequest() {
        System.out.println("isValidHTTPRequest");
        TestHttpServletRequest request = new TestHttpServletRequest();
        request.addParameter("p1", "v1");
        request.addParameter("p2", "v3");
        request.addParameter("p3", "v2");
        request.addHeader("h1","v1");
        request.addHeader("h2","v1");
        request.addHeader("h3","v1");
        ArrayList list = new ArrayList();
        list.add(new Cookie("c1", "v1"));
        list.add(new Cookie("c2", "v2"));
        list.add(new Cookie("c3", "v3"));
        request.setCookies(list);
        assertTrue( ESAPI.validator().isValidHTTPRequest(request) );
        request.addParameter("bad_name", "bad*value");
        request.addHeader("bad_name", "bad*value");
        list.add(new Cookie("bad_name", "bad*value"));
        assertFalse( ESAPI.validator().isValidHTTPRequest(request) );
     }
    
    
    /**
     * Test of killAllCookies method, of class org.owasp.esapi.HTTPUtilities.
     */
    public void testKillAllCookies() {
        System.out.println("killAllCookies");
        TestHttpServletRequest request = new TestHttpServletRequest();
        TestHttpServletResponse response = new TestHttpServletResponse();
        Authenticator instance = (Authenticator)ESAPI.authenticator();
        instance.setCurrentHTTP(request, response);
        assertTrue(response.getCookies().isEmpty());
        ArrayList list = new ArrayList();
        list.add(new Cookie("test1", "1"));
        list.add(new Cookie("test2", "2"));
        list.add(new Cookie("test3", "3"));
        request.setCookies(list);
        ESAPI.httpUtilities().killAllCookies();
        // this tests getHeaders because we're using addHeader in our setCookie method
        assertTrue(response.getHeaderNames().size() == 3);
    }

    /**
     * Test of killCookie method, of class org.owasp.esapi.HTTPUtilities.
     */
    public void testKillCookie() {
        System.out.println("killCookie");
        TestHttpServletRequest request = new TestHttpServletRequest();
        TestHttpServletResponse response = new TestHttpServletResponse();
        Authenticator instance = (Authenticator)ESAPI.authenticator();
        instance.setCurrentHTTP(request, response);
        assertTrue(response.getCookies().isEmpty());
        ArrayList list = new ArrayList();
        list.add(new Cookie("test1", "1"));
        list.add(new Cookie("test2", "2"));
        list.add(new Cookie("test3", "3"));
        request.setCookies(list);
        ESAPI.httpUtilities().killCookie("test1");
        // this tests getHeaders because we're using addHeader in our setCookie method
        assertTrue(response.getHeaderNames().size() == 1);
    }

    /**
     * Test of sendRedirect method, of class org.owasp.esapi.HTTPUtilities.
     * 
     * @throws ValidationException the validation exception
     * @throws IOException Signals that an I/O exception has occurred.
     */
    public void testSendSafeRedirect() throws ValidationException, IOException {
        System.out.println("sendSafeRedirect");
        try {
            ESAPI.httpUtilities().safeSendRedirect("test", "/test1/abcdefg");
            ESAPI.httpUtilities().safeSendRedirect("test", "/test2/1234567");
        } catch (ValidationException e) {
            fail();
        }
        try {
            ESAPI.httpUtilities().safeSendRedirect("test", "http://www.aspectsecurity.com");
            fail();
        } catch (ValidationException e) {
            // expected
        }
        try {
            ESAPI.httpUtilities().safeSendRedirect("test", "/ridiculous");
            fail();
        } catch (ValidationException e) {
            // expected
        }
    }

    /**
     * Test of setCookie method, of class org.owasp.esapi.HTTPUtilities.
     */
    public void testSetCookie() {
        System.out.println("setCookie");
        TestHttpServletRequest request = new TestHttpServletRequest();
        TestHttpServletResponse response = new TestHttpServletResponse();
        Authenticator instance = (Authenticator)ESAPI.authenticator();
        instance.setCurrentHTTP(request, response);
        assertTrue(response.getCookies().isEmpty());
        try {
        	ESAPI.httpUtilities().safeAddCookie("test1", "test1", 10000, "test", "/");
        } catch (ValidationException e) {
        	fail();
        }
        try {
        	ESAPI.httpUtilities().safeAddCookie("test2", "test2", 10000, "test", "/");
	    } catch (ValidationException e) {
	    	fail();
	    }
        try {
        	ESAPI.httpUtilities().safeAddCookie("tes\nt3", "test3", 10000, "test", "/");
	    	fail();
	    } catch (ValidationException e) {
	    	// expected
	    }
        try {
        	ESAPI.httpUtilities().safeAddCookie("test3", "te\nst3", 10000, "test", "/");
	    	fail();
	    } catch (ValidationException e) {
	    	// expected
	    }
	    assertTrue(response.getHeaderNames().size() == 2);
	}

    public void testGetStateFromEncryptedCookie() {
        System.out.println("getStateFromEncryptedCookie");
        TestHttpServletRequest request = new TestHttpServletRequest();
        TestHttpServletResponse response = new TestHttpServletResponse();
        Authenticator instance = (Authenticator)ESAPI.authenticator();
        instance.setCurrentHTTP(request, response);
        HashMap map = new HashMap();
        map.put( "one", "aspect" );
        map.put( "two", "ridiculous" );
        map.put( "test_hard", "&(@#*!^|;,." );
        try {
	        ESAPI.httpUtilities().encryptStateInCookie(map);
	        String value = response.getHeader( "Set-Cookie" );
	        String encrypted = value.substring(value.indexOf("=")+1, value.indexOf(";"));
	        // String encrypted = response.getCookie("state").getValue();
	        request.setCookie( "state", encrypted );
	        Map state = ESAPI.httpUtilities().decryptStateFromCookie();
	        Iterator i = map.entrySet().iterator();
	        while ( i.hasNext() ) {
	        	Map.Entry entry = (Map.Entry)i.next();
	        	String origname = (String)entry.getKey();
	        	String origvalue = (String)entry.getValue();
	        	if( !state.get( origname ).equals( origvalue ) ) {
	        		fail();
	        	}
	        }
        } catch( EncryptionException e ) {
        	fail();
        }
    }
    
    public void testSaveStateInEncryptedCookie() {
        System.out.println("saveStateInEncryptedCookie");
        TestHttpServletRequest request = new TestHttpServletRequest();
        TestHttpServletResponse response = new TestHttpServletResponse();
        Authenticator instance = (Authenticator)ESAPI.authenticator();
        instance.setCurrentHTTP(request, response);
        HashMap map = new HashMap();
        map.put( "one", "aspect" );
        map.put( "two", "ridiculous" );
        map.put( "test_hard", "&(@#*!^|;,." );
        try {
	        ESAPI.httpUtilities().encryptStateInCookie(map);
	        String value = response.getHeader( "Set-Cookie" );
	        String encrypted = value.substring(value.indexOf("=")+1, value.indexOf(";"));
        	ESAPI.encryptor().decrypt( encrypted );
        } catch( EncryptionException e ) {
        	fail();
        }
    }
    
    /**
     * Test set no cache headers.
     */
    public void testSetNoCacheHeaders() {
        System.out.println("setNoCacheHeaders");
        TestHttpServletRequest request = new TestHttpServletRequest();
        TestHttpServletResponse response = new TestHttpServletResponse();
        Authenticator auth = (Authenticator)ESAPI.authenticator();
        auth.setCurrentHTTP(request, response);
        assertTrue(response.getHeaderNames().isEmpty());
        response.addHeader("test1", "1");
        response.addHeader("test2", "2");
        response.addHeader("test3", "3");
        assertFalse(response.getHeaderNames().isEmpty());
        IHTTPUtilities instance = ESAPI.httpUtilities();
        instance.setNoCacheHeaders();
        assertTrue(response.containsHeader("Cache-Control"));
        assertTrue(response.containsHeader("Expires"));
    }

}
