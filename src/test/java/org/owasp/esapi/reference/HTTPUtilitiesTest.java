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

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.owasp.esapi.Authenticator;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.HTTPUtilities;
import org.owasp.esapi.User;
import org.owasp.esapi.codecs.Hex;
import org.owasp.esapi.crypto.CipherText;
import org.owasp.esapi.crypto.PlainText;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.EnterpriseSecurityException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;
import org.owasp.esapi.http.MockHttpSession;
import org.owasp.esapi.util.FileTestUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * The Class HTTPUtilitiesTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class HTTPUtilitiesTest extends TestCase
{
	private static final Class<HTTPUtilitiesTest> CLASS = HTTPUtilitiesTest.class;
	private static final String CLASS_NAME = CLASS.getName();

	/**
	 * Suite.
	 * 
	 * @return the test
	 */
	public static Test suite() {
		return new TestSuite(HTTPUtilitiesTest.class);
	}

	/**
	 * Instantiates a new HTTP utilities test.
	 * 
	 * @param testName the test name
	 */
	public HTTPUtilitiesTest(String testName) {
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

	public void testCSRFToken() throws Exception {
		System.out.println( "CSRFToken");
		String username = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
		User user = ESAPI.authenticator().createUser(username, "addCSRFToken", "addCSRFToken");
		ESAPI.authenticator().setCurrentUser( user );
		String token = ESAPI.httpUtilities().getCSRFToken();
		assertEquals( 8, token.length() );
		MockHttpServletRequest request = new MockHttpServletRequest();
		try {
			ESAPI.httpUtilities().verifyCSRFToken(request);
			fail();
		} catch( Exception e ) {
			// expected
		}
		request.addParameter( DefaultHTTPUtilities.CSRF_TOKEN_NAME, token );
		ESAPI.httpUtilities().verifyCSRFToken(request);
	}

	/**
	 * Test of addCSRFToken method, of class org.owasp.esapi.HTTPUtilities.
	 * @throws AuthenticationException 
	 */
	public void testAddCSRFToken() throws AuthenticationException {
		Authenticator instance = ESAPI.authenticator();
		String username = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
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
	 * Test of assertSecureRequest method, of class org.owasp.esapi.HTTPUtilities.
	 */
	public void testAssertSecureRequest() {
		System.out.println("assertSecureRequest");
		MockHttpServletRequest request = new MockHttpServletRequest();
		try {
			request.setRequestURL( "http://example.com");
			ESAPI.httpUtilities().assertSecureRequest( request );
			fail();
		} catch( Exception e ) {
			// pass
		}
		try {
			request.setRequestURL( "ftp://example.com");
			ESAPI.httpUtilities().assertSecureRequest( request );
			fail();
		} catch( Exception e ) {
			// pass
		}
		try {
			request.setRequestURL( "");
			ESAPI.httpUtilities().assertSecureRequest( request );
			fail();
		} catch( Exception e ) {
			// pass
		}
		try {
			request.setRequestURL( null );
			ESAPI.httpUtilities().assertSecureRequest( request );
			fail();
		} catch( Exception e ) {
			// pass
		}
		try {
			request.setRequestURL( "https://example.com");
			ESAPI.httpUtilities().assertSecureRequest( request );
			// pass
		} catch( Exception e ) {
			fail();
		}
	}


	/**
	 * Test of sendRedirect method, of class org.owasp.esapi.HTTPUtilities.
	 * 
	 * @throws EnterpriseSecurityException
	 */
	public void testChangeSessionIdentifier() throws EnterpriseSecurityException {
		System.out.println("changeSessionIdentifier");
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockHttpSession session = (MockHttpSession) request.getSession();
		ESAPI.httpUtilities().setCurrentHTTP(request, response);
		session.setAttribute("one", "one");
		session.setAttribute("two", "two");
		session.setAttribute("three", "three");
		String id1 = session.getId();
		session = (MockHttpSession) ESAPI.httpUtilities().changeSessionIdentifier( request );
		String id2 = session.getId();
		assertTrue(!id1.equals(id2));
		assertEquals("one", (String) session.getAttribute("one"));
	}

	/**
	 * Test of formatHttpRequestForLog method, of class org.owasp.esapi.HTTPUtilities.
	 * @throws IOException 
	 */
	public void testGetFileUploads() throws IOException {
		File home = null;

		try
		{
			home = FileTestUtils.createTmpDirectory(CLASS_NAME);
			String content = "--ridiculous\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"testupload.txt\"\r\nContent-Type: application/octet-stream\r\n\r\nThis is a test of the multipart broadcast system.\r\nThis is only a test.\r\nStop.\r\n\r\n--ridiculous\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\nSubmit Query\r\n--ridiculous--\r\nEpilogue";

			MockHttpServletResponse response = new MockHttpServletResponse();    
			MockHttpServletRequest request1 = new MockHttpServletRequest("/test", content.getBytes(response.getCharacterEncoding()));
			ESAPI.httpUtilities().setCurrentHTTP(request1, response);
			try {
				ESAPI.httpUtilities().getFileUploads(request1, home);
				fail();
			} catch( ValidationException e ) {
				// expected
			}

			MockHttpServletRequest request2 = new MockHttpServletRequest("/test", content.getBytes(response.getCharacterEncoding()));
			request2.setContentType( "multipart/form-data; boundary=ridiculous");
			ESAPI.httpUtilities().setCurrentHTTP(request2, response);
			try {
				List list = ESAPI.httpUtilities().getFileUploads(request2, home);
				Iterator i = list.iterator();
				while ( i.hasNext() ) {
					File f = (File)i.next();
					System.out.println( "  " + f.getAbsolutePath() );
				}
				assertTrue( list.size() > 0 );
			} catch (ValidationException e) {
				fail();
			}

			MockHttpServletRequest request4 = new MockHttpServletRequest("/test", content.getBytes(response.getCharacterEncoding()));
			request4.setContentType( "multipart/form-data; boundary=ridiculous");
			ESAPI.httpUtilities().setCurrentHTTP(request4, response);
			System.err.println("UPLOAD DIRECTORY: " + ESAPI.securityConfiguration().getUploadDirectory());
			try {
				List list = ESAPI.httpUtilities().getFileUploads(request4, home);
				Iterator i = list.iterator();
				while ( i.hasNext() ) {
					File f = (File)i.next();
					System.out.println( "  " + f.getAbsolutePath() );
				}
				assertTrue( list.size() > 0 );
			} catch (ValidationException e) {
				System.err.println("ERROR: " + e.toString());
				fail();
			}

			MockHttpServletRequest request3 = new MockHttpServletRequest("/test", content.replaceAll("txt", "ridiculous").getBytes(response.getCharacterEncoding()));
			request3.setContentType( "multipart/form-data; boundary=ridiculous");
			ESAPI.httpUtilities().setCurrentHTTP(request3, response);
			try {
				ESAPI.httpUtilities().getFileUploads(request3, home);
				fail();
			} catch (ValidationException e) {
				// expected
			}
		}
		finally
		{
			FileTestUtils.deleteRecursively(home);
		}

	}



	/**
	 * Test of killAllCookies method, of class org.owasp.esapi.HTTPUtilities.
	 */
	public void testKillAllCookies() {
		System.out.println("killAllCookies");
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		assertTrue(response.getCookies().isEmpty());
		ArrayList list = new ArrayList();
		list.add(new Cookie("test1", "1"));
		list.add(new Cookie("test2", "2"));
		list.add(new Cookie("test3", "3"));
		request.setCookies(list);
		ESAPI.httpUtilities().killAllCookies(request, response);
		assertTrue(response.getCookies().size() == 3);
	}

	/**
	 * Test of killCookie method, of class org.owasp.esapi.HTTPUtilities.
	 */
	public void testKillCookie() {
		System.out.println("killCookie");
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		ESAPI.httpUtilities().setCurrentHTTP(request, response);
		assertTrue(response.getCookies().isEmpty());
		ArrayList list = new ArrayList();
		list.add(new Cookie("test1", "1"));
		list.add(new Cookie("test2", "2"));
		list.add(new Cookie("test3", "3"));
		request.setCookies(list);
		ESAPI.httpUtilities().killCookie( request, response, "test1" );
		assertTrue(response.getCookies().size() == 1);
	}

	/**
	 * Test of sendRedirect method, of class org.owasp.esapi.HTTPUtilities.
	 * 
	 * @throws ValidationException the validation exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public void testSendSafeRedirect() throws Exception {
		System.out.println("sendSafeRedirect");
		MockHttpServletResponse response = new MockHttpServletResponse();
		try {
			ESAPI.httpUtilities().sendRedirect(response, "/test1/abcdefg");
			ESAPI.httpUtilities().sendRedirect(response,"/test2/1234567");
		} catch (IOException e) {
			fail();
		}
		try {
			ESAPI.httpUtilities().sendRedirect(response,"http://www.aspectsecurity.com");
			fail();
		} catch (IOException e) {
			// expected
		}
		try {
			ESAPI.httpUtilities().sendRedirect(response,"/ridiculous");
			fail();
		} catch (IOException e) {
			// expected
		}
	}

	/**
	 * Test of setCookie method, of class org.owasp.esapi.HTTPUtilities.
	 */
	public void testSetCookie() {
		System.out.println("setCookie");
		HTTPUtilities instance = ESAPI.httpUtilities(); 
		MockHttpServletResponse response = new MockHttpServletResponse();
		assertTrue(response.getHeaderNames().isEmpty());

		instance.addCookie( response, new Cookie( "test1", "test1" ) );
		assertTrue(response.getHeaderNames().size() == 1);

		instance.addCookie( response, new Cookie( "test2", "test2" ) );
		assertTrue(response.getHeaderNames().size() == 2);

		// test illegal name
		instance.addCookie( response, new Cookie( "tes<t3", "test3" ) );
		assertTrue(response.getHeaderNames().size() == 2);

		// test illegal value
		instance.addCookie( response, new Cookie( "test3", "tes<t3" ) );
		assertTrue(response.getHeaderNames().size() == 2);
	}

	/**
	 *
	 * @throws java.lang.Exception
	 */
	public void testGetStateFromEncryptedCookie() throws Exception {
		System.out.println("getStateFromEncryptedCookie");
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		// test null cookie array
		Map empty = ESAPI.httpUtilities().decryptStateFromCookie(request);
		assertTrue( empty.isEmpty() );

		HashMap map = new HashMap();
		map.put( "one", "aspect" );
		map.put( "two", "ridiculous" );
		map.put( "test_hard", "&(@#*!^|;,." );
		try {
			ESAPI.httpUtilities().encryptStateInCookie(response, map);
			String value = response.getHeader( "Set-Cookie" );
			String encrypted = value.substring(value.indexOf("=")+1, value.indexOf(";"));
			request.setCookie( DefaultHTTPUtilities.ESAPI_STATE, encrypted );
			Map state = ESAPI.httpUtilities().decryptStateFromCookie(request);
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

	/**
	 *
	 */
	public void testSaveStateInEncryptedCookie() {
		System.out.println("saveStateInEncryptedCookie");
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		ESAPI.httpUtilities().setCurrentHTTP(request, response);
		HashMap map = new HashMap();
		map.put( "one", "aspect" );
		map.put( "two", "ridiculous" );
		map.put( "test_hard", "&(@#*!^|;,." );
		try {
			ESAPI.httpUtilities().encryptStateInCookie(response,map);
			String value = response.getHeader( "Set-Cookie" );
			String encrypted = value.substring(value.indexOf("=")+1, value.indexOf(";"));
			byte[] serializedCiphertext = Hex.decode(encrypted);
	        CipherText restoredCipherText =
	            CipherText.fromPortableSerializedBytes(serializedCiphertext);
	        ESAPI.encryptor().decrypt(restoredCipherText);
		} catch( EncryptionException e ) {
			fail();
		}
	}


	/**
	 *
	 */
	public void testSaveTooLongStateInEncryptedCookieException() {
		System.out.println("saveTooLongStateInEncryptedCookie");

		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		ESAPI.httpUtilities().setCurrentHTTP(request, response);

		String foo = ESAPI.randomizer().getRandomString(4096, DefaultEncoder.CHAR_ALPHANUMERICS);

		HashMap map = new HashMap();
		map.put("long", foo);
		try {
			ESAPI.httpUtilities().encryptStateInCookie(response, map);
			fail("Should have thrown an exception");
		}
		catch (EncryptionException expected) {
			//expected
		}    	
	}

	/**
	 * Test set no cache headers.
	 */
	public void testSetNoCacheHeaders() {
		System.out.println("setNoCacheHeaders");
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		ESAPI.httpUtilities().setCurrentHTTP(request, response);
		assertTrue(response.getHeaderNames().isEmpty());
		response.addHeader("test1", "1");
		response.addHeader("test2", "2");
		response.addHeader("test3", "3");
		assertFalse(response.getHeaderNames().isEmpty());
		ESAPI.httpUtilities().setNoCacheHeaders( response );
		assertTrue(response.containsHeader("Cache-Control"));
		assertTrue(response.containsHeader("Expires"));
	}

	/**
	 *
	 * @throws org.owasp.esapi.errors.AuthenticationException
	 */
	public void testSetRememberToken() throws AuthenticationException {
		System.out.println("setRememberToken");
		Authenticator instance = (Authenticator)ESAPI.authenticator();
		String accountName=ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
		String password = instance.generateStrongPassword();
		User user = instance.createUser(accountName, password, password);
		user.enable();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter("username", accountName);
		request.addParameter("password", password);
		MockHttpServletResponse response = new MockHttpServletResponse();
		instance.login( request, response);

		int maxAge = ( 60 * 60 * 24 * 14 );
		ESAPI.httpUtilities().setRememberToken( request, response, password, maxAge, "domain", "/" );
		// Can't test this because we're using safeSetCookie, which sets a header, not a real cookie!
		// String value = response.getCookie( Authenticator.REMEMBER_TOKEN_COOKIE_NAME ).getValue();
		// assertEquals( user.getRememberToken(), value );
	}

	public void testGetSessionAttribute() throws Exception {
		HttpServletRequest request = new MockHttpServletRequest();
		HttpSession session = request.getSession();
		session.setAttribute("testAttribute", 43f);

		try {
			Integer test1 = ESAPI.httpUtilities().getSessionAttribute( session, "testAttribute" );
			fail();
		} catch ( ClassCastException cce ) {}

		Float test2 = ESAPI.httpUtilities().getSessionAttribute( session, "testAttribute" );
		assertEquals( test2, 43f );
	}

	public void testGetRequestAttribute() throws Exception {
		HttpServletRequest request = new MockHttpServletRequest();
		request.setAttribute( "testAttribute", 43f );
		try {
			Integer test1 = ESAPI.httpUtilities().getRequestAttribute( request, "testAttribute" );
			fail();
		} catch ( ClassCastException cce ) {}

		Float test2 = ESAPI.httpUtilities().getRequestAttribute( request, "testAttribute" );
		assertEquals( test2, 43f );
	}
}
