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

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.owasp.esapi.Authenticator;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.EncoderConstants;
import org.owasp.esapi.HTTPUtilities;
import org.owasp.esapi.User;
import org.owasp.esapi.codecs.Hex;
import org.owasp.esapi.crypto.CipherText;
import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.EnterpriseSecurityException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.errors.ValidationUploadException;
import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;
import org.owasp.esapi.http.MockHttpSession;
import org.owasp.esapi.util.FileTestUtils;
import org.owasp.esapi.util.TestUtils;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
// import org.junit.Ignore;     // Doesn't seem to work with TestSuite.
import org.junit.Rule;
import org.junit.rules.ExpectedException;
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
        String username = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
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
        String username = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
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
     * Test of getFileUploads() method, of class org.owasp.esapi.HTTPUtilities.
     * @throws IOException
     */
    public void testGetFileUploads() throws Exception {
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
            List<File> response2 = new ArrayList<>();
            try {
                response2 = ESAPI.httpUtilities().getFileUploads(request2, home);
                assertTrue( response2.size() > 0 );
            } finally {
                response2.forEach(file -> file.delete());
            }

            MockHttpServletRequest request4 = new MockHttpServletRequest("/test", content.getBytes(response.getCharacterEncoding()));
            request4.setContentType( "multipart/form-data; boundary=ridiculous");
            ESAPI.httpUtilities().setCurrentHTTP(request4, response);
            System.err.println("UPLOAD DIRECTORY: " + ESAPI.securityConfiguration().getUploadDirectory());
            List<File> response4 = new ArrayList<>();
            try {
                response4 = ESAPI.httpUtilities().getFileUploads(request4, home);
                assertTrue( response4.size() > 0 );
            } finally {
                response4.forEach(file -> file.delete());
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
     * Second test of getFileUpload() method, of class org.owasp.esapi.HTTPUtilities.
     * This one is designed to fail by uploading 3 files. (The max is set to 2 files.)
     * Based on experimentation with a dummy HTML form to send to localhost:8081
     * and the captured request caught by running 'nc -l 127.0.0.01 8081', this 'content'
     * is what it looks like (changing the boundary back 'ridiculous') for the
     * result of this HTML form:
     * <pre>
     *    <!DOCTYPE html>
     *    <html lang="en-US">
     *    <head>
     *        <title>Multifle-upload</title>
     *    </head>
     *    <body>
     *    Upload files...
     *    <form action="http://127.0.0.1:8081/"
     *           enctype="multipart/form-data"
     *           method="POST">
     *       <p>
     *       What is your name?
     *       <input type="text" name="full-name"><br/>
     *       </p<p><br/>What files are you sending?<br/>
     *       <label for="file1">File 1:</label>
     *       <input type="file" id="file1" name="file1"><br/>
     *       <label for="file2">File 2:</label>
     *       <input type="file" id="file2" name="file2"><br/>
     *       <label for="file3">File 3:</label>
     *       <input type="file" id="file3" name="file3"><br/>
     *       <br/>
     *       <input type="submit" value="Send">
     *       <input type="reset">
     *       </p>
     *     </form>
     *    </body>
     *    </html>
     * </pre>
     * with the 'full-name' field filled in with 'kevin w. wall' and the 3
     * uploaded files filled in with files named 'aaa.txt', 'bbb.txt', and 'ccc.txt',
     * respectively and each those file containing created thusly from bash:
     * <pre>
     *     $ echo AAA >aaa.txt
     *     $ echo BBB >bbb.txt
     *     $ echo CCC >ccc.txt
     * </pre>
     * Because we are uploading 3 files, but have the property HttpUtilities.MaxUploadFileCount
     * set to 2 in 'src/test/resources/esapi/ESAPI.properties', the file upload
     * attempt via HTTPUtilities.getFileUploads() will result in throwing a ValidationUploadException,
     * and if you look through the exception stack trace, you can see the
     * 'Caused by' reason is:
     *      Caused by: org.apache.commons.fileupload.FileCountLimitExceededException: attachment
     *          at org.apache.commons.fileupload.FileUploadBase.parseRequest(FileUploadBase.java:367)
     *          at org.apache.commons.fileupload.servlet.ServletFileUpload.parseRequest(ServletFileUpload.java:113)
     *          at org.owasp.esapi.reference.DefaultHTTPUtilities.getFileUploads(DefaultHTTPUtilities.java:628)
     *          ... 23 more
     * which is as it should be.
     *
     */
    public void testGetFileUploadsTooManyFiles() throws Exception {
        File home = null;

        System.out.println("testGetFileUploadsTooManyFiles");

        try
        {
            home = FileTestUtils.createTmpDirectory(CLASS_NAME);
            String content =    "Content-Type: multipart/form-data; boundary=ridiculous\r\n\r\n\r\n" +
                                "--ridiculous\r\n" +
                                "Content-Disposition: form-data; name=\"full-name\"\r\n\r\n" +
                                "kevin w wall\r\n" +
                                "--ridiculous\r\n" +
                                "Content-Disposition: form-data; name=\"file1\"; filename=\"aaa.txt\"\r\n" +
                                "Content-Type: text/plain\r\n\r\n" +
                                "AAA\r\n\r\n" +
                                "--ridiculous\r\n" +
                                "Content-Disposition: form-data; name=\"file2\"; filename=\"bbb.txt\"\r\n" +
                                "Content-Type: text/plain\r\n\r\n" +
                                "BBB\r\n\r\n" +
                                "--ridiculous\r\n" +
                                "Content-Disposition: form-data; name=\"file3\"; filename=\"ccc.txt\"\r\n" +
                                "Content-Type: text/plain\r\n\r\n" +
                                "CCC\r\n\r\n" +
                                "--ridiculous--\r\n\r\n";

            MockHttpServletResponse response = new MockHttpServletResponse();
            MockHttpServletRequest request1 = new MockHttpServletRequest("/test", content.getBytes(response.getCharacterEncoding()));
            ESAPI.httpUtilities().setCurrentHTTP(request1, response);

            MockHttpServletRequest request2 = new MockHttpServletRequest("/test", content.getBytes(response.getCharacterEncoding()));
            request2.setContentType( "multipart/form-data; boundary=ridiculous");
            ESAPI.httpUtilities().setCurrentHTTP(request2, response);
            List<File> response2 = new ArrayList<>();
            boolean caughtExpectedException = false;
            try {
                response2 = ESAPI.httpUtilities().getFileUploads(request2, home);
            } catch( ValidationUploadException vuex ) {
                caughtExpectedException = true;
            } finally {
                response2.forEach(file -> file.delete());
            }
                // If this assertion fails, check the property HttpUtilities.MaxUploadFileCount in
                // 'src/test/resources/esapi/ESAPI.properties' to make sure it is still to 2.
            assertTrue("Did not catch expected ValidationUploadException because too many files uploaded.", caughtExpectedException );
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
        ArrayList<Cookie> list = new ArrayList<Cookie>();
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
        ArrayList<Cookie> list = new ArrayList<Cookie>();
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
        } catch (AccessControlException e) {
            fail();
        }
        try {
            ESAPI.httpUtilities().sendRedirect(response,"http://www.aspectsecurity.com");
            fail();
        } catch (AccessControlException e) {
            // expected
        }
        try {
            ESAPI.httpUtilities().sendRedirect(response,"/ridiculous");
            fail();
        } catch (AccessControlException e) {
            // expected
        }
    }

        @Rule
        public ExpectedException thrown = ExpectedException.none();

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

        // test illegal name - this case is now handled by the servlet API
                try {
                    instance.addCookie( response, new Cookie( "tes<t3", "test3" ) );
                    fail("Expected IllegalArgumentException");
                } catch (IllegalArgumentException iae) {
                    assertThat(iae.getMessage(), is("Cookie name \"tes<t3\" is a reserved token"));
                }

        // test illegal value
        instance.addCookie( response, new Cookie( "test3", "tes<t3" ) );
        assertTrue(response.getHeaderNames().size() == 2);
    }

    /**
     * Test of setCookie method, of class org.owasp.esapi.HTTPUtilities.
     * Validation failures should prevent cookies being added.
     */
    public void testSetCookieExceedingMaxValueAndName() {
        HTTPUtilities instance = ESAPI.httpUtilities();
        MockHttpServletResponse response = new MockHttpServletResponse();
        assertTrue(response.getHeaderNames().isEmpty());
        //request.addParameter(TestUtils.generateStringOfLength(32), "pass");
        instance.addCookie( response, new Cookie( TestUtils.generateStringOfLength(32), "pass" ) );
        assertTrue(response.getHeaderNames().size() == 1);

        instance.addCookie( response, new Cookie( "pass", TestUtils.generateStringOfLength(32) ) );
        assertTrue(response.getHeaderNames().size() == 2);
        instance.addCookie( response, new Cookie( TestUtils.generateStringOfLength(5000), "fail" ) );
        assertTrue(response.getHeaderNames().size() == 2);
        instance.addCookie( response, new Cookie( "fail", TestUtils.generateStringOfLength(5001) ) );
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
        Map<String, String> empty = ESAPI.httpUtilities().decryptStateFromCookie(request);
        assertTrue( empty.isEmpty() );

        HashMap<String, String> map = new HashMap<String, String>();
        map.put( "one", "aspect" );
        map.put( "two", "ridiculous" );
        map.put( "test_hard", "&(@#*!^|;,." );
        try {
            ESAPI.httpUtilities().encryptStateInCookie(response, map);
            String value = response.getHeader( "Set-Cookie" );
            String encrypted = value.substring(value.indexOf("=")+1, value.indexOf(";"));
            request.setCookie( DefaultHTTPUtilities.ESAPI_STATE, encrypted );
            Map<String, String> state = ESAPI.httpUtilities().decryptStateFromCookie(request);
            Iterator<?> i = map.entrySet().iterator();
            while ( i.hasNext() ) {
                Map.Entry<?, ?> entry = (Map.Entry<?, ?>)i.next();
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
        HashMap<String, String> map = new HashMap<String, String>();
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

        String foo = ESAPI.randomizer().getRandomString(4096, EncoderConstants.CHAR_ALPHANUMERICS);

        HashMap<String, String> map = new HashMap<String, String>();
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
    @SuppressWarnings("deprecation")
    public void testDeprecatedSetRememberToken() throws AuthenticationException {
        System.out.println("setRememberToken");
        Authenticator instance = ESAPI.authenticator();
        String accountName=ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
        String password = instance.generateStrongPassword();
        User user = instance.createUser(accountName, password, password);
        user.enable();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("username", accountName);
        request.addParameter("password", password);
        MockHttpServletResponse response = new MockHttpServletResponse();
        ESAPI.httpUtilities().setCurrentHTTP(request, response);
        instance.login( request, response);

        int maxAge = ( 60 * 60 * 24 * 14 );
        ESAPI.httpUtilities().setRememberToken( request, response, password, maxAge, "domain", "/" );
        // Can't test this because we're using safeSetCookie, which sets a header, not a real cookie!
        // String value = response.getCookie( Authenticator.REMEMBER_TOKEN_COOKIE_NAME ).getValue();
        // assertEquals( user.getRememberToken(), value );
    }

    /**
     *
     * @throws org.owasp.esapi.errors.AuthenticationException
     */
    public void testSetRememberToken() throws Exception {
        //System.out.println("setRememberToken");
        Authenticator instance = ESAPI.authenticator();
        String accountName=ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
        String password = instance.generateStrongPassword();
        User user = instance.createUser(accountName, password, password);
        user.enable();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("username", accountName);
        request.addParameter("password", password);
        HttpServletResponse response = new MockHttpServletResponse();
        ESAPI.httpUtilities().setCurrentHTTP(request, response);
        instance.login( request, response);

        int maxAge = ( 60 * 60 * 24 * 14 );

        ESAPI.httpUtilities().setRememberToken( request, response, maxAge, "domain", "/" );

        Field field = response.getClass().getDeclaredField("cookies");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<Cookie> cookies = (List<Cookie>) field.get(response);
        Cookie cookie = null;
        for(Cookie c: cookies){
            if(c.getName().equals(HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME)){
                cookie = c;
                break;
            }
        }
        assertEquals(HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME, cookie.getName());
    }

    public void testGetSessionAttribute() throws Exception {
        HttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession();
        session.setAttribute("testAttribute", 43f);

        try {
            // Deleting the unused assignment of the results to test1 causes the expected ClassCastException to not occur. So don't delete it!
            @SuppressWarnings("unused")
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
            // Deleting the unused assignment of the results to test1 causes the expected ClassCastException to not occur. So don't delete it!
            @SuppressWarnings("unused")
            Integer test1 = ESAPI.httpUtilities().getRequestAttribute( request, "testAttribute" );
            fail();
        } catch ( ClassCastException cce ) {}

        Float test2 = ESAPI.httpUtilities().getRequestAttribute( request, "testAttribute" );
        assertEquals( test2, 43f );
    }

    /** Test HTTPUtilities.getFileUploads with an unauthenticated (i.e.,
     *  anonymous) user. In 'src/test/resources/esapi/ESAPI.properties', the
     *  property 'HttpUtilities.FileUploadAllowAnonymousUser' is set to 'false'.
     *  This is okay, because as it turns out most (all?) of these tests are
     *  executed after testCSRFToken(), which creates a users.txt file with
     *  a random user account name that gets used when
     *  <pre>
     *      ESAPI.authenticator().setCurrentUser( user );
     *  </pre>
     *  gets called a few lines later. That seems to persist throughout the
     *  remainder of this test suite. However, this test needs to clear that
     *  information so that any further HTTP requests are made as an anonymous
     *  user.
     *
     *  However, there is a concern here. I is not clear whether or not this
     *  would have unintended consequences because I don't this assumptions can
     *  be made about the specific order these test cases within a test suite
     *  are executed in.
     *
     *  Consequently, I ignoring this specific test by commenting it out for the
     *  concerns mentioned above. Unfortunately, the @Ignore annotation from
     *  JUnit 4 doesn't work here; apparently, it doesn't play nicely with the JUnit 3
     *  construct of
     *      public static Test suite() {
     *          return new TestSuite(HTTPUtilitiesTest.class);
     *      }
     *
     *  Note, however, the test does give the expected results and fails the
     *  upload as intended.
     */
/********************* KWWALL Commented Out - Do not delete this comment or test! *************
    public void testGetFileUploadsUnauthenticatedUser() throws Exception {
        System.out.print( "testGetFileUploadsUnauthenticatedUser" );

        File home = null;

            // Clear the current user info making it effective an anonymous user again.
        ESAPI.authenticator().clearCurrent();   // Either this or logout(), but logout may kill the session too.

        try
        {
            home = FileTestUtils.createTmpDirectory(CLASS_NAME);
            String content = "--ridiculous\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"testupload.txt\"\r\nContent-Type: application/octet-stream\r\n\r\nThis is a test of the multipart broadcast system.\r\nThis is only a test.\r\nStop.\r\n\r\n--ridiculous\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\nSubmit Query\r\n--ridiculous--\r\nEpilogue";

            MockHttpServletResponse response = new MockHttpServletResponse();
            MockHttpServletRequest request1 = new MockHttpServletRequest("/test", content.getBytes(response.getCharacterEncoding()));
            ESAPI.httpUtilities().setCurrentHTTP(request1, response);

            MockHttpServletRequest request2 = new MockHttpServletRequest("/test", content.getBytes(response.getCharacterEncoding()));
            request2.setContentType( "multipart/form-data; boundary=ridiculous");
            ESAPI.httpUtilities().setCurrentHTTP(request2, response);
            List<File> response2 = new ArrayList<>();
            try {
                response2 = ESAPI.httpUtilities().getFileUploads(request2, home);
                fail("Expecting an exception here");
            } catch ( java.security.AccessControlException acex ) {
                ;   // Expected
            } catch ( Exception ex ) {
                fail("Wrong exception type caught: " + ex.getClass().getName() +
                     ", received, expected java.security.AccessControlException");
            } finally {
                response2.forEach(file -> file.delete());
            }
        }
        finally
        {
            FileTestUtils.deleteRecursively(home);
        }
    }
********************* KWWALL End Commented Out Code ********************/
}
