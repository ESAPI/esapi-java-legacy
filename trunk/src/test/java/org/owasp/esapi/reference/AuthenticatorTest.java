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

import java.util.Date;
import java.util.Set;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.Authenticator;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.HTTPUtilities;
import org.owasp.esapi.Logger;
import org.owasp.esapi.User;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;

/**
 * The Class AuthenticatorTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class AuthenticatorTest extends TestCase {


	/**
	 * Suite.
	 * 
	 * @return the test
	 */
	public static Test suite() {
		TestSuite suite = new TestSuite(AuthenticatorTest.class);

		return suite;
	}

	/**
	 * Instantiates a new authenticator test.
	 * 
	 * @param testName
	 *            the test name
	 */
	public AuthenticatorTest(String testName) {
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
	 * Test of createAccount method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws AuthenticationException
     *             the authentication exception
     * @throws EncryptionException
	 */
	public void testCreateUser() throws AuthenticationException, EncryptionException {
		System.out.println("createUser");
		String accountName = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
		Authenticator instance = ESAPI.authenticator();
		String password = instance.generateStrongPassword();
		User user = instance.createUser(accountName, password, password);
		assertTrue(user.verifyPassword(password));
        try {
            instance.createUser(accountName, password, password); // duplicate user
            fail();
        } catch (AuthenticationException e) {
            // success
        }
        try {
            instance.createUser(ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS), "password1", "password2"); // don't match
            fail();
        } catch (AuthenticationException e) {
            // success
        }
        try {
            instance.createUser(ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS), "weak1", "weak1");  // weak password
            fail();
        } catch (AuthenticationException e) {
            // success
        }
        try {
            instance.createUser(null, "weak1", "weak1");  // null username
            fail();
        } catch (AuthenticationException e) {
            // success
        }
        try {
            instance.createUser(ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS), null, null);  // null password
            fail();
        } catch (AuthenticationException e) {
            // success
        }
        try {
        	String uName = "ea234kEknr";	//sufficiently random password that also works as a username
            instance.createUser(uName, uName, uName);  // using username as password
            fail();
        } catch (AuthenticationException e) {
            // success
        }
	}

	/**
	 * Test of generateStrongPassword method, of class
	 * org.owasp.esapi.Authenticator.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testGenerateStrongPassword() throws AuthenticationException {
		System.out.println("generateStrongPassword");		
		Authenticator instance = ESAPI.authenticator();
		String oldPassword = "iiiiiiiiii";  // i is not allowed in passwords - this prevents failures from containing pieces of old password
		String newPassword = null;
		for (int i = 0; i < 100; i++) {
            try {
                newPassword = instance.generateStrongPassword();
                instance.verifyPasswordStrength(oldPassword, newPassword);
            } catch( AuthenticationException e ) {
            	System.out.println( "  FAILED >> " + newPassword + " : " + e.getLogMessage());
                fail();
            }
		}
		try {
			instance.verifyPasswordStrength("test56^$test", "abcdx56^$sl" );
		} catch( AuthenticationException e ) {
			// expected
		}
	}


	/**
	 * Test of getCurrentUser method, of class org.owasp.esapi.Authenticator.
	 * 
     *
     * @throws Exception
     */
	public void testGetCurrentUser() throws Exception {
		System.out.println("getCurrentUser");
        Authenticator instance = ESAPI.authenticator();
		String username1 = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
		String username2 = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
		User user1 = instance.createUser(username1, "getCurrentUser", "getCurrentUser");
		User user2 = instance.createUser(username2, "getCurrentUser", "getCurrentUser");		
		user1.enable();
	    MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
        ESAPI.httpUtilities().setCurrentHTTP(request, response);
		user1.loginWithPassword("getCurrentUser");
		User currentUser = instance.getCurrentUser();
		assertEquals( currentUser, user1 );
		instance.setCurrentUser( user2 );
		assertFalse( currentUser.getAccountName().equals( user2.getAccountName() ) );
		
		Runnable echo = new Runnable() {
			private int count = 1;
            private boolean result = false;
			public void run() {
		        Authenticator auth = ESAPI.authenticator();
				User a = null;
				try {
					String password = auth.generateStrongPassword();
					String accountName = "TestAccount" + count++;
					a = auth.getUser(accountName);
					if ( a != null ) {
						auth.removeUser(accountName);
					}
					a = auth.createUser(accountName, password, password);
					auth.setCurrentUser(a);
				} catch (AuthenticationException e) {
					e.printStackTrace();
				}
				User b = auth.getCurrentUser();
				result &= a.equals(b);
			}
		};
        ThreadGroup tg = new ThreadGroup("test");
		for ( int i = 0; i<10; i++ ) {
			new Thread( tg, echo ).start();
		}
        while (tg.activeCount() > 0 ) {
            Thread.sleep(100);
        }
	}

	/**
	 * Test of getUser method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testGetUser() throws AuthenticationException {
		System.out.println("getUser");
        Authenticator instance = ESAPI.authenticator();
		String password = instance.generateStrongPassword();
		String accountName=ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
		instance.createUser(accountName, password, password);
		assertNotNull(instance.getUser( accountName ));
		assertNull(instance.getUser( ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS) ));
	}
	
    /**
     *
     * @throws org.owasp.esapi.errors.AuthenticationException
     */
    public void testGetUserFromRememberToken() throws AuthenticationException {
		System.out.println("getUserFromRememberToken");
        Authenticator instance = ESAPI.authenticator();
        instance.logout();  // in case anyone is logged in
		String password = instance.generateStrongPassword();
		String accountName=ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
		User user = instance.createUser(accountName, password, password);
		user.enable();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		ESAPI.httpUtilities().setCurrentHTTP(request, response);
		
		System.out.println("getUserFromRememberToken - expecting failure");
		request.setCookie( HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME, "ridiculous" );
		try {
			instance.login( request, response );  // wrong cookie will fail
		} catch( AuthenticationException e ) {
			// expected
		}

		System.out.println("getUserFromRememberToken - expecting success");
		request = new MockHttpServletRequest();
		ESAPI.httpUtilities().setCurrentHTTP(request, response);
		ESAPI.authenticator().setCurrentUser(user);
		String newToken = ESAPI.httpUtilities().setRememberToken(request, response, password, 10000, "test.com", request.getContextPath() );
		request.setCookie( HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME, newToken );
        user.logout();  // logout the current user so we can log them in with the remember cookie
		User test2 = instance.login( request, response );
		assertSame( user, test2 );
	}
	

	
	/**
	 * Test get user from session.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testGetUserFromSession() throws AuthenticationException {
		System.out.println("getUserFromSession");
        FileBasedAuthenticator instance = (FileBasedAuthenticator)ESAPI.authenticator();
        instance.logout();  // in case anyone is logged in
		String accountName=ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
		String password = instance.generateStrongPassword();
		User user = instance.createUser(accountName, password, password);
		user.enable();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter("username", accountName);
		request.addParameter("password", password);
		MockHttpServletResponse response = new MockHttpServletResponse();
		ESAPI.httpUtilities().setCurrentHTTP( request, response );
		instance.login( request, response);
		User test = instance.getUserFromSession();
		assertEquals( user, test );
	}

	/**
	 * Test get user names.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testGetUserNames() throws AuthenticationException {
		System.out.println("getUserNames");
        Authenticator instance = ESAPI.authenticator();
		String password = instance.generateStrongPassword();
		String[] testnames = new String[10];
		for(int i=0;i<testnames.length;i++) {
			testnames[i] = ESAPI.randomizer().getRandomString(8,DefaultEncoder.CHAR_ALPHANUMERICS);
		}
		for(int i=0;i<testnames.length;i++) {
			instance.createUser(testnames[i], password, password);
		}
		Set names = instance.getUserNames();
		for(int i=0;i<testnames.length;i++) {
			assertTrue(names.contains(testnames[i].toLowerCase()));
		}
	}
	
	/**
	 * Test of hashPassword method, of class org.owasp.esapi.Authenticator.
     *
     * @throws EncryptionException
     */
	public void testHashPassword() throws EncryptionException {
		System.out.println("hashPassword");
		String username = "Jeff";
		String password = "test";
        Authenticator instance = ESAPI.authenticator();
		String result1 = instance.hashPassword(password, username);
		String result2 = instance.hashPassword(password, username);
		assertTrue(result1.equals(result2));
	}

	/**
	 * Test of login method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testLogin() throws AuthenticationException {
		System.out.println("login");
        Authenticator instance = ESAPI.authenticator();
        String username = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
		String password = instance.generateStrongPassword();
		User user = instance.createUser(username, password, password);
		user.enable();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter("username", username);
		request.addParameter("password", password);
		MockHttpServletResponse response = new MockHttpServletResponse();
		User test = instance.login( request, response);
		assertTrue( test.isLoggedIn() );
	}
	
	/**
	 * Test of removeAccount method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws Exception
	 *             the exception
	 */
	public void testRemoveUser() throws Exception {
		System.out.println("removeUser");
		String accountName = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
        Authenticator instance = ESAPI.authenticator();
		String password = instance.generateStrongPassword();
		instance.createUser(accountName, password, password);
		assertTrue( instance.exists(accountName));
		instance.removeUser(accountName);
		assertFalse( instance.exists(accountName));
	}

	/**
	 * Test of saveUsers method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws Exception
	 *             the exception
	 */
	public void testSaveUsers() throws Exception {
		System.out.println("saveUsers");
		String accountName = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
        FileBasedAuthenticator instance = (FileBasedAuthenticator)ESAPI.authenticator();
		String password = instance.generateStrongPassword();
		instance.createUser(accountName, password, password);
		instance.saveUsers();
		assertNotNull( instance.getUser(accountName) );
		instance.removeUser(accountName);
		assertNull( instance.getUser(accountName) );
	}

	
	/**
	 * Test of setCurrentUser method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testSetCurrentUser() throws AuthenticationException {
		System.out.println("setCurrentUser");
        final Authenticator instance = ESAPI.authenticator();
		String user1 = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_UPPERS);
		String user2 = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_UPPERS);
		User userOne = instance.createUser(user1, "getCurrentUser", "getCurrentUser");
		userOne.enable();
	    MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		ESAPI.httpUtilities().setCurrentHTTP(request, response);
		userOne.loginWithPassword("getCurrentUser");
		User currentUser = instance.getCurrentUser();
		assertEquals( currentUser, userOne );
		User userTwo = instance.createUser(user2, "getCurrentUser", "getCurrentUser");		
		instance.setCurrentUser( userTwo );
		assertFalse( currentUser.getAccountName().equals( userTwo.getAccountName() ) );
		
		Runnable echo = new Runnable() {
			private int count = 1;
			public void run() {
				User u=null;
				try {
					String password = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
					u = instance.createUser("test" + count++, password, password);
					instance.setCurrentUser(u);
					ESAPI.getLogger("test").info( Logger.SECURITY_SUCCESS, "Got current user" );
					// ESAPI.authenticator().removeUser( u.getAccountName() );
				} catch (AuthenticationException e) {
					e.printStackTrace();
				}
			}
		};
		for ( int i = 0; i<10; i++ ) {
			new Thread( echo ).start();
		}
	}
	

	/**
	 * Test of setCurrentUser method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testSetCurrentUserWithRequest() throws AuthenticationException {
		System.out.println("setCurrentUser(req,resp)");
        Authenticator instance = ESAPI.authenticator();
        instance.logout();  // in case anyone is logged in
		String password = instance.generateStrongPassword();
		String accountName = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
		DefaultUser user = (DefaultUser) instance.createUser(accountName, password, password);
		user.enable();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter("username", accountName);
		request.addParameter("password", password);
		MockHttpServletResponse response = new MockHttpServletResponse();
		instance.login( request, response );
		assertEquals( user, instance.getCurrentUser() );
		try {
			user.disable();
			instance.login( request, response );
		} catch( Exception e ) {
			// expected
		}
		try {
			user.enable();
			user.lock();
			instance.login( request, response );
		} catch( Exception e ) {
			// expected
		}
		try {
			user.unlock();
			user.setExpirationTime( new Date() );
			instance.login( request, response );
		} catch( Exception e ) {
			// expected
		}
	}
	
	
	
	/**
	 * Test of validatePasswordStrength method, of class
	 * org.owasp.esapi.Authenticator.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testValidatePasswordStrength() throws AuthenticationException {
		System.out.println("validatePasswordStrength");
        Authenticator instance = ESAPI.authenticator();

		// should fail
		try {
			instance.verifyPasswordStrength("password", "jeff");
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("diff123bang", "same123string");
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("password", "JEFF");
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("password", "1234");
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("password", "password");
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("password", "-1");
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("password", "password123");
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("password", "test123");
			fail();
		} catch (AuthenticationException e) {
			// success
		}

		// should pass
		instance.verifyPasswordStrength("password", "jeffJEFF12!");
		instance.verifyPasswordStrength("password", "super calif ragil istic");
		instance.verifyPasswordStrength("password", "TONYTONYTONYTONY");
		instance.verifyPasswordStrength("password", instance.generateStrongPassword());

        // chrisisbeef - Issue 65 - http://code.google.com/p/owasp-esapi-java/issues/detail?id=65
        instance.verifyPasswordStrength("password", "b!gbr0ther");
	}

	/**
	 * Test of exists method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws Exception
	 *             the exception
	 */
	public void testExists() throws Exception {
		System.out.println("exists");
		String accountName = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
        Authenticator instance = ESAPI.authenticator();
		String password = instance.generateStrongPassword();
		instance.createUser(accountName, password, password);
		assertTrue(instance.exists(accountName));
		instance.removeUser(accountName);
		assertFalse(instance.exists(accountName));
	}

    /**
     * Test of main method, of class org.owasp.esapi.Authenticator.
     * @throws Exception
     */
    public void testMain() throws Exception {
        System.out.println("Authenticator Main");
        Authenticator instance = ESAPI.authenticator();
        String accountName = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
        String password = instance.generateStrongPassword();
        String role = "test";
        
        // test wrong parameters - missing role parameter
        String[] badargs = { accountName, password };
        FileBasedAuthenticator.main( badargs );
        // load users since the new user was added in another instance
        ((FileBasedAuthenticator)instance).loadUsersImmediately();
        User u1 = instance.getUser(accountName);
        assertNull( u1 );

        // test good parameters
        String[] args = { accountName, password, role };
        FileBasedAuthenticator.main(args);
        // load users since the new user was added in another instance
        ((FileBasedAuthenticator)instance).loadUsersImmediately();
        DefaultUser u2 = (DefaultUser) instance.getUser(accountName);
        assertNotNull( u2 );
        assertTrue( u2.isInRole(role));
        assertEquals( instance.hashPassword(password, accountName), ((FileBasedAuthenticator)instance).getHashedPassword(u2) );
    }
    
    
}
