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

import java.util.Arrays;
import java.util.Date;
import java.util.Set;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.http.TestHttpServletRequest;
import org.owasp.esapi.http.TestHttpServletResponse;
import org.owasp.esapi.interfaces.IAuthenticator;

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

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		// none
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		// none
	}

	
	/**
	 * Test of createAccount method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testCreateUser() throws AuthenticationException, EncryptionException {
		System.out.println("createUser");
		String accountName = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
		IAuthenticator instance = ESAPI.authenticator();
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
            instance.createUser(ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS), "password1", "password2"); // don't match
            fail();
        } catch (AuthenticationException e) {
            // success
        }
        try {
            instance.createUser(ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS), "weak1", "weak1");  // weak password
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
            instance.createUser(ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS), null, null);  // null password
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
		IAuthenticator instance = ESAPI.authenticator();
		String oldPassword = instance.generateStrongPassword();
		String newPassword = null;
		for (int i = 0; i < 100; i++) {
            try {
                newPassword = instance.generateStrongPassword();
                instance.verifyPasswordStrength(newPassword, oldPassword);
            } catch( AuthenticationException e ) {
            	System.out.println( "  FAILED >> " + newPassword );
                fail();
            }
		}
	}


	/**
	 * Test of getCurrentUser method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws InterruptedException *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testGetCurrentUser() throws Exception {
		System.out.println("getCurrentUser");
        Authenticator instance = (Authenticator)ESAPI.authenticator();
		String username1 = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
		String username2 = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
		User user1 = instance.createUser(username1, "getCurrentUser", "getCurrentUser");
		User user2 = instance.createUser(username2, "getCurrentUser", "getCurrentUser");		
		user1.enable();
	    TestHttpServletRequest request = new TestHttpServletRequest();
		TestHttpServletResponse response = new TestHttpServletResponse();
        instance.setCurrentHTTP(request, response);
		user1.loginWithPassword("getCurrentUser");
		User currentUser = instance.getCurrentUser();
		assertEquals( currentUser, user1 );
		instance.setCurrentUser( user2 );
		assertFalse( currentUser.getAccountName().equals( user2.getAccountName() ) );
		
		Runnable echo = new Runnable() {
			private int count = 1;
            private boolean result = false;
			public void run() {
		        Authenticator instance = (Authenticator)ESAPI.authenticator();
				User a = null;
				try {
					String password = instance.generateStrongPassword();
					String accountName = "TestAccount" + count++;
					a = instance.getUser(accountName);
					if ( a != null ) {
						instance.removeUser(accountName);
					}
					a = instance.createUser(accountName, password, password);
					instance.setCurrentUser(a);
				} catch (AuthenticationException e) {
					e.printStackTrace();
				}
				User b = instance.getCurrentUser();
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
        // FIXME: AAA need a way to get results here from runnables
	}

	/**
	 * Test of getUser method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testGetUser() throws AuthenticationException {
		System.out.println("getUser");
        IAuthenticator instance = ESAPI.authenticator();
		String password = instance.generateStrongPassword();
		String accountName=ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
		instance.createUser(accountName, password, password);
		assertNotNull(instance.getUser( accountName ));
		assertNull(instance.getUser( ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS) ));
	}
	
	/**
	 * Test get user from session.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testGetUserFromSession() throws AuthenticationException {
		System.out.println("getUserFromSession");
        Authenticator instance = (Authenticator)ESAPI.authenticator();
		String accountName=ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
		String password = instance.generateStrongPassword();
		User user = instance.createUser(accountName, password, password);
		user.enable();
		TestHttpServletRequest request = new TestHttpServletRequest();
		request.addParameter("username", accountName);
		request.addParameter("password", password);
		TestHttpServletResponse response = new TestHttpServletResponse();
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
        IAuthenticator instance = ESAPI.authenticator();
		String password = instance.generateStrongPassword();
		String[] testnames = new String[10];
		for(int i=0;i<testnames.length;i++) {
			testnames[i] = ESAPI.randomizer().getRandomString(8,Encoder.CHAR_ALPHANUMERICS);
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
	 */
	public void testHashPassword() throws EncryptionException {
		System.out.println("hashPassword");
		String username = "Jeff";
		String password = "test";
        IAuthenticator instance = ESAPI.authenticator();
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
        IAuthenticator instance = ESAPI.authenticator();
        String username = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
		String password = instance.generateStrongPassword();
		User user = instance.createUser(username, password, password);
		user.enable();
		TestHttpServletRequest request = new TestHttpServletRequest();
		request.addParameter("username", username);
		request.addParameter("password", password);
		TestHttpServletResponse response = new TestHttpServletResponse();
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
		String accountName = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
        IAuthenticator instance = ESAPI.authenticator();
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
		String accountName = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
        Authenticator instance = (Authenticator)ESAPI.authenticator();
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
        final Authenticator instance = (Authenticator)ESAPI.authenticator();
		String user1 = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_UPPERS);
		String user2 = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_UPPERS);
		User userOne = instance.createUser(user1, "getCurrentUser", "getCurrentUser");
		userOne.enable();
	    TestHttpServletRequest request = new TestHttpServletRequest();
		TestHttpServletResponse response = new TestHttpServletResponse();
		instance.setCurrentHTTP(request, response);
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
					String password = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
					u = instance.createUser("test" + count++, password, password);
					instance.setCurrentUser(u);
					Logger.getLogger("test", "test").logCritical( Logger.SECURITY, "Got current user" );
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
        IAuthenticator instance = ESAPI.authenticator();
		String password = instance.generateStrongPassword();
		String accountName = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
		User user = instance.createUser(accountName, password, password);
		user.enable();
		TestHttpServletRequest request = new TestHttpServletRequest();
		request.addParameter("username", accountName);
		request.addParameter("password", password);
		TestHttpServletResponse response = new TestHttpServletResponse();
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
        IAuthenticator instance = ESAPI.authenticator();

		// should fail
		try {
			instance.verifyPasswordStrength("jeff", "password");
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("same123string", "diff123bang");
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("JEFF", "password");
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("1234", "password");
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
			instance.verifyPasswordStrength("-1", "password");
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("password123", "password");
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("test123", "password");
			fail();
		} catch (AuthenticationException e) {
			// success
		}

		// should pass
		instance.verifyPasswordStrength("jeffJEFF12!", "password");
		instance.verifyPasswordStrength("super calif ragil istic", "password");
		instance.verifyPasswordStrength("TONYTONYTONYTONY", "password");
		instance.verifyPasswordStrength(instance.generateStrongPassword(), "password");
	}

	/**
	 * Test of exists method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws Exception
	 *             the exception
	 */
	public void testExists() throws Exception {
		System.out.println("exists");
		String accountName = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
        IAuthenticator instance = ESAPI.authenticator();
		String password = instance.generateStrongPassword();
		instance.createUser(accountName, password, password);
		assertTrue(instance.exists(accountName));
		instance.removeUser(accountName);
		assertFalse(instance.exists(accountName));
	}

    /**
     * Test of main method, of class org.owasp.esapi.Authenticator.
     */
    public void testMain() throws Exception {
        System.out.println("Authenticator Main");
        IAuthenticator instance = ESAPI.authenticator();
        String accountName = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
        String password = instance.generateStrongPassword();
        String role = "test";
        
        // test wrong parameters - missing role parameter
        String[] badargs = { accountName, password };
        Authenticator.main( badargs );
        // load users since the new user was added in another instance
        ((Authenticator)instance).loadUsersImmediately();
        User u1 = instance.getUser(accountName);
        assertNull( u1 );

        // test good parameters
        String[] args = { accountName, password, role };
        Authenticator.main(args);
        // load users since the new user was added in another instance
        ((Authenticator)instance).loadUsersImmediately();
        User u2 = instance.getUser(accountName);
        assertNotNull( u2 );
        assertTrue( u2.isInRole(role));
        assertEquals( instance.hashPassword(password, accountName), u2.getHashedPassword() );
    }
    
    
}
