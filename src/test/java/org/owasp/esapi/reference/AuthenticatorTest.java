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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import java.util.Calendar;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.hamcrest.core.IsEqual;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ErrorCollector;
import org.junit.rules.TestName;
import org.junit.rules.Timeout;
import org.owasp.esapi.Authenticator;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.EncoderConstants;
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
public class AuthenticatorTest {
    private static Authenticator instance;
    /** 
     * User session information is stored on a per-thread basis.  So long as this has potential to run single threaded then we'll maintain a synchronous nature execution.
     * This is done to prevent tests corrupting each others states since all will be executed on a limited set of Threads within the JVM.
     */
    private static Semaphore threadIsolation = new Semaphore(1, true);

    @Rule
    public ErrorCollector collector = new ErrorCollector();
    @Rule
    public Timeout testTimout = new Timeout(5, TimeUnit.MINUTES);
    @Rule
    public TestName name = new TestName();

    @BeforeClass
    public static void setUpStatic() {
        instance = ESAPI.authenticator();
    }

    @Before
    public void setup() throws InterruptedException {
        while (!threadIsolation.tryAcquire(500, TimeUnit.MILLISECONDS)) {
            //Spurious Interrupt Guard
        }       
    }

    @After
    public void cleanup() {
        try {
            instance.logout();
            instance.clearCurrent();
            HttpServletRequest request = ESAPI.httpUtilities().getCurrentRequest();
            HttpServletResponse response = ESAPI.httpUtilities().getCurrentResponse();
            if (request != null  && response != null) {
                //I don't know why killAllCookies doesn't nullcheck state.  I'm assuming this is unique to the test environment.
                ESAPI.httpUtilities().killAllCookies();
            }
            ESAPI.httpUtilities().clearCurrent();
        } finally {
            threadIsolation.release();
        }
    }

	
	/**
	 * Test of createAccount method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws AuthenticationException
     *             the authentication exception
     * @throws EncryptionException
	 */
	@Test public void testCreateUser() throws AuthenticationException, EncryptionException {
		System.out.println("createUser");
		String accountName = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
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
            instance.createUser(ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS), "password1", "password2"); // don't match
            fail();
        } catch (AuthenticationException e) {
            // success
        }
        try {
            instance.createUser(ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS), "weak1", "weak1");  // weak password
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
            instance.createUser(ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS), null, null);  // null password
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
	@Test public void testGenerateStrongPassword() throws AuthenticationException {
		System.out.println("generateStrongPassword");		
		String oldPassword = "iiiiiiiiii";  // i is not allowed in passwords - this prevents failures from containing pieces of old password
		String newPassword = null;
		String username = "FictionalEsapiUser";
		User user = new DefaultUser(username);
		for (int i = 0; i < 100; i++) {
            try {
                newPassword = instance.generateStrongPassword();
                instance.verifyPasswordStrength(oldPassword, newPassword, user);
            } catch( AuthenticationException e ) {
            	System.out.println( "  FAILED >> " + newPassword + " : " + e.getLogMessage());
                fail();
            }
		}
		try {
			instance.verifyPasswordStrength("test56^$test", "abcdx56^$sl", user );
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
	@Test public void testGetCurrentUser() throws Exception {
		System.out.println("getCurrentUser");
		String username1 = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
		String username2 = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
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
			public void run() {
				User a = null;
				try {
					String password = instance.generateStrongPassword();
					//Create account name using random strings to guarantee uniqueness among running threads.
                    String accountName=ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
					a = instance.getUser(accountName);
					if ( a != null ) {
					    instance.removeUser(accountName);
					}
					a = instance.createUser(accountName, password, password);
					instance.setCurrentUser(a);
				} catch (AuthenticationException e) {
				    //Use ErrorCollector to fail test.
                    collector.addError(e);
				}
				User b = instance.getCurrentUser();
				collector.checkThat("Logged in user should equal original user", a.equals(b), new IsEqual<Boolean>(Boolean.TRUE));
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
	@Test public void testGetUser() throws AuthenticationException {
		System.out.println("getUser");
		String password = instance.generateStrongPassword();
		String accountName=ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
		instance.createUser(accountName, password, password);
		assertNotNull(instance.getUser( accountName ));
		assertNull(instance.getUser( ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS) ));
	}
	
    /**
     *
     * @throws org.owasp.esapi.errors.AuthenticationException
     */
    @Test public void testGetUserFromRememberToken() throws AuthenticationException {
		System.out.println("getUserFromRememberToken");
		String password = instance.generateStrongPassword();
		String accountName=ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
		User user = instance.createUser(accountName, password, password);
		user.enable();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		ESAPI.httpUtilities().setCurrentHTTP(request, response);
		
		System.out.println("getUserFromRememberToken - expecting failure");
		request.setCookie( HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME, "ridiculous" );
		try {
			instance.login( request, response );  // wrong cookie will fail
			fail();
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
	@Test public void testGetUserFromSession() throws AuthenticationException {
		System.out.println("getUserFromSession");
		assumeTrue(instance instanceof FileBasedAuthenticator);
		String accountName=ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
		String password = instance.generateStrongPassword();
		User user = instance.createUser(accountName, password, password);
		user.enable();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter("username", accountName);
		request.addParameter("password", password);
		MockHttpServletResponse response = new MockHttpServletResponse();
		ESAPI.httpUtilities().setCurrentHTTP( request, response );
		instance.login( request, response);
		User test = ((FileBasedAuthenticator)instance).getUserFromSession();
		assertEquals( user, test );
	}

	/**
	 * Test get user names.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	@Test public void testGetUserNames() throws AuthenticationException {
		System.out.println("getUserNames");
		String password = instance.generateStrongPassword();
		String[] testnames = new String[10];
		for(int i=0;i<testnames.length;i++) {
			testnames[i] = ESAPI.randomizer().getRandomString(8,EncoderConstants.CHAR_ALPHANUMERICS);
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
	@Test public void testHashPassword() throws EncryptionException {
		System.out.println("hashPassword");
		String username = "Jeff";
		String password = "test";
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
	@Test public void testLogin() throws AuthenticationException {
		System.out.println("login");
        String username = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
		String password = instance.generateStrongPassword();
		User user = instance.createUser(username, password, password);
		user.enable();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter("username", username);
		request.addParameter("password", password);
		MockHttpServletResponse response = new MockHttpServletResponse();
		ESAPI.httpUtilities().setCurrentHTTP(request, response);
		User test = instance.login( request, response);
		assertTrue( test.isLoggedIn() );
		assertSame(user, test);
	}
	
	/**
	 * Test of removeAccount method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws Exception
	 *             the exception
	 */
	@Test public void testRemoveUser() throws Exception {
		System.out.println("removeUser");
		String accountName = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
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
	@Test public void testSaveUsers() throws Exception {
		System.out.println("saveUsers");
		assumeTrue(instance instanceof FileBasedAuthenticator);
		String accountName = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
		String password = instance.generateStrongPassword();
		instance.createUser(accountName, password, password);
		((FileBasedAuthenticator)instance).saveUsers();
		assertNotNull( instance.getUser(accountName) );
		instance.removeUser(accountName);
		assertNull( instance.getUser(accountName) );
	}

	
	/**
	 * Test of setCurrentUser method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 * @throws InterruptedException Thrown if test is interrupted while awaiting completion of child threads.
	 */
	@Test public void testSetCurrentUser() throws AuthenticationException, InterruptedException {
		System.out.println("setCurrentUser");
        String user1 = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_UPPERS);
		String user2 = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_UPPERS);
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
		final CountDownLatch latch = new CountDownLatch(10);
		Runnable echo = new Runnable() {
			public void run() {
				User u=null;
				try {
				  //Increase pwd size to guarantee greater than (not "or equal to") 16 strength.  See FileBasedAuthenticator 711-715
                    String password = ESAPI.randomizer().getRandomString(17, EncoderConstants.CHAR_ALPHANUMERICS);
                    String username = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
					u = instance.createUser(username, password, password);
					instance.setCurrentUser(u);
					ESAPI.getLogger("test").info( Logger.SECURITY_SUCCESS, "Got current user" );
					//If the user isn't removed every subsequent execution will fail because we cannot create a duplicate user of the same name!
                    instance.removeUser( u.getAccountName() );
				} catch (AuthenticationException e) {
				    collector.addError(e);
                } finally {
                    latch.countDown();
                }
			}
		};
		for ( int i = 0; i<10; i++ ) {
			new Thread( echo ).start();
		}
		while(!latch.await(500, TimeUnit.MILLISECONDS)) {
            //Spurious Interrupt Guard. 
        }
	}
	


    /**
     * Test of setCurrentUser method, of class org.owasp.esapi.Authenticator.
     * 
     * @throws AuthenticationException
     *             the authentication exception
     */
    @Test public void testSetCurrentUserWithRequest() throws AuthenticationException {
        instance.logout();  // in case anyone is logged in
        String password = instance.generateStrongPassword();
        String accountName = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
        DefaultUser user = (DefaultUser) instance.createUser(accountName, password, password);
        user.enable();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("username", accountName);
        request.addParameter("password", password);
        MockHttpServletResponse response = new MockHttpServletResponse();
        ESAPI.httpUtilities().setCurrentHTTP(request, response);
        User loggedIn = instance.login( request, response );
        User currentUser = instance.getCurrentUser();
        assertTrue(loggedIn.isLoggedIn());
        assertSame(currentUser, loggedIn);
        assertSame(user, loggedIn);
    }

    /**
     * Test of setCurrentUser method, of class org.owasp.esapi.Authenticator.
     * 
     * @throws AuthenticationException
     *             the authentication exception
     */
    @Test public void testSetCurrentUserWithRequestDisabledAccount() throws AuthenticationException {
        instance.logout();  // in case anyone is logged in
        String password = instance.generateStrongPassword();
        String accountName = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
        DefaultUser user = (DefaultUser) instance.createUser(accountName, password, password);
        user.enable();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("username", accountName);
        request.addParameter("password", password);
        MockHttpServletResponse response = new MockHttpServletResponse();
        ESAPI.httpUtilities().setCurrentHTTP(request, response);
        try {
            user.disable();
            instance.login( request, response );
            fail("Disabled User Account should not be able to log in.");
        } catch( AuthenticationException e ) {
            // expected
        }
    }
    
    /**
     * Test of setCurrentUser method, of class org.owasp.esapi.Authenticator.
     * 
     * @throws AuthenticationException
     *             the authentication exception
     */
    @Test public void testSetCurrentUserWithRequestLockedAccount() throws AuthenticationException {
        instance.logout();  // in case anyone is logged in
        String password = instance.generateStrongPassword();
        String accountName = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
        DefaultUser user = (DefaultUser) instance.createUser(accountName, password, password);
        user.enable();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("username", accountName);
        request.addParameter("password", password);
        MockHttpServletResponse response = new MockHttpServletResponse();
        ESAPI.httpUtilities().setCurrentHTTP(request, response);
        try {
            user.lock();
            instance.login( request, response );
            fail("Locked User Account should not be able to log in.");
        } catch( AuthenticationException e ) {
            // expected
        }
    }
    /**
     * Test of setCurrentUser method, of class org.owasp.esapi.Authenticator.
     * 
     * @throws AuthenticationException
     *             the authentication exception
     */
    @Test public void testSetCurrentUserWithRequestExpiredAccount() throws AuthenticationException {
        instance.logout();  // in case anyone is logged in
        String password = instance.generateStrongPassword();
        String accountName = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
        DefaultUser user = (DefaultUser) instance.createUser(accountName, password, password);
        user.enable();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("username", accountName);
        request.addParameter("password", password);
        MockHttpServletResponse response = new MockHttpServletResponse();
        ESAPI.httpUtilities().setCurrentHTTP(request, response);
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, -1);
        try {
            user.unlock();
            user.setExpirationTime( calendar.getTime() );
            instance.login( request, response );
            fail("Expired User account should not be allowed to log in.");
        } catch( AuthenticationException e ) {
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
	@Test public void testValidatePasswordStrength() throws AuthenticationException {
		System.out.println("validatePasswordStrength");
        
        String username = "FictionalEsapiUser";
		User user = new DefaultUser(username);

		// should fail
		try {
			instance.verifyPasswordStrength("password", "jeff", user);
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("diff123bang", "same123string", user);
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("password", "JEFF", user);
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("password", "1234", user);
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("password", "password", user);
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("password", "-1", user);
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("password", "password123", user);
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("password", "test123", user);
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		//jtm - 11/16/2010 - fix for bug http://code.google.com/p/owasp-esapi-java/issues/detail?id=108
		try {
			instance.verifyPasswordStrength("password", "FictionalEsapiUser", user);
			fail();
		} catch (AuthenticationException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength("password", "FICTIONALESAPIUSER", user);
			fail();
		} catch (AuthenticationException e) {
			// success
		}

		// should pass
		instance.verifyPasswordStrength("password", "jeffJEFF12!", user);
		instance.verifyPasswordStrength("password", "super calif ragil istic", user);
		instance.verifyPasswordStrength("password", "TONYTONYTONYTONY", user);
		instance.verifyPasswordStrength("password", instance.generateStrongPassword(), user);

        // chrisisbeef - Issue 65 - http://code.google.com/p/owasp-esapi-java/issues/detail?id=65
        instance.verifyPasswordStrength("password", "b!gbr0ther", user);
	}

	/**
	 * Test of exists method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws Exception
	 *             the exception
	 */
	@Test public void testExists() throws Exception {
		System.out.println("exists");
		String accountName = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
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
    @Test public void testMain() throws Exception {
        System.out.println("Authenticator Main");
        String accountName = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
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
