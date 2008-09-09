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

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.http.TestHttpServletRequest;
import org.owasp.esapi.http.TestHttpServletResponse;
import org.owasp.esapi.http.TestHttpSession;
import org.owasp.esapi.interfaces.IAuthenticator;

/**
 * The Class UserTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class UserTest extends TestCase {

	/**
	 * Suite.
	 * 
	 * @return the test
	 */
	public static Test suite() {
		TestSuite suite = new TestSuite(UserTest.class);
		return suite;
	}
	
	/**
	 * Instantiates a new user test.
	 * 
	 * @param testName
	 *            the test name
	 */
	public UserTest(String testName) {
		super(testName);
	}

	/**
	 * Creates the test user.
	 * 
	 * @param password
	 *            the password
	 * 
	 * @return the user
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	private User createTestUser(String password) throws AuthenticationException {
		String username = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
		User user = ESAPI.authenticator().createUser(username, password, password);
		return user;
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
	 * Test of testAddRole method, of class org.owasp.esapi.User.
	 */
	public void testAddRole() throws Exception {
		System.out.println("addRole");
		IAuthenticator instance = ESAPI.authenticator();
		String accountName = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
		String password = ESAPI.authenticator().generateStrongPassword();
		String role = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_LOWERS);
		User user = instance.createUser(accountName, password, password);
		user.addRole(role);
		assertTrue(user.isInRole(role));
		assertFalse(user.isInRole("ridiculous"));
	}

	/**
	 * Test of addRoles method, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testAddRoles() throws AuthenticationException {
		System.out.println("addRoles");
		IAuthenticator instance = ESAPI.authenticator();
		String oldPassword = instance.generateStrongPassword();
		User user = createTestUser(oldPassword);
		Set set = new HashSet();
		set.add("rolea");
		set.add("roleb");
		user.addRoles(set);
		assertTrue(user.isInRole("rolea"));
		assertTrue(user.isInRole("roleb"));
		assertFalse(user.isInRole("ridiculous"));
	}

	/**
	 * Test of changePassword method, of class org.owasp.esapi.User.
	 * 
	 * @throws Exception
	 *             the exception
	 */
	public void testChangePassword() throws Exception {
		System.out.println("changePassword");
		IAuthenticator instance = ESAPI.authenticator();
		String oldPassword = instance.generateStrongPassword();
		User user = createTestUser(oldPassword);
		String password1 = instance.generateStrongPassword();
		user.changePassword(oldPassword, password1, password1);
		assertTrue(user.verifyPassword(password1));
		String password2 = instance.generateStrongPassword();
		user.changePassword(password1, password2, password2);
		try {
			user.changePassword(password2, password1, password1);
		} catch( AuthenticationException e ) {
			// expected
		}
		assertTrue(user.verifyPassword(password2));
		assertFalse(user.verifyPassword("badpass"));
	}

	/**
	 * Test of disable method, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testDisable() throws AuthenticationException {
		System.out.println("disable");
		IAuthenticator instance = ESAPI.authenticator();
		String oldPassword = instance.generateStrongPassword();
		User user = createTestUser(oldPassword);
		user.enable();
		assertTrue(user.isEnabled());
		user.disable();
		assertFalse(user.isEnabled());
	}

	/**
	 * Test of enable method, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testEnable() throws AuthenticationException {
		System.out.println("enable");
		IAuthenticator instance = ESAPI.authenticator();
		String oldPassword = instance.generateStrongPassword();
		User user = createTestUser(oldPassword);
		user.enable();
		assertTrue(user.isEnabled());
		user.disable();
		assertFalse(user.isEnabled());
	}

	/**
	 * Test equals.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testEquals() throws AuthenticationException {
		IAuthenticator instance = ESAPI.authenticator();
		String password = instance.generateStrongPassword();
		User a = new User("userA",password,password);
		User b = new User("userA","differentPass","differentPass");
		a.enable();
		assertTrue(a.equals(b));
	}
	
	/**
	 * Test of failedLoginCount lockout, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testFailedLoginLockout() throws AuthenticationException, EncryptionException {
		System.out.println("failedLoginLockout");
		IAuthenticator instance = ESAPI.authenticator();
		User user = createTestUser("failedLoginLockout");
		String password = instance.generateStrongPassword();
		user.unlock();
		user.changePassword("failedLoginLockout", password, password);
		user.verifyPassword(password);
		user.verifyPassword("ridiculous");
		System.out.println("FAILED: " + user.getFailedLoginCount());
		assertFalse(user.isLocked());
		user.verifyPassword("ridiculous");
		System.out.println("FAILED: " + user.getFailedLoginCount());
		assertFalse(user.isLocked());
		user.verifyPassword("ridiculous");
		System.out.println("FAILED: " + user.getFailedLoginCount());
		assertTrue(user.isLocked());
	}

	/**
	 * Test of getAccountName method, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testGetAccountName() throws AuthenticationException {
		System.out.println("getAccountName");
		User user = createTestUser("getAccountName");
		String accountName = ESAPI.randomizer().getRandomString(7, Encoder.CHAR_ALPHANUMERICS);
		user.setAccountName(accountName);
		assertEquals(accountName.toLowerCase(), user.getAccountName());
		assertFalse("ridiculous".equals(user.getAccountName()));
	}

	/**
	 * Test get last failed login time.
	 * 
	 * @throws Exception
	 *             the exception
	 */
	public void testGetLastFailedLoginTime() throws Exception {
		System.out.println("getLastLoginTime");
		IAuthenticator instance = ESAPI.authenticator();
		String oldPassword = instance.generateStrongPassword();
		User user = createTestUser(oldPassword);
		user.verifyPassword("ridiculous");
		Date llt1 = user.getLastFailedLoginTime();
		Thread.sleep(10); // need a short delay to separate attempts
		user.verifyPassword("ridiculous");
		Date llt2 = user.getLastFailedLoginTime();
		assertTrue(llt1.before(llt2));
	}

	/**
	 * Test get last login time.
	 * 
	 * @throws Exception
	 *             the exception
	 */
	public void testGetLastLoginTime() throws Exception {
		System.out.println("getLastLoginTime");
		IAuthenticator instance = ESAPI.authenticator();
		String oldPassword = instance.generateStrongPassword();
		User user = createTestUser(oldPassword);
		user.verifyPassword(oldPassword);
		Date llt1 = user.getLastLoginTime();
		Thread.sleep(10); // need a short delay to separate attempts
		user.verifyPassword(oldPassword);
		Date llt2 = user.getLastLoginTime();
		assertTrue(llt1.before(llt2));
	}

	/**
	 * Test of getLastPasswordChangeTime method, of class org.owasp.esapi.User.
	 * 
	 * @throws Exception
	 *             the exception
	 */
	public void testGetLastPasswordChangeTime() throws Exception {
		System.out.println("getLastPasswordChangeTime");
		User user = createTestUser("getLastPasswordChangeTime");
		Date t1 = user.getLastPasswordChangeTime();
		Thread.sleep(10); // need a short delay to separate attempts
		String newPassword = ESAPI.authenticator().generateStrongPassword("getLastPasswordChangeTime", user);
		user.changePassword("getLastPasswordChangeTime", newPassword, newPassword);
		Date t2 = user.getLastPasswordChangeTime();
		assertTrue(t2.after(t1));
	}

	/**
	 * Test of getRoles method, of class org.owasp.esapi.User.
	 */
	public void testGetRoles() throws Exception {
		System.out.println("getRoles");
		IAuthenticator instance = ESAPI.authenticator();
		String accountName = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
		String password = ESAPI.authenticator().generateStrongPassword();
		String role = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_LOWERS);
		User user = instance.createUser(accountName, password, password);
		user.addRole(role);
		Set roles = user.getRoles();
		assertTrue(roles.size() > 0);
	}

	/**
	 * Test of xxx method, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testGetScreenName() throws AuthenticationException {
		System.out.println("getScreenName");
		User user = createTestUser("getScreenName");
		String screenName = ESAPI.randomizer().getRandomString(7, Encoder.CHAR_ALPHANUMERICS);
		user.setScreenName(screenName);
		assertEquals(screenName, user.getScreenName());
		assertFalse("ridiculous".equals(user.getScreenName()));
	}

	/**
	 * Test of incrementFailedLoginCount method, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testIncrementFailedLoginCount() throws AuthenticationException {
		System.out.println("incrementFailedLoginCount");
		User user = createTestUser("incrementFailedLoginCount");
		user.enable();
		assertEquals(0, user.getFailedLoginCount());
		TestHttpServletRequest request = new TestHttpServletRequest();
		TestHttpServletResponse response = new TestHttpServletResponse();
        ((Authenticator)ESAPI.authenticator()).setCurrentHTTP(request, response);
		try {
			user.loginWithPassword("ridiculous");
		} catch (AuthenticationException e) {
			// expected
		}
		assertEquals(1, user.getFailedLoginCount());
		try {
			user.loginWithPassword("ridiculous");
		} catch (AuthenticationException e) {
			// expected
		}
		assertEquals(2, user.getFailedLoginCount());
		try {
			user.loginWithPassword("ridiculous");
		} catch (AuthenticationException e) {
			// expected
		}
		assertEquals(3, user.getFailedLoginCount());
		try {
			user.loginWithPassword("ridiculous");
		} catch (AuthenticationException e) {
			// expected
		}
		assertTrue(user.isLocked());
	}

	/**
	 * Test of isEnabled method, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testIsEnabled() throws AuthenticationException {
		System.out.println("isEnabled");
		User user = createTestUser("isEnabled");
		user.disable();
		assertFalse(user.isEnabled());
		user.enable();
		assertTrue(user.isEnabled());
	}

    
    /**
     * Test of isFirstRequest method, of class org.owasp.esapi.User.
     */
    public void testIsFirstRequest() throws AuthenticationException {
        System.out.println("isFirstRequest");
        TestHttpServletRequest request = new TestHttpServletRequest();
        TestHttpServletResponse response = new TestHttpServletResponse();
        IAuthenticator instance = ESAPI.authenticator();
        String password = instance.generateStrongPassword();
        User user = instance.createUser("isFirstRequest", password, password);
        user.enable();
        request.addParameter(ESAPI.securityConfiguration().getPasswordParameterName(), password );
        request.addParameter(ESAPI.securityConfiguration().getUsernameParameterName(), "isFirstRequest" );
        instance.login(request, response);
        assertTrue( user.isFirstRequest() );
        instance.login(request, response);
        assertFalse( user.isFirstRequest() );
        instance.login(request, response);
        assertFalse( user.isFirstRequest() );
    }
    
    
	/**
	 * Test of isInRole method, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testIsInRole() throws AuthenticationException {
		System.out.println("isInRole");
		User user = createTestUser("isInRole");
		String role = "TestRole";
		assertFalse(user.isInRole(role));
		user.addRole(role);
		assertTrue(user.isInRole(role));
		assertFalse(user.isInRole("Ridiculous"));
	}

	/**
	 * Test of xxx method, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testIsLocked() throws AuthenticationException {
		System.out.println("isLocked");
		User user = createTestUser("isLocked");
		user.lock();
		assertTrue(user.isLocked());
		user.unlock();
		assertFalse(user.isLocked());
	}

	/**
	 * Test of isSessionAbsoluteTimeout method, of class
	 * org.owasp.esapi.IntrusionDetector.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testIsSessionAbsoluteTimeout() throws AuthenticationException {
		// FIXME: ENHANCE shouldn't this just be one timeout method that does both checks???
		System.out.println("isSessionAbsoluteTimeout");
		IAuthenticator instance = ESAPI.authenticator();
		String oldPassword = instance.generateStrongPassword();
		User user = createTestUser(oldPassword);
		long now = System.currentTimeMillis();
		TestHttpSession s1 = new TestHttpSession(now - 1000 * 60 * 60 * 3, now);
		assertTrue(user.isSessionAbsoluteTimeout(s1));
		TestHttpSession s2 = new TestHttpSession(now - 1000 * 60 * 60 * 1, now);
		assertFalse(user.isSessionAbsoluteTimeout(s2));
	}

	/**
	 * Test of isSessionTimeout method, of class
	 * org.owasp.esapi.IntrusionDetector.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testIsSessionTimeout() throws AuthenticationException {
		System.out.println("isSessionTimeout");
		IAuthenticator instance = ESAPI.authenticator();
		String oldPassword = instance.generateStrongPassword();
		User user = createTestUser(oldPassword);
		long now = System.currentTimeMillis();
		TestHttpSession s1 = new TestHttpSession(now - 1000 * 60 * 60 * 3, now - 1000 * 60 * 30);
		assertTrue(user.isSessionAbsoluteTimeout(s1));
		TestHttpSession s2 = new TestHttpSession(now - 1000 * 60 * 60 * 3, now - 1000 * 60 * 10);
		assertFalse(user.isSessionTimeout(s2));
	}

	/**
	 * Test of lockAccount method, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testLock() throws AuthenticationException {
		System.out.println("lock");
		IAuthenticator instance = ESAPI.authenticator();
		String oldPassword = instance.generateStrongPassword();
		User user = createTestUser(oldPassword);
		user.lock();
		assertTrue(user.isLocked());
		user.unlock();
		assertFalse(user.isLocked());
	}

	/**
	 * Test of loginWithPassword method, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testLoginWithPassword() throws AuthenticationException {
		System.out.println("loginWithPassword");
		TestHttpServletRequest request = new TestHttpServletRequest();
		TestHttpSession session = (TestHttpSession) request.getSession();
		assertFalse(session.getInvalidated());
		User user = createTestUser("loginWithPassword");
		user.enable();
		user.loginWithPassword("loginWithPassword");
		assertTrue(user.isLoggedIn());
		user.logout();
		assertFalse(user.isLoggedIn());
		assertFalse(user.isLocked());
		try {
			user.loginWithPassword("ridiculous");
		} catch (AuthenticationException e) {
			// expected
		}
		assertFalse(user.isLoggedIn());
		try {
			user.loginWithPassword("ridiculous");
		} catch (AuthenticationException e) {
			// expected
		}
		try {
			user.loginWithPassword("ridiculous");
		} catch (AuthenticationException e) {
			// expected
		}
		assertTrue(user.isLocked());
	}


	/**
	 * Test of logout method, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testLogout() throws AuthenticationException {
		System.out.println("logout");
		TestHttpServletRequest request = new TestHttpServletRequest();
		TestHttpServletResponse response = new TestHttpServletResponse();
		TestHttpSession session = (TestHttpSession) request.getSession();
		assertFalse(session.getInvalidated());
		IAuthenticator instance = ESAPI.authenticator();
		((Authenticator)instance).setCurrentHTTP(request, response);
		String oldPassword = instance.generateStrongPassword();
		User user = createTestUser(oldPassword);
		user.enable();
		System.out.println(user.getLastLoginTime());
		user.loginWithPassword(oldPassword);
		assertTrue(user.isLoggedIn());
		// get new session after user logs in
		session = (TestHttpSession) request.getSession();
		assertFalse(session.getInvalidated());
		user.logout();
		assertFalse(user.isLoggedIn());
		assertTrue(session.getInvalidated());
	}

	/**
	 * Test of testRemoveRole method, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testRemoveRole() throws AuthenticationException {
		System.out.println("removeRole");
		String role = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_LOWERS);
		User user = createTestUser("removeRole");
		user.addRole(role);
		assertTrue(user.isInRole(role));
		user.removeRole(role);
		assertFalse(user.isInRole(role));
	}

	/**
	 * Test of testResetCSRFToken method, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testResetCSRFToken() throws AuthenticationException {
		System.out.println("resetCSRFToken");
		User user = createTestUser("resetCSRFToken");
        String token1 = user.resetCSRFToken();
        String token2 = user.resetCSRFToken();
        assertFalse( token1.equals( token2 ) );
	}
	
	/**
	 * Test reset password.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testResetPassword() throws AuthenticationException, EncryptionException {
		System.out.println("resetPassword");
		User user = createTestUser("resetPassword");
        for ( int i = 0; i<20; i++) {
            assertTrue(user.verifyPassword(user.resetPassword()));
        }
	}

	/**
	 * Test of generateRememberMeToken method, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testResetRememberToken() throws AuthenticationException {
		System.out.println("resetRememberToken");
		User user = createTestUser("resetRememberToken");
		String token = user.resetRememberToken();
        assertEquals(token, user.getRememberToken() );
	}

	/**
	 * Test of setAccountName method, of class org.owasp.esapi.User.
	 */
	public void testSetAccountName() throws AuthenticationException {
		System.out.println("setAccountName");
		User user = createTestUser("setAccountName");
		String accountName = ESAPI.randomizer().getRandomString(7, Encoder.CHAR_ALPHANUMERICS);
		user.setAccountName(accountName);
		assertEquals(accountName.toLowerCase(), user.getAccountName());
		assertFalse("ridiculous".equals(user.getAccountName()));
	}

	/**
	 * Test of setExpirationTime method, of class org.owasp.esapi.User.
	 */
	public void testSetExpirationTime() throws Exception {
		System.out.println("setAccountName");
		String password=ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
		User user = createTestUser(password);
		user.setExpirationTime(new Date(0));
		assertTrue( user.isExpired() );
	}

	
	/**
	 * Test of setRoles method, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testSetRoles() throws AuthenticationException {
		System.out.println("setRoles");
		User user = createTestUser("setRoles");
		user.addRole("user");
		assertTrue(user.isInRole("user"));
		Set set = new HashSet();
		set.add("rolea");
		set.add("roleb");
		user.setRoles(set);
		assertFalse(user.isInRole("user"));
		assertTrue(user.isInRole("rolea"));
		assertTrue(user.isInRole("roleb"));
		assertFalse(user.isInRole("ridiculous"));
	}

	/**
	 * Test of setScreenName method, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testSetScreenName() throws AuthenticationException {
		System.out.println("setScreenName");
		User user = createTestUser("setScreenName");
		String screenName = ESAPI.randomizer().getRandomString(7, Encoder.CHAR_ALPHANUMERICS);
		user.setScreenName(screenName);
		assertEquals(screenName, user.getScreenName());
		assertFalse("ridiculous".equals(user.getScreenName()));
	}

	/**
	 * Test of unlockAccount method, of class org.owasp.esapi.User.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void testUnlock() throws AuthenticationException {
		System.out.println("unlockAccount");
		IAuthenticator instance = ESAPI.authenticator();
		String oldPassword = instance.generateStrongPassword();
		User user = createTestUser(oldPassword);
		user.lock();
		assertTrue(user.isLocked());
		user.unlock();
		assertFalse(user.isLocked());
	}

}
