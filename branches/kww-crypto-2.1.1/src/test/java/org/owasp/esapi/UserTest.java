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
package org.owasp.esapi;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class UserTest extends TestCase {

	public UserTest(String testName) {
		super(testName);
	}

	protected void setUp() throws Exception {
		// none
	}

	protected void tearDown() throws Exception {
		// none
	}

	public static Test suite() {
		TestSuite suite = new TestSuite(UserTest.class);
		return suite;
	}
	
	public void testAllMethods() throws Exception {
		// create a user to test Anonymous
		String accountName = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
		Authenticator instance = ESAPI.authenticator();
		String password = instance.generateStrongPassword();
		
			// Probably could skip the assignment here, but maybe someone had
			// future plans to use this. So will just suppress warning for now.
		@SuppressWarnings("unused")
		User user = instance.createUser(accountName, password, password);
		
		// test the rest of the Anonymous user
		try { User.ANONYMOUS.addRole(null); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.addRoles(null); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.changePassword(null, null, null); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.disable(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.enable(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.getAccountId(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.getAccountName(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.getName(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.getCSRFToken(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.getExpirationTime(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.getFailedLoginCount(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.getLastFailedLoginTime(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.getLastLoginTime(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.getLastPasswordChangeTime(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.getRoles(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.getScreenName(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.addSession(null); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.removeSession(null); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.incrementFailedLoginCount(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.isAnonymous(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.isEnabled(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.isExpired(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.isInRole(null); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.isLocked(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.isLoggedIn(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.isSessionAbsoluteTimeout(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.isSessionTimeout(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.lock(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.loginWithPassword(null); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.logout(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.removeRole(null); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.resetCSRFToken(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.setAccountName(null); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.setExpirationTime(null); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.setRoles(null); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.setScreenName(null); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.unlock(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.verifyPassword(null); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.setLastFailedLoginTime(null); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.setLastLoginTime(null); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.setLastHostAddress(null); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.setLastPasswordChangeTime(null); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.getEventMap(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.getLocale(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.setLocale(null); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.getAccountName(); } catch( RuntimeException e ) {}
		try { User.ANONYMOUS.getAccountName(); } catch( RuntimeException e ) {}
	}
}


