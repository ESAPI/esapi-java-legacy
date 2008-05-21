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

import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * The IAuthenticator interface defines a set of methods for generating and
 * handling account credentials and session identifiers. The goal of this
 * interface is to encourage developers to protect credentials from disclosure
 * to the maximum extent possible.
 * <P>
 * <img src="doc-files/Authenticator.jpg" height="600">
 * <P>
 * Once possible implementation relies on the use of a thread local variable to
 * store the current user's identity. The application is responsible for calling
 * setCurrentUser() as soon as possible after each HTTP request is received. The
 * value of getCurrentUser() is used in several other places in this API. This
 * eliminates the need to pass a user object to methods throughout the library.
 * For example, all of the logging, access control, and exception calls need
 * access to the currently logged in user.
 * <P>
 * The goal is to minimize the responsibility of the developer for
 * authentication. In this example, the user simply calls authenticate with the
 * current request and the name of the parameters containing the username and
 * password. The implementation should verify the password if necessary, create
 * a session if necessary, and set the user as the current user.
 * 
 * <pre>
 * public void doPost(ServletRequest request, ServletResponse response) {
 * try {
 * ESAPI.authenticator().authenticate(request, response, &quot;username&quot;,&quot;password&quot;);
 * // continue with authenticated user
 * } catch (AuthenticationException e) {
 * // handle failed authentication (it's already been logged)
 * }
 * </pre>
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface IAuthenticator {

	/**
	 * Clear the current user. This allows the thread to be reused safely.
	 */
	void clearCurrent();

	/**
	 * Authenticates the user's credentials from the HttpServletRequest if
	 * necessary, creates a session if necessary, and sets the user as the
	 * current user.
	 * 
	 * @param request
	 *            the current HTTP request
	 * @param response
	 *            the response
	 * 
	 * @return the user
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	IUser login(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException;

	/**
	 * Verify that the supplied password matches the password for this user. This method
	 * is typically used for "reauthentication" for the most sensitive functions, such
	 * as transactions, changing email address, and changing other account information.
	 * 
	 * @param user the user
	 * @param password the password
	 * @return
	 */
	boolean verifyPassword(IUser user, String password);
	
	/**
	 * Logs out the current user.
	 */
    void logout();

	/**
	 * Creates the user.
	 * 
	 * @param accountName
	 *            the account name
	 * @param password1
	 *            the password
	 * @param password2
	 *            copy of the password
	 * 
	 * @return the new User object
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	IUser createUser(String accountName, String password1, String password2) throws AuthenticationException;

	/**
	 * Generate a strong password.
	 * 
	 * @return the string
	 */
	String generateStrongPassword();

	/**
	 * Generate strong password that takes into account the user's information and old password.
	 * 
	 * @param oldPassword
	 *            the old password
	 * @param user
	 *            the user
	 * 
	 * @return the string
	 */
	String generateStrongPassword(String oldPassword, IUser user);

	/**
	 * Changes the password for the specified user. This requires the current password, as well as 
	 * the password to replace it with. This new password must be repeated to ensure that the user has
	 * typed it in correctly.
	 * 
	 * @param user the user to change the password for
	 * @param currentPassword the current password for the specified user
	 * @param newPassword the new password to use
	 * @param newPassword2 a verification copy of the new password
	 * @throws AuthenticationException if any errors occur
	 */
	void changePassword(IUser user, String currentPassword, String newPassword, String newPassword2) throws AuthenticationException;
	
	/**
	 * Returns the User matching the provided accountName.
	 * 
	 * @param accountName
	 *            the account name
	 * 
	 * @return the matching User object, or null if no match exists
	 */
	IUser getUser(String accountName);

	/**
	 * Gets the user names.
	 * 
	 * @return the user names
	 */
	Set getUserNames();

	/**
	 * Returns the currently logged in User.
	 * 
	 * @return the matching User object, or the Anonymous user if no match
	 *         exists
	 */
	IUser getCurrentUser();

	/**
	 * Sets the currently logged in User.
	 * 
	 * @param user
	 *            the current user
	 */
	void setCurrentUser(IUser user);

	/**
	 * Returns a string representation of the hashed password, using the
	 * accountName as the salt. The salt helps to prevent against "rainbow"
	 * table attacks where the attacker pre-calculates hashes for known strings.
	 * 
	 * @param password
	 *            the password
	 * @param accountName
	 *            the account name
	 * 
	 * @return the string
	 */
	String hashPassword(String password, String accountName) throws EncryptionException;

	/**
	 * Removes the account.
	 * 
	 * @param accountName
	 *            the account name
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	void removeUser(String accountName) throws AuthenticationException;

	/**
	 * Validate password strength.
	 * 
	 * @param accountName
	 *            the account name
	 * 
	 * @return true, if successful
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	void verifyAccountNameStrength(String accountName) throws AuthenticationException;

	/**
	 * Validate password strength.
	 * @param oldPassword
	 *            the old password
	 * @param newPassword
	 *            the new password
	 * 
	 * @return true, if successful
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	void verifyPasswordStrength(String oldPassword, String newPassword) throws AuthenticationException;

	/**
	 * Verifies the account exists.
	 * 
	 * @param accountName
	 *            the account name
	 * 
	 * @return true, if successful
	 */
	boolean exists(String accountName);

}
