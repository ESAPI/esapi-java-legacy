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

import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.EncryptionException;


/**
 * The Authenticator interface defines a set of methods for generating and
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
 * User user = ESAPI.authenticator().login(request, response);
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
public interface Authenticator {

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
	User login(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException;

	/**
	 * Verify that the supplied password matches the password for this user. This method
	 * is typically used for "reauthentication" for the most sensitive functions, such
	 * as transactions, changing email address, and changing other account information.
	 * 
	 * @param user the user
	 * @param password the password
	 * @return true if the password is correct for the specified user
	 */
	boolean verifyPassword(User user, String password);
	
	/**
	 * Logs out the current user.
	 */
    void logout();

	/**
	 * Creates a new User with the information provided. Implementations should check the
	 * accountName and password for proper format and strength against brute force attacks.
	 * Two copies of the new password are required to encourage user interface designers to
	 * include two fields in their forms. Implementations should verify that both are the
	 * same. 
	 */
	User createUser(String accountName, String password1, String password2) throws AuthenticationException;

	/**
	 * Generate a strong password. Implementations should use a large character set that does not
	 * include confusing characters, such as i I 1 l 0 o and O.  There are many algorithms to
	 * generate strong memorable passwords that have been studied in the past.
	 */
	String generateStrongPassword();

	/**
	 * Generate strong password that takes into account the user's information and old password. Implementations
	 * should verify that the new password does not include information such as the username, fragments of the
	 * old password, and other information that could be used to weaken the strength of the password.
	 */
	String generateStrongPassword(User user, String oldPassword);

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
	void changePassword(User user, String currentPassword, String newPassword, String newPassword2) throws AuthenticationException;
	
	/**
	 * Returns the User matching the provided accountName.
	 * 
	 * @param accountName
	 *            the account name
	 * 
	 * @return the matching User object, or null if no match exists
	 */
	User getUser(String accountName);

	/**
	 * Gets a collection containing all the existing user names.
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
	User getCurrentUser();

	/**
	 * Sets the currently logged in User.
	 * 
	 * @param user
	 *            the current user
	 */
	void setCurrentUser(User user);

	/**
	 * Returns a string representation of the hashed password, using the
	 * accountName as the salt. The salt helps to prevent against "rainbow"
	 * table attacks where the attacker pre-calculates hashes for known strings.
	 * This method specifies the use of the user's account name as the "salt"
	 * value. The Encryptor.hash method can be used if a different salt is
	 * required.
	 * 
	 * @param password
	 *            the password
	 * @param accountName
	 *            the account name
	 * 
	 * @return the hashed password
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
	 * Ensures that the account name passes site-specific complexity requirements.
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
	 * Ensures that the password meets site-specific complexity requirements. This
	 * method takes the old password so that the algorithm can analyze the new password
	 * to see if it is too similar to the old password. Note that this has to be
	 * invoked when the user has entered the old password, as this list of old
	 * credentials stored by ESAPI are all hashed.
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
	 * Determine if the account already exists.
	 * 
	 * @param accountName
	 *            the account name
	 * 
	 * @return true, if the account exists
	 */
	boolean exists(String accountName);

}
