package org.owasp.esapi.reference;

import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.HTTPUtilities;
import org.owasp.esapi.Logger;
import org.owasp.esapi.User;
import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.errors.AuthenticationCredentialsException;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.AuthenticationLoginException;
import org.owasp.esapi.errors.EnterpriseSecurityException;
/**
 * A partial implementation of the Authenticator interface.
 * This class should not implement any methods that would be meant
 * to modify a User object, since that's probably implementation specific.
 *
 */
public abstract class AbstractAuthenticator implements org.owasp.esapi.Authenticator {

	/**
     * Key for user in session
     */
    protected static final String USER = "ESAPIUserSessionKey";
    
    private final Logger logger = ESAPI.getLogger("Authenticator");
    
    /**
     * The currentUser ThreadLocal variable is used to make the currentUser available to any call in any part of an
     * application. Otherwise, each thread would have to pass the User object through the calltree to any methods that
     * need it. Because we want exceptions and log calls to contain user data, that could be almost anywhere. Therefore,
     * the ThreadLocal approach simplifies things greatly. <P> As a possible extension, one could create a delegation
     * framework by adding another ThreadLocal to hold the delegating user identity.
     */
    private final ThreadLocalUser currentUser = new ThreadLocalUser();

    private class ThreadLocalUser extends InheritableThreadLocal<User> {

        public User initialValue() {
            return User.ANONYMOUS;
        }

        public User getUser() {
            return super.get();
        }

        public void setUser(User newUser) {
            super.set(newUser);
        }
    }
    
	/**
	 *
	 */
	public AbstractAuthenticator() {
		super();
	}
	
    /**
     * {@inheritDoc}
     */
    public void clearCurrent() {
        // logger.logWarning(Logger.SECURITY, "************Clearing threadlocals. Thread" + Thread.currentThread().getName() );
        currentUser.setUser(null);
    }
    
    /**
     * {@inheritDoc}
     */
    public boolean exists(String accountName) {
        return getUser(accountName) != null;
    }
    
    /**
     * {@inheritDoc}
     * <p/>
     * Returns the currently logged user as set by the setCurrentUser() methods. Must not log in this method because the
     * logger calls getCurrentUser() and this could cause a loop.
     */
    public User getCurrentUser() {
        User user = currentUser.get();
        if (user == null) {
            user = User.ANONYMOUS;
        }
        return user;
    }
    
    /**
     * Gets the user from session.
     *
     * @return the user from session or null if no user is found in the session
     */
    protected User getUserFromSession() {
        HttpSession session = ESAPI.httpUtilities().getCurrentRequest().getSession(false);
        if (session == null) return null;
        return ESAPI.httpUtilities().getSessionAttribute(USER);
    }
    
    /**
     * Returns the user if a matching remember token is found, or null if the token
     * is missing, token is corrupt, token is expired, account name does not match
     * and existing account, or hashed password does not match user's hashed password.
     *
     * @return the user if a matching remember token is found, or null if the token
     *         is missing, token is corrupt, token is expired, account name does not match
     *         and existing account, or hashed password does not match user's hashed password.
     */
    protected DefaultUser getUserFromRememberToken() {
        try {
            String token = ESAPI.httpUtilities().getCookie(ESAPI.currentRequest(), HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME);
            if (token == null) return null;
            
            // TODO - kww - URLDecode token first, and THEN unseal. See Google Issue 144.

            String[] data = ESAPI.encryptor().unseal(token).split("\\|");
            if (data.length != 2) {
                logger.warning(Logger.SECURITY_FAILURE, "Found corrupt or expired remember token");
                ESAPI.httpUtilities().killCookie(ESAPI.currentRequest(), ESAPI.currentResponse(), HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME);
                return null;
            }

            String username = data[0];
            String password = data[1];
            System.out.println("DATA0: " + username);
            System.out.println("DATA1:" + password);
            DefaultUser user = (DefaultUser) getUser(username);
            if (user == null) {
                logger.warning(Logger.SECURITY_FAILURE, "Found valid remember token but no user matching " + username);
                return null;
            }

            logger.info(Logger.SECURITY_SUCCESS, "Logging in user with remember token: " + user.getAccountName());
            user.loginWithPassword(password);
            return user;
        } catch (AuthenticationException ae) {
            logger.warning(Logger.SECURITY_FAILURE, "Login via remember me cookie failed", ae);
        } catch (EnterpriseSecurityException e) {
            logger.warning(Logger.SECURITY_FAILURE, "Remember token was missing, corrupt, or expired");
        }
        ESAPI.httpUtilities().killCookie(ESAPI.currentRequest(), ESAPI.currentResponse(), HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME);
        return null;
    }
    
    /**
     * Utility method to extract credentials and verify them.
     *
     * @param request The current HTTP request
     * @return The user that successfully authenticated
     * @throws AuthenticationException if the submitted credentials are invalid.
     */
    private User loginWithUsernameAndPassword(HttpServletRequest request) throws AuthenticationException {

        String username = request.getParameter(ESAPI.securityConfiguration().getUsernameParameterName());
        String password = request.getParameter(ESAPI.securityConfiguration().getPasswordParameterName());

        // if a logged-in user is requesting to login, log them out first
        User user = getCurrentUser();
        if (user != null && !user.isAnonymous()) {
            logger.warning(Logger.SECURITY_SUCCESS, "User requested relogin. Performing logout then authentication");
            user.logout();
        }

        // now authenticate with username and password
        if (username == null || password == null) {
            if (username == null) {
                username = "unspecified user";
            }
            throw new AuthenticationCredentialsException("Authentication failed", "Authentication failed for " + username + " because of null username or password");
        }
        user = getUser(username);
        if (user == null) {
            throw new AuthenticationCredentialsException("Authentication failed", "Authentication failed because user " + username + " doesn't exist");
        }
        user.loginWithPassword(password);

        request.setAttribute(user.getCSRFToken(), "authenticated");
        return user;
    }
    
    /**
     * {@inheritDoc}
     */
    public User login() throws AuthenticationException {
        return login(ESAPI.currentRequest(), ESAPI.currentResponse());
    }
    
    /**
     * {@inheritDoc}
     */
    public User login(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        if (request == null || response == null) {
            throw new AuthenticationCredentialsException("Invalid request", "Request or response objects were null");
        }

        // if there's a user in the session then use that
        DefaultUser user = (DefaultUser) getUserFromSession();

        // else if there's a remember token then use that
        if (user == null) {
            user = getUserFromRememberToken();
        }

        // else try to verify credentials - throws exception if login fails
        if (user == null) {
            user = (DefaultUser) loginWithUsernameAndPassword(request);
        }

        // set last host address
        user.setLastHostAddress(request.getRemoteHost());

        // warn if this authentication request was not POST or non-SSL connection, exposing credentials or session id
        try {
            ESAPI.httpUtilities().assertSecureRequest(ESAPI.currentRequest());
        } catch (AccessControlException e) {
            throw new AuthenticationException("Attempt to login with an insecure request", e.getLogMessage(), e);
        }

        // don't let anonymous user log in
        if (user.isAnonymous()) {
            user.logout();
            throw new AuthenticationLoginException("Login failed", "Anonymous user cannot be set to current user. User: " + user.getAccountName());
        }

        // don't let disabled users log in
        if (!user.isEnabled()) {
            user.logout();
            user.incrementFailedLoginCount();
            user.setLastFailedLoginTime(new Date());
            throw new AuthenticationLoginException("Login failed", "Disabled user cannot be set to current user. User: " + user.getAccountName());
        }

        // don't let locked users log in
        if (user.isLocked()) {
            user.logout();
            user.incrementFailedLoginCount();
            user.setLastFailedLoginTime(new Date());
            throw new AuthenticationLoginException("Login failed", "Locked user cannot be set to current user. User: " + user.getAccountName());
        }

        // don't let expired users log in
        if (user.isExpired()) {
            user.logout();
            user.incrementFailedLoginCount();
            user.setLastFailedLoginTime(new Date());
            throw new AuthenticationLoginException("Login failed", "Expired user cannot be set to current user. User: " + user.getAccountName());
        }

        // check session inactivity timeout
        if (user.isSessionTimeout()) {
            user.logout();
            user.incrementFailedLoginCount();
            user.setLastFailedLoginTime(new Date());
            throw new AuthenticationLoginException("Login failed", "Session inactivity timeout: " + user.getAccountName());
        }

        // check session absolute timeout
        if (user.isSessionAbsoluteTimeout()) {
            user.logout();
            user.incrementFailedLoginCount();
            user.setLastFailedLoginTime(new Date());
            throw new AuthenticationLoginException("Login failed", "Session absolute timeout: " + user.getAccountName());
        }

        //set Locale to the user object in the session from request
        user.setLocale(request.getLocale());

        // create new session for this User
        HttpSession session = request.getSession();
        user.addSession(session);
        session.setAttribute(USER, user);
        setCurrentUser(user);
        return user;
    }
    
    /**
     * {@inheritDoc}
     */
    public void logout() {
        User user = getCurrentUser();
        if (user != null && !user.isAnonymous()) {
            user.logout();
        }
    }

    /**
     * {@inheritDoc}
     */
    public void setCurrentUser(User user) {
        currentUser.setUser(user);
    }

}
