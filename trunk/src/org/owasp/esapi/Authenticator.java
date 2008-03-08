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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.owasp.esapi.errors.AuthenticationAccountsException;
import org.owasp.esapi.errors.AuthenticationCredentialsException;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.AuthenticationLoginException;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.interfaces.IRandomizer;
import org.owasp.esapi.interfaces.IUser;

/**
 * Reference implementation of the IAuthenticator interface. This reference implementation is backed by a simple text
 * file that contains serialized information about users. Many organizations will want to create their own
 * implementation of the methods provided in the IAuthenticator interface backed by their own user repository. This
 * reference implementation captures information about users in a simple text file format that contains user information
 * separated by the pipe "|" character. Here's an example of a single line from the users.txt file:
 * 
 * <PRE>
 * 
 * account name | hashed password | roles | lockout | status | remember token | old password hashes | last
 * hostname | last change | last login | last failed | expiration | failed
 * ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 * mitch | 44k/NAzQUlrCq9musTGGkcMNmdzEGJ8w8qZTLzpxLuQ= | admin,user | unlocked | enabled | token |
 * u10dW4vTo3ZkoM5xP+blayWCz7KdPKyKUojOn9GJobg= | 192.168.1.255 | 1187201000926 | 1187200991568 | 1187200605330 |
 * 2187200605330 | 1
 * 
 * </PRE>
 * 
 * @author <a href="mailto:jeff.williams@aspectsecurity.com?subject=ESAPI question">Jeff Williams</a> at <a
 * href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.interfaces.IAuthenticator
 */
public class Authenticator implements org.owasp.esapi.interfaces.IAuthenticator {

    /** The Constant USER. */
    protected static final String USER = "ESAPIUserSessionKey";

    /** The logger. */
    private static final Logger logger = Logger.getLogger("ESAPI", "Authenticator");

    /** The file that contains the user db */
    private File userDB = null;
    
    /** How frequently to check the user db for external modifications */
    private long checkInterval = 60 * 1000;

    /** The last modified time we saw on the user db. */
    private long lastModified = 0;

    /** The last time we checked if the user db had been modified externally */
    private long lastChecked = 0;
    
    /**
     * Fail safe main program to add or update an account in an emergency.
     * <P>
     * Warning: this method does not perform the level of validation and checks
     * generally required in ESAPI, and can therefore be used to create a username and password that do not comply
     * with the username and password strength requirements.
     * <P>
     * Example: Use this to add the alice account with the admin role to the users file: 
     * <PRE>
     * 
     * java -Dorg.owasp.esapi.resources="/path/resources" -classpath esapi.jar org.owasp.esapi.Authenticator alice password admin
     * 
     * </PRE>
     * 
     * @param args the args
     * @throws AuthenticationException the authentication exception
     */
    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("Usage: Authenticator accountname password role");
            return;
        }
        Authenticator auth = new Authenticator();
        String accountName = args[0].toLowerCase();
        String password = args[1];
        String role = args[2];
        User user = auth.getUser(args[0]);
        if (user == null) {
            user = new User();
            user.setAccountName(accountName);
            auth.userMap.put(accountName, user);
            logger.logCritical(Logger.SECURITY, "New user created: " + accountName);
        }
		String newHash = auth.hashPassword(password, accountName);
		user.setHashedPassword(newHash);
        user.addRole(role);
        user.enable();
        user.unlock();
        auth.saveUsers();
        System.out.println("User account " + user.getAccountName() + " updated");
    }

    // FIXME: ENHANCE consider an impersonation feature
    
    /** The anonymous user */
    // FIXME: AAA is this whole anonymous user concept right?
    static User anonymous = new User("anonymous", "anonymous");

    /** The user map. */
    private Map userMap = new HashMap();

    
    /*
     * The currentUser ThreadLocal variable is used to make the currentUser available to any call in any part of an
     * application. Otherwise, each thread would have to pass the User object through the calltree to any methods that
     * need it. Because we want exceptions and log calls to contain user data, that could be almost anywhere. Therefore,
     * the ThreadLocal approach simplifies things greatly. <P> As a possible extension, one could create a delegation
     * framework by adding another ThreadLocal to hold the delegating user identity.
     */
    private static ThreadLocalUser currentUser = new ThreadLocalUser();

    private static class ThreadLocalUser extends InheritableThreadLocal {
        
        public Object initialValue() {
        	return anonymous;
        }
        
        public IUser getUser() {
            return (IUser)super.get();
        }

        public void setUser(IUser newUser) {
        	// System.out.println( "SETTING Thread: " + Thread.currentThread() + " " + (getUser() != null ? getUser().getAccountName() : "null" ) + " --> " + (newUser != null ? (newUser).getAccountName() : "null" ) );
            super.set(newUser);
        }
    };

    /*
     * The currentRequest ThreadLocal variable is used to make the currentRequest available to any call in any part of an
     * application. This enables API's for actions that require the request to be much simpler. For example, the logout()
     * method in the Authenticator class requires the currentRequest to get the session in order to invalidate it.
     */
    private static ThreadLocalRequest currentRequest = new ThreadLocalRequest();

    private static class ThreadLocalRequest extends InheritableThreadLocal {
        
        public Object initialValue() {
        	return null;
        }
        
        public HttpServletRequest getRequest() {
            return (HttpServletRequest)super.get();
        }

        public void setUser(HttpServletRequest newRequest) {
            super.set(newRequest);
        }
    };

    /*
     * The currentResponse ThreadLocal variable is used to make the currentResponse available to any call in any part of an
     * application. This enables API's for actions that require the response to be much simpler. For example, the logout()
     * method in the Authenticator class requires the currentResponse to kill the JSESSIONID cookie.
     */
    private static ThreadLocalResponse currentResponse = new ThreadLocalResponse();

    private static class ThreadLocalResponse extends InheritableThreadLocal {
        
        public Object initialValue() {
        	return null;
        }
        
        public HttpServletResponse getResponse() {
            return (HttpServletResponse)super.get();
        }

        public void setUser(HttpServletResponse newResponse) {
            super.set(newResponse);
        }
    };

       
    
    public Authenticator() {
    }

    /**
     * Clears all threadlocal variables from the thread. This should ONLY be called after
     * all possible ESAPI operations have concluded. If you clear too early, many calls will
     * fail, including logging, which requires the user identity.
     */
    public void clearCurrent() {
    	currentUser.setUser(null);
    	currentResponse.set(null);
    	currentRequest.set(null);
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#createAccount(java.lang.String, java.lang.String)
     */
    public synchronized User createUser(String accountName, String password1, String password2) throws AuthenticationException {
        loadUsersIfNecessary();
        if (accountName == null) {
            throw new AuthenticationAccountsException("Account creation failed", "Attempt to create user with null accountName");
        }
        if (userMap.containsKey(accountName.toLowerCase())) {
            throw new AuthenticationAccountsException("Account creation failed", "Duplicate user creation denied for " + accountName);
        }
        User user = new User(accountName, password1, password2);
        userMap.put(accountName.toLowerCase(), user);
        logger.logCritical(Logger.SECURITY, "New user created: " + accountName);
        saveUsers();
        return user;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#exists(java.lang.String)
     */
    public boolean exists(String accountName) {
        User user = getUser(accountName);
        return user != null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#generateStrongPassword(int, char[])
     */
    public String generateStrongPassword() {
        return generateStrongPassword("");
    }

    private String generateStrongPassword(String oldPassword) {
        IRandomizer r = ESAPI.randomizer();
        int letters = r.getRandomInteger(4, 6);  // inclusive, exclusive
        int digits = 7-letters;
        String passLetters = r.getRandomString(letters, Encoder.CHAR_PASSWORD_LETTERS );
        String passDigits = r.getRandomString( digits, Encoder.CHAR_PASSWORD_DIGITS );
        String passSpecial = r.getRandomString( 1, Encoder.CHAR_PASSWORD_SPECIALS );
        String newPassword = passLetters + passSpecial + passDigits;
        return newPassword;
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#generateStrongPassword(int, char[])
     */
    public String generateStrongPassword(String oldPassword, IUser user) {
        String newPassword = generateStrongPassword(oldPassword);
        if (newPassword != null)
            logger.logCritical(Logger.SECURITY, "Generated strong password for " + user.getAccountName());
        return newPassword;
    }

    /*
     * Returns the currently logged user as set by the setCurrentUser() methods. Must not log in this method because the
     * logger calls getCurrentUser() and this could cause a loop.
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#getCurrentUser()
     */
    public User getCurrentUser() {
        User user = (User)currentUser.get();
        if (user == null)
            user = anonymous;
        return user;
    }

    /*
     * Returns the current HttpServletRequest.
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#getCurrentRequest()
     */
    public HttpServletRequest getCurrentRequest() {
        return (HttpServletRequest)currentRequest.get();
    }

    public HttpServletResponse getCurrentResponse() {
        return (HttpServletResponse)currentResponse.get();
    }

    /**
     * Gets the user object with the matching account name or null if there is no match.
     * 
     * @param accountName the account name
     * @return the user, or null if not matched.
     */
    public synchronized User getUser(String accountName) {
        loadUsersIfNecessary();
        User user = (User) userMap.get(accountName.toLowerCase());
        return user;
    }

    /*
     * Get the current user from the session and set it as the current user. (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#setCurrentUser(javax.servlet.http.HttpServletRequest)
     */
    /**
     * Gets the user from session.
     * 
     * @param request the request
     * @return the user from session
     */
    public User getUserFromSession() {
        HttpSession session = getCurrentRequest().getSession();
        String userName = (String) session.getAttribute(USER);
        if (userName != null) {
            User sessionUser = this.getUser(userName);
            if (sessionUser != null) {
                return sessionUser;
            }
        }
        return null;
    }

    /**
     * Gets the user names.
     * 
     * @return list of user account names
     */
    public synchronized Set getUserNames() {
        loadUsersIfNecessary();
    	return new HashSet(userMap.keySet());
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#hashPassword(java.lang.String, java.lang.String)
     */
    public String hashPassword(String password, String accountName) throws EncryptionException {
        String salt = accountName.toLowerCase();
        return ESAPI.encryptor().hash(password, salt);
    }
    
    /**
     * Load users.
     * 
     * @return the hash map
     * @throws AuthenticationException the authentication exception
     */
    protected void loadUsersIfNecessary() {
        if (userDB == null)
            userDB = new File(((SecurityConfiguration)ESAPI.securityConfiguration()).getResourceDirectory(), "users.txt");
        
        // We only check at most every checkInterval milliseconds
        long now = System.currentTimeMillis();
        if (now - lastChecked < checkInterval) {
            return;
        }
        lastChecked = now;
        
        long lastModified = userDB.lastModified();
        if (this.lastModified == lastModified) {
            return;
        }
        loadUsersImmediately();
    }
    
    protected void loadUsersImmediately() {
        // file was touched so reload it
    	synchronized( this ) {
	        logger.logTrace(Logger.SECURITY, "Loading users from " + userDB.getAbsolutePath(), null);
	
	        // FIXME: AAA Necessary?
	        // add the Anonymous user to the database
	        // map.put(anonymous.getAccountName(), anonymous);
	
	        BufferedReader reader = null;
	        try {
	            HashMap map = new HashMap();
	            reader = new BufferedReader(new FileReader(userDB));
	            String line = null;
	            while ((line = reader.readLine()) != null) {
	                if (line.length() > 0 && line.charAt(0) != '#') {
	                    User user = new User(line);
	                    if (!user.getAccountName().equals("anonymous")) {
	                        if (map.containsKey(user.getAccountName())) {
	                            logger.logCritical(Logger.SECURITY, "Problem in user file. Skipping duplicate user: " + user, null);
	                        }
	                        map.put(user.getAccountName(), user);
	                    }
	                }
	            }
                userMap = map;
                this.lastModified = System.currentTimeMillis();
                logger.logTrace(Logger.SECURITY, "User file reloaded: " + map.size(), null);
	        } catch (Exception e) {
	            logger.logCritical(Logger.SECURITY, "Failure loading user file: " + userDB.getAbsolutePath(), e);
	        } finally {
	            try {
	                if (reader != null) {
	                    reader.close();
	                }
	            } catch (IOException e) {
	                logger.logCritical(Logger.SECURITY, "Failure closing user file: " + userDB.getAbsolutePath(), e);
	            }
	        }
    	}
    }

    /**
     * Utility method to extract credentials and verify them.
     * 
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     * @throws
     */
    private User loginWithUsernameAndPassword(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // FIXME: AAA the login servlet path should also be a configuration - this
        // should check (if loginrequest && parameters then do
        // loginWithPassword)

        String username = request.getParameter(ESAPI.securityConfiguration().getUsernameParameterName());
        String password = request.getParameter(ESAPI.securityConfiguration().getPasswordParameterName());

        // if a logged-in user is requesting to login, log them out first
        User user = getCurrentUser();
        if (user != null && !user.isAnonymous()) {
            logger.logWarning(Logger.SECURITY, "User requested relogin. Performing logout then authentication" );
            user.logout();
        }

        // now authenticate with username and password
        if (username == null || password == null) {
            if (username == null)
                username = "unspecified user";
            throw new AuthenticationCredentialsException("Authentication failed", "Authentication failed for " + username + " because of null username or password");
        }
        user = getUser(username);
        if (user == null) {
            throw new AuthenticationCredentialsException("Authentication failed", "Authentication failed because user " + username + " doesn't exist");
        }
        user.loginWithPassword(password);
        return user;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#removeUser(java.lang.String)
     */
    public synchronized void removeUser(String accountName) throws AuthenticationException {
        loadUsersIfNecessary();
    	User user = getUser(accountName);
        if (user == null) {
            throw new AuthenticationAccountsException("Remove user failed", "Can't remove invalid accountName " + accountName);
        }
        userMap.remove(accountName.toLowerCase());
        saveUsers();
    }

    /**
     * Saves the user database to the file system. In this implementation you must call save to commit any changes to
     * the user file. Otherwise changes will be lost when the program ends.
     * 
     * @throws AuthenticationException the authentication exception
     */
    protected synchronized void saveUsers() throws AuthenticationException {
        PrintWriter writer = null;
        try {
            writer = new PrintWriter(new FileWriter(userDB));
            writer.println("# This is the user file associated with the ESAPI library from http://www.owasp.org");
            writer.println("# accountName | hashedPassword | roles | locked | enabled | rememberToken | csrfToken | oldPasswordHashes | lastPasswordChangeTime | lastLoginTime | lastFailedLoginTime | expirationTime | failedLoginCount");
            writer.println();
            saveUsers(writer);
            writer.flush();
            logger.logCritical(Logger.SECURITY, "User file written to disk" );
        } catch (IOException e) {
            logger.logCritical(Logger.SECURITY, "Problem saving user file " + userDB.getAbsolutePath(), e );
            throw new AuthenticationException("Internal Error", "Problem saving user file " + userDB.getAbsolutePath(), e);
        } finally {
            if (writer != null) {
                writer.close();
                lastModified = userDB.lastModified();
                lastChecked = lastModified;
            }
        }
    }

    /**
     * Save users.
     * 
     * @param writer the writer
     * @throws IOException
     */
    protected synchronized void saveUsers(PrintWriter writer) {
        Iterator i = getUserNames().iterator();
        while (i.hasNext()) {
            String accountName = (String) i.next();
            User u = getUser(accountName);
            if ( u != null && !u.isAnonymous() ) {
            	writer.println(u.save());
            } else {
            	new AuthenticationCredentialsException("Problem saving user", "Skipping save of user " + accountName );
            }
        }
    }

    /**
     * This method should be called for every HTTP request, to login the current user either from the session of HTTP
     * request. This method will set the current user so that getCurrentUser() will work properly. This method also
     * checks that the user's access is still enabled, unlocked, and unexpired before allowing login. For convenience
     * this method also returns the current user.
     * 
     * @param request the request
     * @param response the response
     * @return the user
     * @throws AuthenticationException the authentication exception
     */
    public User login(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

    	if ( request == null || response == null ) {
            throw new AuthenticationCredentialsException( "Invalid request", "Request or response objects were null" );
    	}
    	// save the current request and response in the threadlocal variables
    	setCurrentHTTP(request, response);
    	
        if ( !ESAPI.httpUtilities().isSecureChannel() ) {
            new AuthenticationCredentialsException( "Session exposed", "Authentication attempt made over non-SSL connection. Check web.xml and server configuration" );
        }
        User user = null;

        // if there's a user in the session then use that
        user = getUserFromSession();
        
        if ( user != null ) {
            user.setLastHostAddress( request.getRemoteHost() );
            user.setFirstRequest(false);
        } else {
        	// try to verify credentials
            user = loginWithUsernameAndPassword(request, response);
            user.setFirstRequest(true);
        }

        // don't let anonymous user log in
        if (user.isAnonymous()) {
        	user.logout();
            throw new AuthenticationLoginException("Login failed", "Anonymous user cannot be set to current user");
        }

        // don't let disabled users log in
        if (!user.isEnabled()) {
        	user.logout();
            user.setLastFailedLoginTime(new Date());
            throw new AuthenticationLoginException("Login failed", "Disabled user cannot be set to current user: " + user.getAccountName());
        }

        // don't let locked users log in
        if (user.isLocked()) {
        	user.logout();
            user.setLastFailedLoginTime(new Date());
            throw new AuthenticationLoginException("Login failed", "Locked user cannot be set to current user: " + user.getAccountName());
        }

        // don't let expired users log in
        if (user.isExpired()) {
        	user.logout();
            user.setLastFailedLoginTime(new Date());
            throw new AuthenticationLoginException("Login failed", "Expired user cannot be set to current user: " + user.getAccountName());
        }

        setCurrentUser(user);
        return user;
    }


    /**
     * Log out the current user.
     */
    public void logout() {
    	User user = getCurrentUser();
        user.logout();
    }
    
    
    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#setCurrentUser(org.owasp.esapi.User)
     */
    public void setCurrentUser(IUser user) {
        currentUser.setUser(user);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#setCurrentHTTP(javax.servlet.http.HttpServletRequest,javax.servlet.http.HttpServletResponse)
     */
    public void setCurrentHTTP(HttpServletRequest request, HttpServletResponse response) {
    	if ( request == null || response == null ) {
            new AuthenticationCredentialsException( "Invalid request or response", "Request or response objects were null" );
            return;
    	}
    	currentRequest.set(request);
        currentResponse.set(response);
    }

    
    
    /*
     * This implementation simply verifies that account names are at least 5 characters long. This helps to defeat a
     * brute force attack, however the real strength comes from the name length and complexity.
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#validateAccountNameStrength(java.lang.String)
     */
    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#verifyAccountNameStrength(java.lang.String)
     */
    public void verifyAccountNameStrength(String context, String newAccountName) throws AuthenticationException {
        if (newAccountName == null) {
            throw new AuthenticationCredentialsException("Invalid account name", "Attempt to create account with a null account name");
        }
        // FIXME: ENHANCE make the lengths configurable?
        if (!ESAPI.validator().isValidDataFromBrowser(context, "AccountName", newAccountName )) {
            throw new AuthenticationCredentialsException("Invalid account name", "New account name is not valid: " + newAccountName);
        }
    }

    /*
     * This implementation checks: - for any 3 character substrings of the old password - for use of a length *
     * character sets > 16 (where character sets are upper, lower, digit, and special (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#validatePasswordStrength(java.lang.String)
     */
    public void verifyPasswordStrength(String newPassword, String oldPassword) throws AuthenticationException {
        String oPassword = (oldPassword == null) ? "" : oldPassword;

        // can't change to a password that contains any 3 character substring of old password
        int length = oPassword.length();
        for (int i = 0; i < length - 2; i++) {
            String sub = oPassword.substring(i, i + 3);
            if (newPassword.indexOf(sub) > -1 )
                throw new AuthenticationCredentialsException("Invalid password", "New password cannot contain pieces of old password");
        }

        // new password must have enough character sets and length
        int charsets = 0;
        for (int i = 0; i < newPassword.length(); i++)
            if (Arrays.binarySearch(Encoder.CHAR_LOWERS, newPassword.charAt(i)) > 0) {
                charsets++;
                break;
            }
        for (int i = 0; i < newPassword.length(); i++)
            if (Arrays.binarySearch(Encoder.CHAR_UPPERS, newPassword.charAt(i)) > 0) {
                charsets++;
                break;
            }
        for (int i = 0; i < newPassword.length(); i++)
            if (Arrays.binarySearch(Encoder.CHAR_DIGITS, newPassword.charAt(i)) > 0) {
                charsets++;
                break;
            }
        for (int i = 0; i < newPassword.length(); i++)
            if (Arrays.binarySearch(Encoder.CHAR_SPECIALS, newPassword.charAt(i)) > 0) {
                charsets++;
                break;
            }
        
        // calculate and verify password strength
        int strength = newPassword.length() * charsets;        
        if (strength < 16) {
        	// FIXME: enhance - make password strength configurable
            throw new AuthenticationCredentialsException("Invalid password", "New password is not long and complex enough");
        }
    }

}
