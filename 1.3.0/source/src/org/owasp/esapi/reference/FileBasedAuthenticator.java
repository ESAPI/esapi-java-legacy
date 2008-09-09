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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.HTTPUtilities;
import org.owasp.esapi.Logger;
import org.owasp.esapi.Randomizer;
import org.owasp.esapi.User;
import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.errors.AuthenticationAccountsException;
import org.owasp.esapi.errors.AuthenticationCredentialsException;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.AuthenticationLoginException;
import org.owasp.esapi.errors.EncryptionException;

/**
 * Reference implementation of the Authenticator interface. This reference implementation is backed by a simple text
 * file that contains serialized information about users. Many organizations will want to create their own
 * implementation of the methods provided in the IAuthenticator interface backed by their own user repository. This
 * reference implementation captures information about users in a simple text file format that contains user information
 * separated by the pipe "|" character. Here's an example of a single line from the users.txt file:
 * 
 * <PRE>
 * 
 * account id | account name | hashed password | roles | lockout | status | old password hashes | last
 * hostname | last change | last login | last failed | expiration | failed
 * ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 * 1203123710837 | mitch | 44k/NAzQUlrCq9musTGGkcMNmdzEGJ8w8qZTLzpxLuQ= | admin,user | unlocked | enabled |
 * u10dW4vTo3ZkoM5xP+blayWCz7KdPKyKUojOn9GJobg= | 192.168.1.255 | 1187201000926 | 1187200991568 | 1187200605330 |
 * 2187200605330 | 1
 * 
 * </PRE>
 * 
 * @author <a href="mailto:jeff.williams@aspectsecurity.com?subject=ESAPI question">Jeff Williams</a> at <a
 * href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Authenticator
 */
public class FileBasedAuthenticator implements org.owasp.esapi.Authenticator {

    /** Key for user in session */
    protected static final String USER = "ESAPIUserSessionKey";

    /** The logger. */
    private final Logger logger = ESAPI.getLogger("Authenticator");

    /** The file that contains the user db */
    private File userDB = null;
    
    /** How frequently to check the user db for external modifications */
    private long checkInterval = 60 * 1000;

    /** The last modified time we saw on the user db. */
    private long lastModified = 0;

    /** The last time we checked if the user db had been modified externally */
    private long lastChecked = 0;
    
    private final int MAX_ACCOUNT_NAME_LENGTH = 250;
    
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
        FileBasedAuthenticator auth = new FileBasedAuthenticator();
        String accountName = args[0].toLowerCase();
        String password = args[1];
        String role = args[2];
        DefaultUser user = (DefaultUser) auth.getUser(args[0]);
        if (user == null) {
            user = new DefaultUser(accountName);
    		String newHash = auth.hashPassword(password, accountName);
    		auth.setHashedPassword(user, newHash);
            user.addRole(role);
            user.enable();
            user.unlock();
            auth.userMap.put(new Long(user.getAccountId()), user);
            System.out.println("New user created: " + accountName);
            auth.saveUsers();
            System.out.println("User account " + user.getAccountName() + " updated");
        } else {
        	System.err.println("User account " + user.getAccountName() + " already exists!");
        }
    }

    private void setHashedPassword(User user, String hash) {
    	List hashes = getAllHashedPasswords(user, true);
		hashes.add( 0, hash);
		if (hashes.size() > ESAPI.securityConfiguration().getMaxOldPasswordHashes() ) 
			hashes.remove( hashes.size() - 1 );
		logger.info(Logger.SECURITY, "New hashed password stored for " + user.getAccountName() );
    }
    
    String getHashedPassword(User user) {
    	List hashes = getAllHashedPasswords(user, false);
    	return (String) hashes.get(0);
    }
    
    void setOldPasswordHashes(User user, List oldHashes) {
    	List hashes = getAllHashedPasswords(user, true);
    	if (hashes.size() > 1)
    		hashes.removeAll(hashes.subList(1, hashes.size()-1));
    	hashes.addAll(oldHashes);
    }
    
    List getAllHashedPasswords(User user, boolean create) {
    	List hashes = (List) passwordMap.get(user);
    	if (hashes != null)
    		return hashes;
    	if (create) {
    		hashes = new ArrayList();
    		passwordMap.put(user, hashes);
    		return hashes;
    	}
    	throw new RuntimeException("No hashes found for " + user.getAccountName() + ". Is User.hashcode() and equals() implemented correctly?");
    }
    
    List getOldPasswordHashes(User user) {
    	List hashes = getAllHashedPasswords(user, false);
    	if (hashes.size() > 1)
    		return Collections.unmodifiableList(hashes.subList(1, hashes.size()-1));
    	return Collections.EMPTY_LIST;
    }
    
    /** The user map. */
    private Map userMap = new HashMap();

    // Map<User, List<String>>, where the strings are password hashes, with the current hash in entry 0
    private Map passwordMap = new Hashtable();
    
    /*
     * The currentUser ThreadLocal variable is used to make the currentUser available to any call in any part of an
     * application. Otherwise, each thread would have to pass the User object through the calltree to any methods that
     * need it. Because we want exceptions and log calls to contain user data, that could be almost anywhere. Therefore,
     * the ThreadLocal approach simplifies things greatly. <P> As a possible extension, one could create a delegation
     * framework by adding another ThreadLocal to hold the delegating user identity.
     */
    private ThreadLocalUser currentUser = new ThreadLocalUser();

    private class ThreadLocalUser extends InheritableThreadLocal {
        
        public Object initialValue() {
        	return User.ANONYMOUS;
        }
        
        public User getUser() {
            return (User)super.get();
        }

        public void setUser(User newUser) {
            super.set(newUser);
        }
    };

    public FileBasedAuthenticator() {
    }

    /**
     * Clears all threadlocal variables from the thread. This should ONLY be called after
     * all possible ESAPI operations have concluded. If you clear too early, many calls will
     * fail, including logging, which requires the user identity.
     */
    public void clearCurrent() {
    	// logger.logWarning(Logger.SECURITY, "************Clearing threadlocals. Thread" + Thread.currentThread().getName() );
    	currentUser.setUser(null);
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
        if (getUser(accountName) != null) {
            throw new AuthenticationAccountsException("Account creation failed", "Duplicate user creation denied for " + accountName);
        }
        
		verifyAccountNameStrength(accountName);

		if ( password1 == null ) {
			throw new AuthenticationCredentialsException( "Invalid account name", "Attempt to create account " + accountName + " with a null password" );
		}
		verifyPasswordStrength(null, password1);
		
		if (!password1.equals(password2)) throw new AuthenticationCredentialsException("Passwords do not match", "Passwords for " + accountName + " do not match");

        DefaultUser user = new DefaultUser(accountName);
		try {
		    setHashedPassword( user, hashPassword(password1, accountName) );
		} catch (EncryptionException ee) {
		    throw new AuthenticationException("Internal error", "Error hashing password for " + accountName, ee);
		}
        userMap.put(new Long( user.getAccountId() ), user);
        logger.info(Logger.SECURITY, "New user created: " + accountName);
        saveUsers();
        return user;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#exists(java.lang.String)
     */
    public boolean exists(String accountName) {
        return getUser(accountName) != null;
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
        Randomizer r = ESAPI.randomizer();
        int letters = r.getRandomInteger(4, 6);  // inclusive, exclusive
        int digits = 7-letters;
        String passLetters = r.getRandomString(letters, DefaultEncoder.CHAR_PASSWORD_LETTERS );
        String passDigits = r.getRandomString( digits, DefaultEncoder.CHAR_PASSWORD_DIGITS );
        String passSpecial = r.getRandomString( 1, DefaultEncoder.CHAR_PASSWORD_SPECIALS );
        String newPassword = passLetters + passSpecial + passDigits;
        return newPassword;
    }

    /* (non-Javadoc)
     * @see org.owasp.esapi.interfaces.IAuthenticator#changePassword(org.owasp.esapi.interfaces.IUser, java.lang.String, java.lang.String, java.lang.String)
     */
    public void changePassword(User user, String currentPassword,
            String newPassword, String newPassword2)
            throws AuthenticationException {
    	String accountName = user.getAccountName();
    	try {
        	String currentHash = getHashedPassword(user);
        	String verifyHash = hashPassword(currentPassword, accountName);
    		if (!currentHash.equals(verifyHash)) {
    			throw new AuthenticationCredentialsException("Password change failed", "Authentication failed for password change on user: " + accountName );
    		}
    		if (newPassword == null || newPassword2 == null || !newPassword.equals(newPassword2)) {
    			throw new AuthenticationCredentialsException("Password change failed", "Passwords do not match for password change on user: " + accountName );
    		}
    		verifyPasswordStrength(currentPassword, newPassword);
    		((DefaultUser)user).setLastPasswordChangeTime(new Date());
    		String newHash = hashPassword(newPassword, accountName);
    		if (getOldPasswordHashes(user).contains(newHash)) {
    			throw new AuthenticationCredentialsException( "Password change failed", "Password change matches a recent password for user: " + accountName );
    		}
    		setHashedPassword(user, newHash);
    		logger.info(Logger.SECURITY, "Password changed for user: " + accountName );
    	} catch (EncryptionException ee) {
    		throw new AuthenticationException("Password change failed", "Encryption exception changing password for " + accountName, ee);
    	}
    }

    
	/* (non-Javadoc)
     * @see org.owasp.esapi.interfaces.IAuthenticator#verifyPassword(org.owasp.esapi.interfaces.IUser, java.lang.String)
     */
    public boolean verifyPassword(User user, String password) {
		String accountName = user.getAccountName();
		try {
			String hash = hashPassword(password, accountName);
			String currentHash = getHashedPassword(user);
			if (hash.equals(currentHash)) {
				((DefaultUser)user).setLastLoginTime(new Date());
				((DefaultUser)user).setFailedLoginCount(0);
				logger.info(Logger.SECURITY, "Password verified for " + accountName );
				return true;
			}
		} catch( EncryptionException e ) {
			logger.fatal(Logger.SECURITY, "Encryption error verifying password for " + accountName );
		}
		logger.fatal(Logger.SECURITY, "Password verification failed for " + accountName );
		return false;
    }

	/*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#generateStrongPassword(int, char[])
     */
    public String generateStrongPassword(User user, String oldPassword) {
        String newPassword = generateStrongPassword(oldPassword);
        if (newPassword != null)
            logger.info(Logger.SECURITY, "Generated strong password for " + user.getAccountName());
        return newPassword;
    }

    /*
     * Returns the currently logged user as set by the setCurrentUser() methods. Must not log in this method because the
     * logger calls getCurrentUser() and this could cause a loop.
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#getCurrentUser()
     */
    public User getCurrentUser() {
        User user = (User) currentUser.get();
        if (user == null) {
            user = User.ANONYMOUS;
        }
        return user;
    }

    
    /**
     * Gets the user object with the matching account name or null if there is no match.
     * 
     * @param accountName the account name
     * @return the user, or null if not matched.
     */
    public synchronized User getUser(long accountId) {
    	if ( accountId == 0 ) {
    		return User.ANONYMOUS;
    	}
        loadUsersIfNecessary();
        User user = (User) userMap.get(new Long( accountId ));
        return user;
    }

    /**
     * Gets the user object with the matching account name or null if there is no match.
     * 
     * @param accountName the account name
     * @return the user, or null if not matched.
     */
    public synchronized User getUser(String accountName) {
    	if ( accountName == null ) {
    		return User.ANONYMOUS;
    	}
        loadUsersIfNecessary();
        Iterator i = userMap.values().iterator();
        while( i.hasNext() ) {
        	User u = (User)i.next();
        	if ( u.getAccountName().equalsIgnoreCase(accountName) ) return u;
        }
        return null;
    }
    
    
    /**
     * Gets the user from session.
     * 
     * @param request the request
     * @return the user from session
     */
    protected User getUserFromSession() {
        HttpSession session = ESAPI.httpUtilities().getCurrentRequest().getSession();
        return (User)session.getAttribute(USER);
    }

    /**
     * Returns the user if a matching remember token is found, or null if the token
     * is missing, token is corrupt, token is expired, account name does not match 
     * and existing account, or hashed password does not match user's hashed password.
     */
    protected DefaultUser getUserFromRememberToken()  {
    	Cookie token = ESAPI.httpUtilities().getCookie( ESAPI.currentRequest(), HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME );
    	if ( token == null ) {
    		return null;
    	}

    	String[] data = null;
		try {
			data = ESAPI.encryptor().unseal( token.getValue() ).split( ":" );
		} catch (EncryptionException e) {			
	    	logger.warning(Logger.SECURITY, "Found corrupt or expired remember token" );
	    	ESAPI.httpUtilities().killCookie( ESAPI.currentRequest(), ESAPI.currentResponse(), HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME );
	    	return null;
    	}
		
		if ( data.length != 3 ) {
			return null;
		}
		// data[0] is a random nonce, which can be ignored
		String username = data[1];
		String password = data[2];
    	DefaultUser user = (DefaultUser) getUser( username );
		if ( user == null ) {
			logger.warning( Logger.SECURITY, "Found valid remember token but no user matching " + username );
			return null;
		}
		
		logger.warning( Logger.SECURITY, "Logging in user with remember token: " + user.getAccountName() );
		try {
			user.loginWithPassword(password);
		} catch (AuthenticationException ae) {
			logger.warning( Logger.SECURITY, "Login via remember me cookie failed for user " + username, ae);
	    	ESAPI.httpUtilities().killCookie( ESAPI.currentRequest(), ESAPI.currentResponse(), HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME );
			return null;
		}
		return user;
    }

    /**
     * Gets the user names.
     * 
     * @return list of user account names
     */
    public synchronized Set getUserNames() {
        loadUsersIfNecessary();
    	HashSet results = new HashSet();
    	Iterator i = userMap.values().iterator();
    	while( i.hasNext() ) {
    		User u = (User)i.next();
    		results.add( u.getAccountName() );
    	}
    	return results;
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
        if (userDB == null) {
            userDB = new File((ESAPI.securityConfiguration()).getResourceDirectory(), "users.txt");
        }
        
        // We only check at most every checkInterval milliseconds
        long now = System.currentTimeMillis();
        if (now - lastChecked < checkInterval) {
            return;
        }
        lastChecked = now;
        
        if (lastModified == userDB.lastModified()) {
            return;
        }
        loadUsersImmediately();
    }
    
    // file was touched so reload it
    protected void loadUsersImmediately() {
    	synchronized( this ) {
	        logger.trace(Logger.SECURITY, "Loading users from " + userDB.getAbsolutePath(), null);
	
	        BufferedReader reader = null;
	        try {
	            HashMap map = new HashMap();
	            reader = new BufferedReader(new FileReader(userDB));
	            String line = null;
	            while ((line = reader.readLine()) != null) {
	                if (line.length() > 0 && line.charAt(0) != '#') {
	                    DefaultUser user = createUser(line);
                        if (map.containsKey( new Long( user.getAccountId()))) {
                            logger.fatal(Logger.SECURITY, "Problem in user file. Skipping duplicate user: " + user, null);
                        }
                        map.put( new Long( user.getAccountId() ), user);
                    }
	            }
                userMap = map;
                this.lastModified = System.currentTimeMillis();
                logger.trace(Logger.SECURITY, "User file reloaded: " + map.size(), null);
	        } catch (Exception e) {
	            logger.fatal(Logger.SECURITY, "Failure loading user file: " + userDB.getAbsolutePath(), e);
	        } finally {
	            try {
	                if (reader != null) {
	                    reader.close();
	                }
	            } catch (IOException e) {
	                logger.fatal(Logger.SECURITY, "Failure closing user file: " + userDB.getAbsolutePath(), e);
	            }
	        }
    	}
    }

	private DefaultUser createUser(String line) throws AuthenticationException {
		String[] parts = line.split(" *\\| *");
		String accountIdString = parts[0];
		long accountId = Long.parseLong(accountIdString);
		String accountName = parts[1];
		
		verifyAccountNameStrength( accountName );
		DefaultUser user = new DefaultUser( accountName );
		user.accountId = accountId;
		
		String password = parts[2];
		verifyPasswordStrength(null, password);
		setHashedPassword(user, password);
        
		String[] roles = parts[3].toLowerCase().split(" *, *");
		for (int i=0; i<roles.length; i++) 
			if (!"".equals(roles[i]))
					user.addRole(roles[i]);
		if (!"unlocked".equalsIgnoreCase(parts[4]))
			user.lock();
		if ("enabled".equalsIgnoreCase(parts[5])) {
			user.enable();
		} else {
			user.disable();
		}

		// generate a new csrf token
        user.resetCSRFToken();
        
        setOldPasswordHashes(user, Arrays.asList(parts[6].split(" *, *")));
        user.setLastHostAddress("null".equals(parts[7]) ? null : parts[7]);
        user.setLastPasswordChangeTime(new Date( Long.parseLong(parts[8])));
		user.setLastLoginTime(new Date( Long.parseLong(parts[9])));
		user.setLastFailedLoginTime(new Date( Long.parseLong(parts[10])));
		user.setExpirationTime(new Date( Long.parseLong(parts[11])));
		user.setFailedLoginCount(Integer.parseInt(parts[12]));
		return user;
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

        String username = request.getParameter(ESAPI.securityConfiguration().getUsernameParameterName());
        String password = request.getParameter(ESAPI.securityConfiguration().getPasswordParameterName());

        // if a logged-in user is requesting to login, log them out first
        User user = getCurrentUser();
        if (user != null && !user.isAnonymous()) {
            logger.warning(Logger.SECURITY, "User requested relogin. Performing logout then authentication" );
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
        userMap.remove( new Long( user.getAccountId() ));
        System.out.println("Removing user " +user.getAccountName());
        passwordMap.remove(user.getAccountName());
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
            writer.println("# accountId | accountName | hashedPassword | roles | locked | enabled | csrfToken | oldPasswordHashes | lastPasswordChangeTime | lastLoginTime | lastFailedLoginTime | expirationTime | failedLoginCount");
            writer.println();
            saveUsers(writer);
            writer.flush();
            logger.info(Logger.SECURITY, "User file written to disk" );
        } catch (IOException e) {
            logger.fatal(Logger.SECURITY, "Problem saving user file " + userDB.getAbsolutePath(), e );
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
            DefaultUser u = (DefaultUser) getUser(accountName);
            if ( u != null && !u.isAnonymous() ) {
            	writer.println(save(u));
            } else {
            	new AuthenticationCredentialsException("Problem saving user", "Skipping save of user " + accountName );
            }
        }
    }

	/**
	 * Save.
	 * 
	 * @return the string
	 */
	private String save(DefaultUser user) {
		StringBuffer sb = new StringBuffer();
		sb.append( user.getAccountId() );
		sb.append( " | " );
		sb.append( user.getAccountName() );
		sb.append( " | " );
		sb.append( getHashedPassword(user) );
		sb.append( " | " );
		sb.append( dump(user.getRoles()) );
		sb.append( " | " );
		sb.append( user.isLocked() ? "locked" : "unlocked" );
		sb.append( " | " );
		sb.append( user.isEnabled() ? "enabled" : "disabled" );
		sb.append( " | " );
		sb.append( dump(getOldPasswordHashes(user)) );
        sb.append( " | " );
        sb.append( user.getLastHostAddress() );
        sb.append( " | " );
        sb.append( user.getLastPasswordChangeTime().getTime() );
		sb.append( " | " );
		sb.append( user.getLastLoginTime().getTime() );
		sb.append( " | " );
		sb.append( user.getLastFailedLoginTime().getTime() );
		sb.append( " | " );
		sb.append( user.getExpirationTime().getTime() );
		sb.append( " | " );
		sb.append( user.getFailedLoginCount() );
		return sb.toString();
	}

	/**
	 * Dump a collection as a comma-separated list.
	 * @return the string
	 */
	private String dump( Collection c ) {
		StringBuffer sb = new StringBuffer();
		Iterator i = c.iterator();
		while ( i.hasNext() ) {
			String s = (String)i.next();
			sb.append( s );
			if ( i.hasNext() ) sb.append( ",");
		}
		return sb.toString();
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

        // if there's a user in the session then use that
        DefaultUser user = (DefaultUser)getUserFromSession();
        
        // else if there's a remember token then use that
        if ( user == null ) {
        	user = getUserFromRememberToken(); 
        }
        
    	// else try to verify credentials - throws exception if login fails
        if ( user == null ) {
            user = (DefaultUser)loginWithUsernameAndPassword(request, response);
        }
        
        // set last host address
        user.setLastHostAddress( request.getRemoteHost() );
        
        // warn if this authentication request was not POST or non-SSL connection, exposing credentials or session id
        try {
        	ESAPI.httpUtilities().assertSecureRequest( ESAPI.currentRequest() );
        } catch( AccessControlException e ) {
        	throw new AuthenticationException( "Attempt to login with an insecure request", e.getLogMessage(), e );
        }
                
        // don't let anonymous user log in
        if (user.isAnonymous()) {
        	user.logout();
            throw new AuthenticationLoginException("Login failed", "Anonymous user cannot be set to current user. User: " + user.getAccountName() );
        }

        // don't let disabled users log in
        if (!user.isEnabled()) {
        	user.logout();
			user.incrementFailedLoginCount();
            user.setLastFailedLoginTime(new Date());
            throw new AuthenticationLoginException("Login failed", "Disabled user cannot be set to current user. User: " + user.getAccountName() );
        }

        // don't let locked users log in
        if (user.isLocked()) {
        	user.logout();
			user.incrementFailedLoginCount();
            user.setLastFailedLoginTime(new Date());
            throw new AuthenticationLoginException("Login failed", "Locked user cannot be set to current user. User: " + user.getAccountName() );
        }

        // don't let expired users log in
        if (user.isExpired()) {
        	user.logout();
			user.incrementFailedLoginCount();
            user.setLastFailedLoginTime(new Date());
            throw new AuthenticationLoginException("Login failed", "Expired user cannot be set to current user. User: " + user.getAccountName() );
        }

        // check session inactivity timeout
		if ( user.isSessionTimeout() ) {
        	user.logout();
			user.incrementFailedLoginCount();
            user.setLastFailedLoginTime(new Date());
			throw new AuthenticationLoginException("Login failed", "Session inactivity timeout: " + user.getAccountName() );
		}
				
		// check session absolute timeout
		if ( user.isSessionAbsoluteTimeout() ) {
        	user.logout();
			user.incrementFailedLoginCount();
            user.setLastFailedLoginTime(new Date());
			throw new AuthenticationLoginException("Login failed", "Session absolute timeout: " + user.getAccountName() );
		}
			
		request.getSession().setAttribute(USER, user);
        setCurrentUser(user);
        return user;
    }


    /**
     * Log out the current user.
     */
    public void logout() {
    	User user = getCurrentUser();
        if ( user != null && !user.isAnonymous() ) {
        	user.logout();
        }
    }
    
    
    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#setCurrentUser(org.owasp.esapi.User)
     */
    public void setCurrentUser(User user) {
        currentUser.setUser(user);
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
    public void verifyAccountNameStrength(String newAccountName) throws AuthenticationException {
        if (newAccountName == null) {
            throw new AuthenticationCredentialsException("Invalid account name", "Attempt to create account with a null account name");
        }
        if (!ESAPI.validator().isValidInput("verifyAccountNameStrength", newAccountName, "AccountName", MAX_ACCOUNT_NAME_LENGTH, false )) {
            throw new AuthenticationCredentialsException("Invalid account name", "New account name is not valid: " + newAccountName);
        }
    }

    /*
     * This implementation checks: - for any 3 character substrings of the old password - for use of a length *
     * character sets > 16 (where character sets are upper, lower, digit, and special (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.IAuthenticator#verifyPasswordStrength(java.lang.String)
     */
    public void verifyPasswordStrength(String oldPassword, String newPassword) throws AuthenticationException {
        if ( oldPassword == null ) oldPassword = "";
        if ( newPassword == null ) throw new AuthenticationCredentialsException("Invalid password", "New password cannot be null" );

        // can't change to a password that contains any 3 character substring of old password
        int length = oldPassword.length();
        for (int i = 0; i < length - 2; i++) {
            String sub = oldPassword.substring(i, i + 3);
            if (newPassword.indexOf(sub) > -1 ) {
                throw new AuthenticationCredentialsException("Invalid password", "New password cannot contain pieces of old password" );
            }
        }

        // new password must have enough character sets and length
        int charsets = 0;
        for (int i = 0; i < newPassword.length(); i++)
            if (Arrays.binarySearch(DefaultEncoder.CHAR_LOWERS, newPassword.charAt(i)) > 0) {
                charsets++;
                break;
            }
        for (int i = 0; i < newPassword.length(); i++)
            if (Arrays.binarySearch(DefaultEncoder.CHAR_UPPERS, newPassword.charAt(i)) > 0) {
                charsets++;
                break;
            }
        for (int i = 0; i < newPassword.length(); i++)
            if (Arrays.binarySearch(DefaultEncoder.CHAR_DIGITS, newPassword.charAt(i)) > 0) {
                charsets++;
                break;
            }
        for (int i = 0; i < newPassword.length(); i++)
            if (Arrays.binarySearch(DefaultEncoder.CHAR_SPECIALS, newPassword.charAt(i)) > 0) {
                charsets++;
                break;
            }
        
        // calculate and verify password strength
        int strength = newPassword.length() * charsets;        
        if (strength < 16) {
            throw new AuthenticationCredentialsException("Invalid password", "New password is not long and complex enough");
        }
    }

}
