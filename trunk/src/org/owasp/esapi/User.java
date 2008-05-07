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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.owasp.esapi.errors.AuthenticationAccountsException;
import org.owasp.esapi.errors.AuthenticationCredentialsException;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.AuthenticationHostException;
import org.owasp.esapi.errors.AuthenticationLoginException;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.IntegrityException;
import org.owasp.esapi.interfaces.ILogger;
import org.owasp.esapi.interfaces.IUser;

/**
 * Reference implementation of the IUser interface. This implementation is serialized into a flat file in a simple format.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.interfaces.IUser
 */
public class User implements IUser, Serializable {


	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/** The logger. */
	private static final ILogger logger = ESAPI.getLogger("User");
    
	/** The account name. */
	private String accountName = "";

	/** The screen name. */
	private String screenName = "";

	/** The hashed password. */
	private String hashedPassword = "";

	/** The old password hashes. */
	private List oldPasswordHashes = new ArrayList();

	/** The remember token. */
	protected String rememberToken = "";

	/** The csrf token. */
	private String csrfToken = "";

	/** The roles. */
	private Set roles = new HashSet();

	/** The locked. */
	private boolean locked = false;

	/** The logged in. */
	private boolean loggedIn = true;

    /** The enabled. */
	private boolean enabled = false;

    /** The last host address used. */
    private String lastHostAddress;

	/** The last password change time. */
	private Date lastPasswordChangeTime = new Date();

	/** The last login time. */
	private Date lastLoginTime = new Date();

	/** The last failed login time. */
	private Date lastFailedLoginTime = new Date();
	
	/** The expiration time. */
	private Date expirationTime = new Date(Long.MAX_VALUE);

	/** A flag to indicate that the password must be changed before the account can be used. */
	// FIXME: ENHANCE enable this required password change feature?
	// private boolean requiresPasswordChange = true;
	
	/** The failed login count. */
	private int failedLoginCount = 0;
    
    // FIXME: ENHANCE consider adding these for authentication / access control support
    //
    //private String authenticationMethod = null;
    //
    //private String connectionChannel = null;
	
    /**
     * TODO: Push to configuration? 
     * Maximum legal role size 
     **/
    private final int MAX_ROLE_LENGTH = 250;
    
	/**
	 * Instantiates a new user.
	 */
	protected User() {
		// hidden
	}

	void setOldPasswordHashes(List hashes) {
		oldPasswordHashes.clear();
		oldPasswordHashes.addAll(hashes);
	}
	
	List getOldPasswordHashes() {
		return Collections.unmodifiableList(oldPasswordHashes);
	}
	
	/**
	 * Instantiates a new user.
	 * 
	 * @param accountName
	 *            the account name
	 * @param password1
	 *            the password1
	 * @param password2
	 *            the password2
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	User(String accountName, String password1, String password2) throws AuthenticationException {
		
		ESAPI.authenticator().verifyAccountNameStrength(accountName);

		if ( password1 == null ) {
			throw new AuthenticationCredentialsException( "Invalid account name", "Attempt to create account " + accountName + " with a null password" );
		}
		ESAPI.authenticator().verifyPasswordStrength(password1, null );
		
		if (!password1.equals(password2)) throw new AuthenticationCredentialsException("Passwords do not match", "Passwords for " + accountName + " do not match");
		
		this.accountName = accountName.toLowerCase();
		try {
		    setHashedPassword( ESAPI.encryptor().hash(password1, this.accountName) );
		} catch (EncryptionException ee) {
		    throw new AuthenticationException("Internal error", "Error hashing password for " + this.accountName, ee);
		}
		
		resetRememberToken();
		
		// FIXME: make configurable
		expirationTime = new Date( System.currentTimeMillis() + (long)1000 * 60 * 60 * 24 * 90 );  // 90 days
		logger.fatal(Logger.SECURITY, "Account created successfully: " + accountName );
	}

	/* (non-Javadoc)
	 * @see org.owasp.esapi.interfaces.IUser#addRole(java.lang.String)
	 */
	public void addRole(String role) throws AuthenticationException {
		String roleName = role.toLowerCase();
		if ( ESAPI.validator().isValidInput("addRole", roleName, "RoleName", MAX_ROLE_LENGTH, false) ) {
			roles.add(roleName);
			logger.fatal(Logger.SECURITY, "Role " + roleName + " added to " + getAccountName() );
		} else {
			throw new AuthenticationAccountsException( "Add role failed", "Attempt to add invalid role " + roleName + " to " + getAccountName() );
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#addRoles(java.util.Set)
	 */
	public void addRoles(Set newRoles) throws AuthenticationException {
		Iterator i = newRoles.iterator();
		while(i.hasNext()) {
			addRole((String)i.next());
		}
	}

	// FIXME: ENHANCE - make admin only methods separate from public API
	/**
	 * Change password.
	 * 
	 * @param newPassword1
	 *            the new password1
	 * @param newPassword2
	 *            the new password2
	 */
	protected void changePassword(String newPassword1, String newPassword2) throws EncryptionException {
		setLastPasswordChangeTime(new Date());
		String newHash = ESAPI.authenticator().hashPassword(newPassword1, getAccountName() );
		setHashedPassword( newHash );
		logger.fatal(Logger.SECURITY, "Password changed for user: " + getAccountName() );
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#setPassword(java.lang.String, java.lang.String)
	 */
	public void changePassword(String oldPassword, String newPassword1, String newPassword2) throws AuthenticationException, EncryptionException {
		if (!hashedPassword.equals(ESAPI.authenticator().hashPassword(oldPassword, getAccountName()))) {
			throw new AuthenticationCredentialsException("Password change failed", "Authentication failed for password change on user: " + getAccountName() );
		}
		if (newPassword1 == null || newPassword2 == null || !newPassword1.equals(newPassword2)) {
			throw new AuthenticationCredentialsException("Password change failed", "Passwords do not match for password change on user: " + getAccountName() );
		}
		ESAPI.authenticator().verifyPasswordStrength(newPassword1, oldPassword);
		setLastPasswordChangeTime(new Date());
		String newHash = ESAPI.authenticator().hashPassword(newPassword1, accountName);
		if (oldPasswordHashes.contains(newHash)) {
			throw new AuthenticationCredentialsException( "Password change failed", "Password change matches a recent password for user: " + getAccountName() );
		}
		setHashedPassword( newHash );
		logger.fatal(Logger.SECURITY, "Password changed for user: " + getAccountName() );
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#disable()
	 */
	public void disable() {
		// FIXME: ENHANCE what about disabling for a short time period - to address DOS attack?
		enabled = false;
		logger.info( Logger.SECURITY, "Account disabled: " + getAccountName() );
	}
	
	/**
	 * Enable the account
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#enable()
	 */
	public void enable() {
		this.enabled = true;
		logger.info( Logger.SECURITY, "Account enabled: " + getAccountName() );
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!getClass().equals(obj.getClass()))
			return false;
		final User other = (User)obj;
		return accountName.equals(other.accountName);
	}

	/**
	 * Gets the account name.
	 * 
	 * @return the accountName
	 */
	public String getAccountName() {
		return accountName;
	}

	/**
	 * Gets the CSRF token. Use the HTTPUtilities.checkCSRFToken( request ) to verify the token.
	 * 
	 * @return the csrfToken
	 */
	public String getCSRFToken() {
		return csrfToken;
	}

	/**
	 * Gets the expiration time.
	 * 
	 * @return The expiration time of the current user.
	 */
	public Date getExpirationTime() {
		return (Date)expirationTime.clone();
	}

	/**
	 * Gets the failed login count.
	 * 
	 * @return the failedLoginCount
	 */
	public int getFailedLoginCount() {
		return failedLoginCount;
	}
	
	void setFailedLoginCount(int count) {
		failedLoginCount = count;
	}
	
	/*
	 * Gets the hashed password.
	 * 
	 * @return the hashedPassword
	 */
	protected String getHashedPassword() {
		return hashedPassword;
	}

	/**
	 * Gets the remember token for use in cookies.
	 */
	protected String getRememberToken() {
		return rememberToken;
	}

	/**
	 * Gets the last failed login time.
	 * 
	 * @return the lastFailedLoginTime
	 */
	public Date getLastFailedLoginTime() {
		return (Date)lastFailedLoginTime.clone();
	}

	public String getLastHostAddress() {
        return lastHostAddress;
    }

	/**
	 * Gets the last login time.
	 * 
	 * @return the lastLoginTime
	 */
	public Date getLastLoginTime() {
		return (Date)lastLoginTime.clone();
	}

	/**
	 * Gets the last password change time.
	 * 
	 * @return the lastPasswordChangeTime
	 */
	public Date getLastPasswordChangeTime() {
		return (Date)lastPasswordChangeTime.clone();
	}

	/**
	 * Gets the roles.
	 * 
	 * @return the roles
	 */
	public Set getRoles() {
		return Collections.unmodifiableSet(roles);
	}
	
	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#getScreenName()
	 */
	public String getScreenName() {
		return screenName;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	public int hashCode() {
		return accountName.hashCode();
	}

	/* (non-Javadoc)
	 * @see org.owasp.esapi.interfaces.IUser#incrementFailedLoginCount()
	 */
	public void incrementFailedLoginCount() {
		failedLoginCount++;
	}

	/* (non-Javadoc)
	 * @see org.owasp.esapi.interfaces.IUser#isAnonymous()
	 */
	public boolean isAnonymous() {
		// User cannot be anonymous, since we have a special IUser.ANONYMOUS instance
		// for the anonymous user
		return false;
	}

	/**
	 * Checks if is enabled.
	 * 
	 * @return the enabled
	 */
	public boolean isEnabled() {
		return enabled;
	}

	/* (non-Javadoc)
	 * @see org.owasp.esapi.interfaces.IUser#isExpired()
	 */
	public boolean isExpired() {
		return getExpirationTime().before( new Date() );

// FIXME: ENHANCE should expiration happen automatically?  Or based on lastPasswordChangeTime?
//		long from = lastPasswordChangeTime.getTime();
//		long to = new Date().getTime();
//		double difference = to - from;
//		long days = Math.round((difference / (1000 * 60 * 60 * 24)));
//		return days > 60;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#isInRole(java.lang.String)
	 */
	public boolean isInRole(String role) {
		return roles.contains(role.toLowerCase());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#isLocked()
	 */
	public boolean isLocked() {
		return locked;
	}

	/* (non-Javadoc)
	 * @see org.owasp.esapi.interfaces.IUser#isLoggedIn()
	 */
	public boolean isLoggedIn() {
		return loggedIn;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IIntrusionDetector#isSessionAbsoluteTimeout(java.lang.String)
	 */
	public boolean isSessionAbsoluteTimeout() {
		// FIXME: make configurable - currently 2 hours
		HttpSession session = ESAPI.httpUtilities().getCurrentRequest().getSession();
		Date deadline = new Date( session.getCreationTime() + 1000 * 60 * 60 * 2);
		Date now = new Date();
		return now.after(deadline);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IIntrusionDetector#isSessionTimeout(java.lang.String)
	 */
	public boolean isSessionTimeout() {
		HttpSession session = ESAPI.httpUtilities().getCurrentRequest().getSession();
		// FIXME: make configurable - currently -20 minutes
		Date deadline = new Date(session.getLastAccessedTime() + 1000 * 60 * 20);
		Date now = new Date();
		return now.after(deadline);
	}

    /*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#lock()
	 */
	public void lock() {
		this.locked = true;
		logger.fatal(Logger.SECURITY, "Account locked: " + getAccountName() );
	}

    /*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#login(java.lang.String)
	 */
	public void loginWithPassword(String password) throws AuthenticationException {
		if ( password == null || password.equals("") ) {
			setLastFailedLoginTime(new Date());
			incrementFailedLoginCount();
			throw new AuthenticationLoginException( "Login failed", "Missing password: " + accountName  );
		}
		
		// don't let disabled users log in
		if ( !isEnabled() ) {
			setLastFailedLoginTime(new Date());
			incrementFailedLoginCount();
			throw new AuthenticationLoginException("Login failed", "Disabled user attempt to login: " + accountName );
		}
		
		// don't let locked users log in
		if ( isLocked() ) {
			setLastFailedLoginTime(new Date());
			incrementFailedLoginCount();
			throw new AuthenticationLoginException("Login failed", "Locked user attempt to login: " + accountName );
		}
		
		// don't let expired users log in
		if ( isExpired() ) {
			setLastFailedLoginTime(new Date());
			incrementFailedLoginCount();
			throw new AuthenticationLoginException("Login failed", "Expired user attempt to login: " + accountName );
		}
		
		logout();

		if ( verifyPassword( password ) ) {
			// FIXME: AAA verify loggedIn is properly maintained
			loggedIn = true;
			HttpSession session = ESAPI.httpUtilities().changeSessionIdentifier();
			ESAPI.authenticator().setCurrentUser(this);
			setLastLoginTime(new Date());
            setLastHostAddress( ESAPI.httpUtilities().getCurrentRequest().getRemoteHost() );
			logger.trace(ILogger.SECURITY, "User logged in: " + accountName );
		} else {
			loggedIn = false;
			setLastFailedLoginTime(new Date());
			incrementFailedLoginCount();
			if (getFailedLoginCount() >= ESAPI.securityConfiguration().getAllowedLoginAttempts()) {
				lock();
			}
			throw new AuthenticationLoginException("Login failed", "Incorrect password provided for " + getAccountName() );
		}
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#logout()
	 */
	public void logout() {
		ESAPI.httpUtilities().killCookie( Authenticator.REMEMBER_TOKEN_COOKIE_NAME );
		
		HttpServletRequest request = ESAPI.httpUtilities().getCurrentRequest();
		HttpSession session = request.getSession(false);
		if (session != null) {
			session.invalidate();
		}
		ESAPI.httpUtilities().killCookie("JSESSIONID");
		loggedIn = false;
		logger.info(Logger.SECURITY, "Logout successful" );
		ESAPI.authenticator().setCurrentUser(IUser.ANONYMOUS);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#removeRole(java.lang.String)
	 */
	public void removeRole(String role) {
		roles.remove(role.toLowerCase());
		logger.trace(ILogger.SECURITY, "Role " + role + " removed from " + getAccountName() );
	}

	/**
	 * In this implementation, we have chosen to use a random token that is
	 * stored in the User object. Note that it is possible to avoid the use of
	 * server side state by using either the hash of the users's session id or
	 * an encrypted token that includes a timestamp and the user's IP address.
	 * user's IP address. A relatively short 8 character string has been chosen
	 * because this token will appear in all links and forms.
	 * 
	 * @return the string
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#resetCSRFToken()
	 */
	public String resetCSRFToken() {
		// user.csrfToken = ESAPI.encryptor().hash( session.getId(),user.name );
		// user.csrfToken = ESAPI.encryptor().encrypt( address + ":" + ESAPI.encryptor().getTimeStamp();
		csrfToken = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS);
		return csrfToken;
	}

	/**
	 * Reset password.
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#setPassword(java.lang.String, java.lang.String)
	 * @return the string
	 */
	public String resetPassword() throws EncryptionException {
		// FIXME: set a flag to require manual reset on first login
		String newPassword = ESAPI.authenticator().generateStrongPassword();
		changePassword( newPassword, newPassword );
		return newPassword;
	}

	/**
	 * Regenerates the user's remember token by sealing the account name and hashed password with a timestamp.
	 * The account name is used to look up the user when the remember token is received. The hashed password
	 * is included to allow the user to invalidate all existing remember tokens by changing their password.
	 * 
	 * @return the string
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public String resetRememberToken() throws AuthenticationException {
		// FIXME: make length of time configurable
		// String random = ESAPI.randomizer().getRandomString(8, Encoder.CHAR_ALPHANUMERICS );
		long timestamp = ESAPI.encryptor().getRelativeTimeStamp( 1000 * 60 * 60 * 24 * 14 );
		try {
		    rememberToken = ESAPI.encryptor().seal( getAccountName() + "|" + getHashedPassword(), timestamp );
		} catch (IntegrityException e) {
		    throw new AuthenticationException("Internal error", "Error creating remember token for " + accountName, e);
		}
		
		// FIXME: don't  log this.
		logger.trace(ILogger.SECURITY, "New remember token generated for: " + getAccountName() + " = " + this.rememberToken );
		return rememberToken;
	}

	/**
	 * Sets the account name.
	 * 
	 * @param accountName
	 *            the accountName to set
	 */
	public void setAccountName(String accountName) {
		String old = accountName;
		this.accountName = accountName.toLowerCase();
		logger.fatal(Logger.SECURITY, "Account name changed from " + old + " to " + getAccountName() );
	}

	/**
	 * Sets the expiration time.
	 * 
	 * @param expirationTime
	 *            the expirationTime to set
	 */
	public void setExpirationTime(Date expirationTime) {
		this.expirationTime = new Date( expirationTime.getTime() );
		logger.fatal(Logger.SECURITY, "Account expiration time set to " + expirationTime + " for " + getAccountName() );
	}

	/**
	 * Sets the hashed password.
	 * 
	 * @param hash
	 *            the hash
	 */
	void setHashedPassword(String hash) {
		oldPasswordHashes.add( hashedPassword);
		if (oldPasswordHashes.size() > ESAPI.securityConfiguration().getMaxOldPasswordHashes() ) oldPasswordHashes.remove( 0 );
		hashedPassword = hash;
		logger.fatal(Logger.SECURITY, "New hashed password stored for " + getAccountName() );
	}
	
	/**
	 * Sets the last failed login time.
	 * 
	 * @param lastFailedLoginTime
	 *            the lastFailedLoginTime to set
	 */
	protected void setLastFailedLoginTime(Date lastFailedLoginTime) {
		this.lastFailedLoginTime = lastFailedLoginTime;
		logger.fatal(Logger.SECURITY, "Set last failed login time to " + lastFailedLoginTime + " for " + getAccountName() );
	}
	
	
	/**
     * Sets the last remote host address used by this User.
     * @param remoteHost
     */
	public void setLastHostAddress(String remoteHost) {
		if ( lastHostAddress != null && !lastHostAddress.equals(remoteHost)) {
        	// returning remote address not remote hostname to prevent DNS lookup
			new AuthenticationHostException("Host change", "User session just jumped from " + lastHostAddress + " to " + remoteHost );
		}
		lastHostAddress = remoteHost;
    }

	/**
	 * Sets the last login time.
	 * 
	 * @param lastLoginTime
	 *            the lastLoginTime to set
	 */
	protected void setLastLoginTime(Date lastLoginTime) {
		this.lastLoginTime = lastLoginTime;
		logger.fatal(Logger.SECURITY, "Set last successful login time to " + lastLoginTime + " for " + getAccountName() );
	}

	/**
	 * Sets the last password change time.
	 * 
	 * @param lastPasswordChangeTime
	 *            the lastPasswordChangeTime to set
	 */
	protected void setLastPasswordChangeTime(Date lastPasswordChangeTime) {
		this.lastPasswordChangeTime = lastPasswordChangeTime;
		logger.fatal(Logger.SECURITY, "Set last password change time to " + lastPasswordChangeTime + " for " + getAccountName() );
	}

	/**
	 * Sets the roles.
	 * 
	 * @param roles
	 *            the roles to set
	 */
	public void setRoles(Set roles) throws AuthenticationException {
		this.roles = new HashSet();
		addRoles(roles);
		logger.fatal(Logger.SECURITY, "Adding roles " + roles + " to " + getAccountName() );
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#setScreenName(java.lang.String)
	 */
	public void setScreenName(String screenName) {
		this.screenName = screenName;
		logger.fatal(Logger.SECURITY, "ScreenName changed to " + screenName + " for " + getAccountName() );
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		return "USER:" + accountName;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#unlock()
	 */
	public void unlock() {
		this.locked = false;
		this.failedLoginCount = 0;
		logger.info( Logger.SECURITY, "Account unlocked: " + getAccountName() );
	}

	//FIXME:Enhance - think about having a second "transaction" password for each user

	
    /*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#verifyPassword(java.lang.String)
	 */
	public boolean verifyPassword(String password) {
		try {
			String hash = ESAPI.authenticator().hashPassword(password, accountName);
			if (hash.equals(hashedPassword)) {
				setLastLoginTime(new Date());
				failedLoginCount = 0;
				logger.fatal(Logger.SECURITY, "Password verified for " + getAccountName() );
				return true;
			}
		} catch( EncryptionException e ) {
			logger.fatal(Logger.SECURITY, "Encryption error verifying password for " + getAccountName() );
		}
		logger.fatal(Logger.SECURITY, "Password verification failed for " + getAccountName() );
		return false;
	}
    
    /**
     * Override clone and make final to prevent duplicate user objects.
     */
    public final Object clone() throws java.lang.CloneNotSupportedException {
    	  throw new java.lang.CloneNotSupportedException();
    }
    
}
