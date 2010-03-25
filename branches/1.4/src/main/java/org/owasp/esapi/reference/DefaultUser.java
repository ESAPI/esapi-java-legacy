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

import java.io.Serializable;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.servlet.http.HttpSession;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.HTTPUtilities;
import org.owasp.esapi.Logger;
import org.owasp.esapi.User;
import org.owasp.esapi.errors.AuthenticationAccountsException;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.AuthenticationHostException;
import org.owasp.esapi.errors.AuthenticationLoginException;
import org.owasp.esapi.errors.EncryptionException;

/**
 * Reference implementation of the User interface. This implementation is serialized into a flat file in a simple format.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.User
 */
public class DefaultUser implements User, Serializable {


	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/** The idle timeout length specified in the ESAPI config file. */
	private static final int IDLE_TIMEOUT_LENGTH = ESAPI.securityConfiguration().getSessionIdleTimeoutLength();
	
	/** The absolute timeout length specified in the ESAPI config file. */
	private static final int ABSOLUTE_TIMEOUT_LENGTH = ESAPI.securityConfiguration().getSessionAbsoluteTimeoutLength();
	
	/** The logger used by the class. */
	private static final Logger logger = ESAPI.getLogger("DefaultUser");
    
	/** This user's account id. */
	long accountId = 0;

	/** This user's account name. */
	private String accountName = "";

	/** This user's screen name (account name alias). */
	private String screenName = "";

	/** This user's CSRF token. */
	private String csrfToken = "";

	/** This user's assigned roles. */
	private Set roles = new HashSet();

	/** Whether this user's account is locked. */
	private boolean locked = false;

	/** Whether this user is logged in. */
	private boolean loggedIn = true;

    /** Whether this user's account is enabled. */
	private boolean enabled = false;

    /** The last host address used by this user. */
    private String lastHostAddress;

	/** The last password change time for this user. */
	private Date lastPasswordChangeTime = new Date(0);

	/** The last login time for this user. */
	private Date lastLoginTime = new Date(0);

	/** The last failed login time for this user. */
	private Date lastFailedLoginTime = new Date(0);
	
	/** The expiration date/time for this user's account. */
	private Date expirationTime = new Date(Long.MAX_VALUE);

	/** The session's this user is associated with */
	private Set sessions = new HashSet();
	
	/* A flag to indicate that the password must be changed before the account can be used. */
	// private boolean requiresPasswordChange = true;
	
	/** The failed login count for this user's account. */
	private int failedLoginCount = 0;
    
    private final int MAX_ROLE_LENGTH = 250;
    
	/**
	 * Instantiates a new user.
	 * 
	 * @param accountName
	 * 		The name of this user's account.
	 */
	DefaultUser(String accountName) {
		setAccountName(accountName);
		while( true ) {
			long id = Math.abs( ESAPI.randomizer().getRandomLong() );
			if ( ESAPI.authenticator().getUser( id ) == null && id != 0 ) {
				setAccountId(id);
				break;
			}
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public void addRole(String role) throws AuthenticationException {
		String roleName = role.toLowerCase();
		if ( ESAPI.validator().isValidInput("addRole", roleName, "RoleName", MAX_ROLE_LENGTH, false) ) {
			roles.add(roleName);
			logger.info(Logger.SECURITY, true, "Role " + roleName + " added to " + getAccountName() );
		} else {
			throw new AuthenticationAccountsException( "Add role failed", "Attempt to add invalid role " + roleName + " to " + getAccountName() );
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public void addRoles(Set newRoles) throws AuthenticationException {
		Iterator i = newRoles.iterator();
		while(i.hasNext()) {
			addRole((String)i.next());
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public void changePassword(String oldPassword, String newPassword1, String newPassword2) throws AuthenticationException, EncryptionException {
		ESAPI.authenticator().changePassword(this, oldPassword, newPassword1, newPassword2);
	}

	/**
	 * {@inheritDoc}
	 */
	public void disable() {
		enabled = false;
		logger.info( Logger.SECURITY, true, "Account disabled: " + getAccountName() );
	}
	
	/**
	 * {@inheritDoc}
	 */
	public void enable() {
		this.enabled = true;
		logger.info( Logger.SECURITY, true, "Account enabled: " + getAccountName() );
	}

	/**
	 * {@inheritDoc}
	 */
    public long getAccountId() {
        return accountId;
    }

	/**
	 * {@inheritDoc}
	 */
	public String getAccountName() {
		return accountName;
	}

	/**
	 * {@inheritDoc}
	 */
	public String getCSRFToken() {
		return csrfToken;
	}

	/**
	 * {@inheritDoc}
	 */
	public Date getExpirationTime() {
		return (Date)expirationTime.clone();
	}

	/**
	 * {@inheritDoc}
	 */
	public int getFailedLoginCount() {
		return failedLoginCount;
	}
	
	/**
	 * Set the failed login count
	 * 
	 * @param count
	 * 			the number of failed logins
	 */
	void setFailedLoginCount(int count) {
		failedLoginCount = count;
	}

	/**
	 * {@inheritDoc}
	 */
	public Date getLastFailedLoginTime() {
		return (Date)lastFailedLoginTime.clone();
	}

	/**
	 * {@inheritDoc}
	 */
	public String getLastHostAddress() {
		if ( lastHostAddress == null ) {
			return "local";
		}
        return lastHostAddress;
    }

	/**
	 * {@inheritDoc}
	 */
	public Date getLastLoginTime() {
		return (Date)lastLoginTime.clone();
	}

	/**
	 * {@inheritDoc}
	 */
	public Date getLastPasswordChangeTime() {
		return (Date)lastPasswordChangeTime.clone();
	}

	/**
	 * {@inheritDoc}
	 */
	public String getName() {
		return this.getAccountName();
	}
	
	/**
	 * {@inheritDoc}
	 */
	public Set getRoles() {
		return Collections.unmodifiableSet(roles);
	}
	
	/**
	 * {@inheritDoc}
	 */
	public String getScreenName() {
		return screenName;
	}

	/**
	 * {@inheritDoc}
	 */
    public void addSession( HttpSession s ) {
        sessions.add( s );
    }
    
	/**
	 * {@inheritDoc}
	 */
    public void removeSession( HttpSession s ) {
        sessions.remove( s );
    }
    
	/**
	 * {@inheritDoc}
	 */
	public Set getSessions() {
	    return sessions;
	}
	
	/**
	 * {@inheritDoc}
	 */
	public void incrementFailedLoginCount() {
		failedLoginCount++;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isAnonymous() {
		// User cannot be anonymous, since we have a special User.ANONYMOUS instance
		// for the anonymous user
		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isEnabled() {
		return enabled;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isExpired() {
		return getExpirationTime().before( new Date() );

		// If expiration should happen automatically or based on lastPasswordChangeTime?
		//		long from = lastPasswordChangeTime.getTime();
		//		long to = new Date().getTime();
		//		double difference = to - from;
		//		long days = Math.round((difference / (1000 * 60 * 60 * 24)));
		//		return days > 60;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isInRole(String role) {
		return roles.contains(role.toLowerCase());
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isLocked() {
		return locked;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isLoggedIn() {
		return loggedIn;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isSessionAbsoluteTimeout() {
		HttpSession session = ESAPI.httpUtilities().getCurrentRequest().getSession(false);
		if ( session == null ) return true;
		Date deadline = new Date( session.getCreationTime() + ABSOLUTE_TIMEOUT_LENGTH);
		Date now = new Date();
		return now.after(deadline);
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isSessionTimeout() {
		HttpSession session = ESAPI.httpUtilities().getCurrentRequest().getSession(false);
		if ( session == null ) return true;
		Date deadline = new Date(session.getLastAccessedTime() + IDLE_TIMEOUT_LENGTH);
		Date now = new Date();
		return now.after(deadline);
	}

	/**
	 * {@inheritDoc}
	 */
	public void lock() {
		this.locked = true;
		logger.info(Logger.SECURITY, true, "Account locked: " + getAccountName() );
	}

	/**
	 * {@inheritDoc}
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
			loggedIn = true;
			ESAPI.httpUtilities().changeSessionIdentifier( ESAPI.currentRequest() );
			ESAPI.authenticator().setCurrentUser(this);
			setLastLoginTime(new Date());
            setLastHostAddress( ESAPI.httpUtilities().getCurrentRequest().getRemoteHost() );
			logger.trace(Logger.SECURITY, true, "User logged in: " + accountName );
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


	/**
	 * {@inheritDoc}
	 */
	public void logout() {
		ESAPI.httpUtilities().killCookie( ESAPI.currentRequest(), ESAPI.currentResponse(), HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME );
		
		HttpSession session = ESAPI.currentRequest().getSession(false);
		if (session != null) {
            removeSession(session);
			session.invalidate();
		}
		ESAPI.httpUtilities().killCookie(ESAPI.currentRequest(), ESAPI.currentResponse(), "JSESSIONID");
		loggedIn = false;
		logger.info(Logger.SECURITY, true, "Logout successful" );
		ESAPI.authenticator().setCurrentUser(User.ANONYMOUS);
	}

	/**
	 * {@inheritDoc}
	 */
	public void removeRole(String role) {
		roles.remove(role.toLowerCase());
		logger.trace(Logger.SECURITY, true, "Role " + role + " removed from " + getAccountName() );
	}

	/**
	 * {@inheritDoc}
	 * 
	 * In this implementation, we have chosen to use a random token that is
	 * stored in the User object. Note that it is possible to avoid the use of
	 * server side state by using either the hash of the users's session id or
	 * an encrypted token that includes a timestamp and the user's IP address.
	 * user's IP address. A relatively short 8 character string has been chosen
	 * because this token will appear in all links and forms.
	 * 
	 * @return the string
	 */
	public String resetCSRFToken() {
		// user.csrfToken = ESAPI.encryptor().hash( session.getId(),user.name );
		// user.csrfToken = ESAPI.encryptor().encrypt( address + ":" + ESAPI.encryptor().getTimeStamp();
		csrfToken = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
		return csrfToken;
	}

	/**
	 * Sets the account id for this user's account.
	 */
	private void setAccountId(long accountId) {
		this.accountId = accountId;
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public void setAccountName(String accountName) {
		String old = getAccountName();
		this.accountName = accountName.toLowerCase();
		if (old != null)
			logger.info(Logger.SECURITY, true, "Account name changed from " + old + " to " + getAccountName() );
	}

	/**
	 * {@inheritDoc}
	 */
	public void setExpirationTime(Date expirationTime) {
		this.expirationTime = new Date( expirationTime.getTime() );
		logger.info(Logger.SECURITY, true, "Account expiration time set to " + expirationTime + " for " + getAccountName() );
	}

	/**
	 * {@inheritDoc}
	 */
	public void setLastFailedLoginTime(Date lastFailedLoginTime) {
		this.lastFailedLoginTime = lastFailedLoginTime;
		logger.info(Logger.SECURITY, true, "Set last failed login time to " + lastFailedLoginTime + " for " + getAccountName() );
	}
	
	/**
	 * {@inheritDoc}
	 */
	public void setLastHostAddress(String remoteHost) {
		if ( lastHostAddress != null && !lastHostAddress.equals(remoteHost)) {
        	// returning remote address not remote hostname to prevent DNS lookup
			new AuthenticationHostException("Host change", "User session just jumped from " + lastHostAddress + " to " + remoteHost );
		}
		lastHostAddress = remoteHost;
    }

	/**
	 * {@inheritDoc}
	 */
	public void setLastLoginTime(Date lastLoginTime) {
		this.lastLoginTime = lastLoginTime;
		logger.info(Logger.SECURITY, true, "Set last successful login time to " + lastLoginTime + " for " + getAccountName() );
	}

	/**
	 * {@inheritDoc}
	 */
	public void setLastPasswordChangeTime(Date lastPasswordChangeTime) {
		this.lastPasswordChangeTime = lastPasswordChangeTime;
		logger.info(Logger.SECURITY, true, "Set last password change time to " + lastPasswordChangeTime + " for " + getAccountName() );
	}

	/**
	 * {@inheritDoc}
	 */
	public void setRoles(Set roles) throws AuthenticationException {
		this.roles = new HashSet();
		addRoles(roles);
		logger.info(Logger.SECURITY, true, "Adding roles " + roles + " to " + getAccountName() );
	}

	/**
	 * {@inheritDoc}
	 */
	public void setScreenName(String screenName) {
		this.screenName = screenName;
		logger.info(Logger.SECURITY, true, "ScreenName changed to " + screenName + " for " + getAccountName() );
	}

	/**
	 * {@inheritDoc}
	 */
	public String toString() {
		return "USER:" + accountName;
	}

	/**
	 * {@inheritDoc}
	 */
	public void unlock() {
		this.locked = false;
		this.failedLoginCount = 0;
		logger.info( Logger.SECURITY, true, "Account unlocked: " + getAccountName() );
	}
	
	/**
	 * {@inheritDoc}
	 */
	public boolean verifyPassword(String password) {
		return ESAPI.authenticator().verifyPassword(this, password);
	}
    
    /**
     * Override clone and make final to prevent duplicate user objects.
     */
    public final Object clone() throws java.lang.CloneNotSupportedException {
    	  throw new java.lang.CloneNotSupportedException();
    }
    
}
