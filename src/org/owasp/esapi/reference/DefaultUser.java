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

	/** The logger. */
	private final Logger logger = ESAPI.getLogger("User");
    
	/** The account id. */
	long accountId = 0;

	/** The account name. */
	private String accountName = "";

	/** The screen name. */
	private String screenName = "";

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
	private Date lastPasswordChangeTime = new Date(0);

	/** The last login time. */
	private Date lastLoginTime = new Date(0);

	/** The last failed login time. */
	private Date lastFailedLoginTime = new Date(0);
	
	/** The expiration time. */
	private Date expirationTime = new Date(Long.MAX_VALUE);

	/** A flag to indicate that the password must be changed before the account can be used. */
	// private boolean requiresPasswordChange = true;
	
	/** The failed login count. */
	private int failedLoginCount = 0;
    
    private final int MAX_ROLE_LENGTH = 250;
    
	/**
	 * Instantiates a new user.
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

	/* (non-Javadoc)
	 * @see org.owasp.esapi.interfaces.IUser#addRole(java.lang.String)
	 */
	public void addRole(String role) throws AuthenticationException {
		String roleName = role.toLowerCase();
		if ( ESAPI.validator().isValidInput("addRole", roleName, "RoleName", MAX_ROLE_LENGTH, false) ) {
			roles.add(roleName);
			logger.info(Logger.SECURITY, "Role " + roleName + " added to " + getAccountName() );
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

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#setPassword(java.lang.String, java.lang.String)
	 */
	public void changePassword(String oldPassword, String newPassword1, String newPassword2) throws AuthenticationException, EncryptionException {
		ESAPI.authenticator().changePassword(this, oldPassword, newPassword1, newPassword2);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#disable()
	 */
	public void disable() {
		enabled = false;
		logger.info( Logger.SECURITY, "Account disabled: " + getAccountName() );
	}
	
	/**
	 * Enable the account
	 * 
	 * @see org.owasp.esapi.User#enable()
	 */
	public void enable() {
		this.enabled = true;
		logger.info( Logger.SECURITY, "Account enabled: " + getAccountName() );
	}

	/* (non-Javadoc)
     * @see org.owasp.esapi.User#getAccountId()
     */
    public long getAccountId() {
        return accountId;
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

	/**
	 * Gets the last failed login time.
	 * 
	 * @return the lastFailedLoginTime
	 */
	public Date getLastFailedLoginTime() {
		return (Date)lastFailedLoginTime.clone();
	}

	public String getLastHostAddress() {
		if ( lastHostAddress == null ) {
			return "local";
		}
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

	public String getName() {
		return this.getAccountName();
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

		// If expiration should happen automatically or based on lastPasswordChangeTime?
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
		logger.info(Logger.SECURITY, "Account locked: " + getAccountName() );
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
			loggedIn = true;
			ESAPI.httpUtilities().changeSessionIdentifier( ESAPI.currentRequest() );
			ESAPI.authenticator().setCurrentUser(this);
			setLastLoginTime(new Date());
            setLastHostAddress( ESAPI.httpUtilities().getCurrentRequest().getRemoteHost() );
			logger.trace(Logger.SECURITY, "User logged in: " + accountName );
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
		ESAPI.httpUtilities().killCookie( ESAPI.currentRequest(), ESAPI.currentResponse(), HTTPUtilities.REMEMBER_TOKEN_COOKIE_NAME );
		
		HttpSession session = ESAPI.currentRequest().getSession(false);
		if (session != null) {
			session.invalidate();
		}
		ESAPI.httpUtilities().killCookie(ESAPI.currentRequest(), ESAPI.currentResponse(), "JSESSIONID");
		loggedIn = false;
		logger.info(Logger.SECURITY, "Logout successful" );
		ESAPI.authenticator().setCurrentUser(User.ANONYMOUS);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#removeRole(java.lang.String)
	 */
	public void removeRole(String role) {
		roles.remove(role.toLowerCase());
		logger.trace(Logger.SECURITY, "Role " + role + " removed from " + getAccountName() );
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
	 * @see org.owasp.esapi.User#resetCSRFToken()
	 */
	public String resetCSRFToken() {
		// user.csrfToken = ESAPI.encryptor().hash( session.getId(),user.name );
		// user.csrfToken = ESAPI.encryptor().encrypt( address + ":" + ESAPI.encryptor().getTimeStamp();
		csrfToken = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
		return csrfToken;
	}

	/**
	 * Sets the account id.
	 */
	private void setAccountId(long accountId) {
		this.accountId = accountId;
	}
	
	
	/**
	 * Sets the account name.
	 * 
	 * @param accountName
	 *            the accountName to set
	 */
	public void setAccountName(String accountName) {
		String old = getAccountName();
		this.accountName = accountName.toLowerCase();
		if (old != null)
			logger.info(Logger.SECURITY, "Account name changed from " + old + " to " + getAccountName() );
	}

	/**
	 * Sets the expiration time.
	 * 
	 * @param expirationTime
	 *            the expirationTime to set
	 */
	public void setExpirationTime(Date expirationTime) {
		this.expirationTime = new Date( expirationTime.getTime() );
		logger.info(Logger.SECURITY, "Account expiration time set to " + expirationTime + " for " + getAccountName() );
	}

	/**
	 * Sets the last failed login time.
	 * 
	 * @param lastFailedLoginTime
	 *            the lastFailedLoginTime to set
	 */
	public void setLastFailedLoginTime(Date lastFailedLoginTime) {
		this.lastFailedLoginTime = lastFailedLoginTime;
		logger.info(Logger.SECURITY, "Set last failed login time to " + lastFailedLoginTime + " for " + getAccountName() );
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
	public void setLastLoginTime(Date lastLoginTime) {
		this.lastLoginTime = lastLoginTime;
		logger.info(Logger.SECURITY, "Set last successful login time to " + lastLoginTime + " for " + getAccountName() );
	}

	/**
	 * Sets the last password change time.
	 * 
	 * @param lastPasswordChangeTime
	 *            the lastPasswordChangeTime to set
	 */
	public void setLastPasswordChangeTime(Date lastPasswordChangeTime) {
		this.lastPasswordChangeTime = lastPasswordChangeTime;
		logger.info(Logger.SECURITY, "Set last password change time to " + lastPasswordChangeTime + " for " + getAccountName() );
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
		logger.info(Logger.SECURITY, "Adding roles " + roles + " to " + getAccountName() );
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#setScreenName(java.lang.String)
	 */
	public void setScreenName(String screenName) {
		this.screenName = screenName;
		logger.info(Logger.SECURITY, "ScreenName changed to " + screenName + " for " + getAccountName() );
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
	
    /*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IUser#verifyPassword(java.lang.String)
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
