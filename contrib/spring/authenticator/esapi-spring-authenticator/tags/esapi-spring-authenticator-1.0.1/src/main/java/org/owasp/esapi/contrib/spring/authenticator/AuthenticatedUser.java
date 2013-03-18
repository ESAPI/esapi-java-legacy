package org.owasp.esapi.contrib.spring.authenticator;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.EncoderConstants;
import org.owasp.esapi.User;
import org.owasp.esapi.contrib.spring.util.DateUtils;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.AuthenticationHostException;
import org.owasp.esapi.errors.EncryptionException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.userdetails.UserDetails;

import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.util.*;

/**
 * AuthenticatedUser bridges the ESAPI User Interface with the Spring-Security UserDetails Interface so that the same
 * object can be retrieved when both {@link org.owasp.esapi.Authenticator#getCurrentUser()} or
 * {@link org.springframework.security.core.context.SecurityContext#getAuthentication()} are called.
 */
public class AuthenticatedUser implements User, UserDetails, Serializable {
    private UserProfile userProfile;
    private Set<GrantedAuthority> authorities;
    private transient String csrfToken;

    // Issue 292 - Fix Java 7 incompatibility
    private transient Collection<HttpSession> sessions;

    private transient HashMap eventMap;

    public AuthenticatedUser(UserProfile userProfile) {
        this.userProfile = userProfile;
        authorities = new TreeSet<GrantedAuthority>();
        sessions = new ArrayList<HttpSession>();
        eventMap = new HashMap();

        // Issue 292 Fix Java 7 incompatibility
        sessions.add(ESAPI.currentRequest().getSession());
    }

    public Locale getLocale() {
        // TODO: Allow this to be overridden in the database
        return ESAPI.currentRequest().getLocale();
    }

    public void setLocale(Locale locale) {
        throw new UnsupportedOperationException("not implemented");
    }

    public void addRole(String role) throws AuthenticationException {
        GrantedAuthority authority = new GrantedAuthorityImpl(role);
        authorities.add(authority);
    }

    public void addRoles(Set<String> newRoles) throws AuthenticationException {
        for (String role : newRoles) {
            GrantedAuthority authority = new GrantedAuthorityImpl(role);
            authorities.add(authority);
        }
    }

    public void changePassword(String oldPassword, String newPassword1, String newPassword2) throws AuthenticationException, EncryptionException {
        ESAPI.authenticator().changePassword(this, oldPassword, newPassword1, newPassword2);
    }

    public void disable() {
        userProfile.setEnabled(false);
    }

    public void enable() {
        userProfile.setEnabled(true);
    }

    public long getAccountId() {
        return userProfile.getId();
    }

    public String getAccountName() {
        return userProfile.getAccountName();
    }

    public String getCSRFToken() {
        return csrfToken;
    }

    public Date getExpirationTime() {
        return userProfile.getExpirationDate();
    }

    public int getFailedLoginCount() {
        return userProfile.getFailedLoginCount();
    }

    public String getLastHostAddress() {
        return userProfile.getLastHostAddress();
    }

    public Date getLastFailedLoginTime() throws AuthenticationException {
        return userProfile.getLastFailedLoginTime();
    }

    public Date getLastLoginTime() {
        return userProfile.getLastLoginTime();
    }

    public Date getLastPasswordChangeTime() {
        return userProfile.getLastPasswordChangeTime();
    }

    public Set<String> getRoles() {
        Set<String> roles = new TreeSet<String>();
        for (GrantedAuthority authority : authorities) {
            roles.add(authority.getAuthority());
        }
        return roles;
    }

    public String getScreenName() {
        return userProfile.getScreenName();
    }

    public void addSession(HttpSession s) {
        if (!sessions.contains(s)) {
            sessions.add(s);
        }
    }

    public void removeSession(HttpSession s) {
        // Issue 292 Changed to use removeAll in case of duplicates
        sessions.removeAll(Arrays.asList(s));
    }

    public Set getSessions() {
        return new HashSet(sessions);
    }

    public void incrementFailedLoginCount() {
        userProfile.setFailedLoginCount(userProfile.getFailedLoginCount() + 1);
    }

    public boolean isAnonymous() {
        return false;
    }

    public Collection<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public String getPassword() {
        return userProfile.getPassword();
    }

    public String getUsername() {
        return userProfile.getAccountName();
    }

    public boolean isAccountNonExpired() {
        return DateUtils.isDateFuture(userProfile.getExpirationDate());
    }

    public boolean isAccountNonLocked() {
        return userProfile.isEnabled();
    }

    public boolean isCredentialsNonExpired() {
        // TODO: Implement a policy
        return false;
    }

    public boolean isEnabled() {
        return userProfile.isEnabled();
    }

    public boolean isExpired() {
        return DateUtils.isDatePast(userProfile.getExpirationDate());
    }

    public boolean isInRole(String role) {
        for (GrantedAuthority authority : authorities) {
            if (authority.getAuthority().equals(role)) {
                return true;
            }
        }
        return false;
    }

    public boolean isLocked() {
        return userProfile.isLocked();
    }

    public boolean isLoggedIn() {
        return userProfile.isLoggedIn();
    }

    public boolean isSessionAbsoluteTimeout() {
        // TODO: Implement
        return false;
    }

    public boolean isSessionTimeout() {
        // TODO: Implement
        return false;
    }

    public void lock() {
        userProfile.setLocked(true);
    }

    public void loginWithPassword(String password) throws AuthenticationException {
        throw new UnsupportedOperationException("not implemented");
    }

    public void logout() {
        throw new UnsupportedOperationException("not implemented");
    }

    public void removeRole(String role) throws AuthenticationException {
        for (GrantedAuthority authority : authorities) {
            if (authority.getAuthority().equals(role)) {
                authorities.remove(authority);
            }
        }
    }

    public String resetCSRFToken() throws AuthenticationException {
        csrfToken = ESAPI.randomizer().getRandomString(32, EncoderConstants.CHAR_ALPHANUMERICS);
        return csrfToken;
    }

    public void setAccountName(String accountName) {
        userProfile.setAccountName(accountName);
    }

    public void setExpirationTime(Date expirationTime) {
        userProfile.setExpirationDate(expirationTime);
    }

    public void setRoles(Set<String> roles) throws AuthenticationException {
        this.authorities = new TreeSet<GrantedAuthority>();
        addRoles(roles);
    }

    public void setScreenName(String screenName) {
        userProfile.setScreenName(screenName);
    }

    public void unlock() {
        userProfile.setLocked(false);
    }

    public boolean verifyPassword(String password) throws EncryptionException {
        return this.getPassword().equals(password);
    }

    public void setLastFailedLoginTime(Date lastFailedLoginTime) {
        userProfile.setLastFailedLoginTime(lastFailedLoginTime);
    }

    public void setLastHostAddress(String remoteHost) throws AuthenticationHostException {
        userProfile.setLastHostAddress(remoteHost);
    }

    public void setLastLoginTime(Date lastLoginTime) {
        userProfile.setLastLoginTime(lastLoginTime);
    }

    public void setLastPasswordChangeTime(Date lastPasswordChangeTime) {
        userProfile.setLastPasswordChangeTime(lastPasswordChangeTime);
    }

    public HashMap getEventMap() {
        return eventMap;
    }

    public String getName() {
        return userProfile.getFirstName() + " " + userProfile.getLastName();
    }

    public void setAuthorities(Set<GrantedAuthority> authorities) {
        this.authorities = authorities;
    }

    public boolean isSuperUser() {
        return userProfile.isSuperUser();
    }
}
