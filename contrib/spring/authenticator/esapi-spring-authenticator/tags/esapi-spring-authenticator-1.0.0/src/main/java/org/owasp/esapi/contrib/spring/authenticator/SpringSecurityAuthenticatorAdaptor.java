package org.owasp.esapi.contrib.spring.authenticator;

import org.owasp.esapi.Authenticator;
import org.owasp.esapi.User;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.reference.DefaultUser;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.intercept.RunAsUserToken;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

public abstract class SpringSecurityAuthenticatorAdaptor<T> implements Authenticator, AuthenticationProvider, InitializingBean {
    private UserDetailsService userDetailsService;

    private AuthenticationStrategy<T> authenticationStrategy;

    private AuthoritiesPopulator authoritiesPopulator;

    protected AuthenticationStrategy<T> getAuthenticationStrategy() {
        return authenticationStrategy;
    }

    public void setAuthenticationStrategy(AuthenticationStrategy<T> authenticationStrategy) {
        this.authenticationStrategy = authenticationStrategy;
    }

    protected UserDetailsService getUserDetailsService() {
        return userDetailsService;
    }

    public void setAuthoritiesPopulator(AuthoritiesPopulator authoritiesPopulator) {
        this.authoritiesPopulator = authoritiesPopulator;
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public void clearCurrent() {
        SecurityContextHolder.getContext().setAuthentication(null);
    }

    public User login() throws AuthenticationException {
        throw new UnsupportedOperationException("not implemented - Spring-Security handles login and logout");
    }

    public User login(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        throw new UnsupportedOperationException("not implemented - Spring-Security handles login and logout");
    }

    public boolean verifyPassword(User user, String password) {
        throw new UnsupportedOperationException("not implemented - Spring-Security handles login and logout");
    }

    public void logout() {
        throw new UnsupportedOperationException("not implemented - Spring-Security handles login and logout");
    }

    public User getCurrentUser() {
        if (SecurityContextHolder.getContext() != null && SecurityContextHolder.getContext().getAuthentication() != null) {
            Authentication authn = SecurityContextHolder.getContext().getAuthentication();
            if (authn instanceof AnonymousAuthenticationToken) {
                return DefaultUser.ANONYMOUS;
            }
            return (User) SecurityContextHolder.getContext().getAuthentication().getDetails();
        }
        return null;
    }

    public void setCurrentUser(User user) {
        Assert.notNull(user);
        Assert.isInstanceOf(AuthenticatedUser.class, user);

        AuthenticatedUser authenticatedUser = AuthenticatedUser.class.cast(user);

        Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();

        SecurityContextHolder.getContext().setAuthentication(new RunAsUserToken(
                String.valueOf(user.getAccountId()),
                user.getAccountName(),
                authenticatedUser.getPassword(),
                authenticatedUser.getAuthorities(),
                currentAuthentication.getClass())
        );
    }

    public Authentication authenticate(Authentication authentication) throws org.springframework.security.core.AuthenticationException {
        T authenticatedUser = authenticationStrategy.authenticate(authentication);
        List<GrantedAuthority> authorities = authoritiesPopulator.getAuthoritiesForUser(authentication);
        UserDetails userDetails = userDetailsService.loadUserByUsername(authentication.getName());
        return getAuthentication(authenticatedUser, userDetails, authorities);
    }

    public abstract Authentication getAuthentication(T user, UserDetails userDetails, List<GrantedAuthority> authorities);

    public boolean supports(Class<? extends Object> aClass) {
        return true;
    }

    public User createUser(String accountName, String password1, String password2) throws AuthenticationException {
        Assert.notNull(accountName, "Account Name cannot be null or empty");
        Assert.notNull(password1, "Password cannot be null or empty");
        Assert.isTrue(password1.equals(password2), "Passwords do not match");

        verifyAccountNameStrength(accountName);

        DefaultUser createUser = new DefaultUser(accountName);

        verifyPasswordStrength(null, password1, createUser);

        return authenticationStrategy.createUser(accountName, password1);
    }

    public void changePassword(User user, String currentPassword, String newPassword, String newPassword2) throws AuthenticationException {
        Assert.notNull(user);
        Assert.notNull(currentPassword);
        Assert.notNull(newPassword);
        Assert.isTrue(newPassword.equals(newPassword2));

        verifyPasswordStrength(currentPassword, newPassword, user);

        authenticationStrategy.changePassword(user.getAccountName(), newPassword);
    }

    public void removeUser(String accountName) throws AuthenticationException {
        authenticationStrategy.deleteUser(accountName);
    }

    public boolean exists(String accountName) {
        return authenticationStrategy.userExists(accountName);
    }
}
