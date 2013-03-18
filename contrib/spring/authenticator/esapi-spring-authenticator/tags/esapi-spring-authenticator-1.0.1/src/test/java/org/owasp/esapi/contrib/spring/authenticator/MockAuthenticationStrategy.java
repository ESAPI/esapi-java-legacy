package org.owasp.esapi.contrib.spring.authenticator;

import org.owasp.esapi.User;
import org.owasp.esapi.contrib.spring.util.DateUtils;
import org.owasp.esapi.reference.DefaultUser;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.Date;

@Component("authenticationStrategy")
public class MockAuthenticationStrategy implements AuthenticationStrategy<String> {
    private String adminPassword = "$$$$$$";
    private boolean adminDeleted = false;

    private Date expirationDate = new Date(System.currentTimeMillis() + (1000L * 60));

    public String authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication);
        UsernamePasswordAuthenticationToken credentials = UsernamePasswordAuthenticationToken.class.cast(authentication);
        if (credentials.getName().equalsIgnoreCase("admin") && credentials.getCredentials().equals(adminPassword)) {
            if (adminDeleted) {
                throw new DisabledException("Account Deleted");
            }

            if (DateUtils.isDatePast(expirationDate)) {
                throw new AccountExpiredException("Account is expired");
            }
            return "Admin";
        }
        throw new BadCredentialsException("Invalid Username/Password");
    }

    public User createUser(String username, String password) {
        adminDeleted = false;
        return new DefaultUser(username);
    }

    public void changePassword(String username, String newPassword) {
        adminPassword = newPassword;
    }

    public void deleteUser(String username) {
        adminDeleted = true;
    }

    public boolean userExists(String username) {
        return "admin".equalsIgnoreCase(username);
    }

    public void reset() {
        adminPassword = "$$$$$$";
        adminDeleted = false;
        expirationDate = new Date(System.currentTimeMillis() + (1000L * 60));
    }
}
