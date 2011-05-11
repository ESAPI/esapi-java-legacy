package org.owasp.esapi.contrib.spring.authenticator;

import org.owasp.esapi.Authenticator;
import org.owasp.esapi.User;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.EncryptionException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.util.List;
import java.util.Set;
import java.util.TreeSet;

public class MockAuthenticator extends SpringSecurityAuthenticatorAdaptor<String> {
    private static Authenticator instance;

    public static Authenticator getInstance() {
        return instance;
    }

    @Override
    public Authentication getAuthentication(String user, UserDetails userDetails, List<GrantedAuthority> authorities) {
        Assert.isInstanceOf(AuthenticatedUser.class, userDetails);
        ((AuthenticatedUser) userDetails).setAuthorities(new TreeSet<GrantedAuthority>(authorities));
        UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(user, user, authorities);
        return result;
    }

    public String generateStrongPassword() {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public String generateStrongPassword(User user, String s) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public User getUser(long l) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public User getUser(String s) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public Set getUserNames() {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public String hashPassword(String s, String s1) throws EncryptionException {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public void verifyAccountNameStrength(String s) throws AuthenticationException {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public void verifyPasswordStrength(String s, String s1, User user) throws AuthenticationException {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public void afterPropertiesSet() throws Exception {
        instance = this;
    }
}
