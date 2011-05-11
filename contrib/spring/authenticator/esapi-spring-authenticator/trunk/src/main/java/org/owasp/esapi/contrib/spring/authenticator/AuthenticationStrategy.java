package org.owasp.esapi.contrib.spring.authenticator;

import org.owasp.esapi.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * This interface defines the actual Authentication itself. Implementations of this interface are responsible for
 * authenticating the provided credentials
 *
 * @param <T>
 */
public interface AuthenticationStrategy<T> {
    T authenticate(Authentication authentication) throws AuthenticationException;

    User createUser(String username, String password);

    void changePassword(String username, String newPassword);

    void deleteUser(String username);

    boolean userExists(String username);
}
