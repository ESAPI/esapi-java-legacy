package org.owasp.esapi.contrib.spring.authenticator;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

/**
 * This interface is invoked after the user is authenticated and the user's details are loaded and is responsible for
 * retrieving the Roles/Authorities/Permissions of the logged in user.
 */
public interface AuthoritiesPopulator {
    List<GrantedAuthority> getAuthoritiesForUser(Authentication authentication);
}
