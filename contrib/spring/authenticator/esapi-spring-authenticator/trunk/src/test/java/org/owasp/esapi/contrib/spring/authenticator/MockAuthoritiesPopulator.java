package org.owasp.esapi.contrib.spring.authenticator;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class MockAuthoritiesPopulator implements AuthoritiesPopulator {
    public List<GrantedAuthority> getAuthoritiesForUser(Authentication authentication) {
        List<GrantedAuthority> out = new ArrayList<GrantedAuthority>();
        GrantedAuthority test = new GrantedAuthorityImpl("test");
        out.add(test);
        return out;
    }
}
