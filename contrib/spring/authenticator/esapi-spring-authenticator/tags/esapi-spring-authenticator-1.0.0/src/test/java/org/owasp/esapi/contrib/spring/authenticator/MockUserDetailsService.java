package org.owasp.esapi.contrib.spring.authenticator;

import org.springframework.dao.DataAccessException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class MockUserDetailsService implements UserDetailsService {
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException, DataAccessException {
        return new AuthenticatedUser(new UserProfile() {
            public void setEnabled(boolean enabled) {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            public long getId() {
                return 0;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public String getAccountName() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public Date getExpirationDate() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public int getFailedLoginCount() {
                return 0;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public String getLastHostAddress() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public Date getLastFailedLoginTime() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public Date getLastLoginTime() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public Date getLastPasswordChangeTime() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public String getScreenName() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public void setFailedLoginCount(int count) {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            public String getPassword() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public boolean isEnabled() {
                return false;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public boolean isLocked() {
                return false;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public boolean isLoggedIn() {
                return false;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public void setLocked(boolean b) {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            public void setAccountName(String accountName) {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            public void setExpirationDate(Date expirationTime) {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            public void setScreenName(String screenName) {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            public void setLastFailedLoginTime(Date lastFailedLoginTime) {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            public void setLastHostAddress(String remoteHost) {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            public void setLastLoginTime(Date lastLoginTime) {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            public void setLastPasswordChangeTime(Date lastPasswordChangeTime) {
                //To change body of implemented methods use File | Settings | File Templates.
            }

            public String getFirstName() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public String getLastName() {
                return null;  //To change body of implemented methods use File | Settings | File Templates.
            }

            public boolean isSuperUser() {
                return false;  //To change body of implemented methods use File | Settings | File Templates.
            }
        });
    }
}
