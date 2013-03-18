package org.owasp.esapi.contrib.spring.authenticator;

import java.util.Date;

public interface UserProfile {
    void setEnabled(boolean enabled);

    long getId();

    String getAccountName();

    Date getExpirationDate();

    int getFailedLoginCount();

    String getLastHostAddress();

    Date getLastFailedLoginTime();

    Date getLastLoginTime();

    Date getLastPasswordChangeTime();

    String getScreenName();

    void setFailedLoginCount(int count);

    String getPassword();

    boolean isEnabled();

    boolean isLocked();

    boolean isLoggedIn();

    void setLocked(boolean b);

    void setAccountName(String accountName);

    void setExpirationDate(Date expirationTime);

    void setScreenName(String screenName);

    void setLastFailedLoginTime(Date lastFailedLoginTime);

    void setLastHostAddress(String remoteHost);

    void setLastLoginTime(Date lastLoginTime);

    void setLastPasswordChangeTime(Date lastPasswordChangeTime);

    String getFirstName();

    String getLastName();

    boolean isSuperUser();
}
