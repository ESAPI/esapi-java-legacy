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
 * @created 2019
 */

package org.owasp.esapi.logging.appender;

// Uncomment and use once ESAPI supports Java 8 as the minimal baseline.
// import java.util.function.Supplier;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.User;

/**
 * Supplier which can provide a String representing the client-side connection
 * information.
 */
public class UserInfoSupplier   // implements Supplier<String>
{
    /** Default UserName string if the Authenticated user is null.*/
    private static final String DEFAULT_USERNAME = "#ANONYMOUS#";
    
    /** Whether to log the user info from this instance. */
    private boolean logUserInfo = true;
    
    // @Override    -- Uncomment when we switch to Java 8 as minimal baseline.
    public String get() {
        // log user information - username:session@ipaddr
        User user = ESAPI.authenticator().getCurrentUser();
        
        String userInfo = "";
        if (logUserInfo) {
            if (user == null) {
                userInfo = DEFAULT_USERNAME;
            } else {
                userInfo = user.getAccountName();            
            }
        } 
        
        return userInfo;
    }

    /**
     * Specify whether the instance should record the client info.
     * 
     * @param log {@code true} to record
     */
    public void setLogUserInfo(boolean log) {
        this.logUserInfo = log;
    }
}
