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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.User;

/**
 * Supplier which can provide a String representing the client-side connection
 * information.
 */
public class ClientInfoSupplier // implements Supplier<String>
{
    /** Default Last Host string if the Authenticated user is null.*/
    private static final String DEFAULT_LAST_HOST = "#UNKNOWN_HOST#";
    /** Session Attribute containing the ESAPI Session id. */
    private static final String ESAPI_SESSION_ATTR = "ESAPI_SESSION";
    /**
     * Minimum value for generating a random session value if one is not defined.
     */
    private static final int ESAPI_SESSION_RAND_MIN = 0;
    /**
     * Maximum value for generating a random session value if one is not defined.
     */
    private static final int ESAPI_SESSION_RAND_MAX = 1000000;

    /** Format for supplier output. */
    private static final String USER_INFO_FORMAT = "%s@%s"; // SID, USER_HOST_ADDRESS

    /** Whether to log the user info from this instance. */
    private boolean logClientInfo = true;

    // @Override    -- Uncomment when we switch to Java 8 as minimal baseline.
    public String get() {
        String clientInfo = "";

        if (logClientInfo) {
            HttpServletRequest request = ESAPI.currentRequest();
            // create a random session number for the user to represent the user's
            // 'session', if it doesn't exist already
            String sid = "";
            if (request != null) {
                HttpSession session = request.getSession(false);
                if (session != null) {
                    sid = (String) session.getAttribute(ESAPI_SESSION_ATTR);
                    // if there is no session ID for the user yet, we create one and store it in the
                    // user's session
                    if (sid == null) {
                        sid = "" + ESAPI.randomizer().getRandomInteger(ESAPI_SESSION_RAND_MIN, ESAPI_SESSION_RAND_MAX);
                        session.setAttribute(ESAPI_SESSION_ATTR, sid);
                    }
                }
            }
            // log user information - username:session@ipaddr
            User user = ESAPI.authenticator().getCurrentUser();
            if (user == null) {
                clientInfo = String.format(USER_INFO_FORMAT, sid, DEFAULT_LAST_HOST);
            } else {
                clientInfo = String.format(USER_INFO_FORMAT, sid, user.getLastHostAddress());
            }
        }
        return clientInfo;
    }

    /**
     * Specify whether the instance should record the client info.
     * 
     * @param log {@code true} to record
     */
    public void setLogClientInfo(boolean log) {
        this.logClientInfo = log;
    }

}
