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

import org.owasp.esapi.ESAPI;

/**
 * Supplier which can provide a String representing the server-side connection
 * information.
 */
public class ServerInfoSupplier     // implements Supplier<String>
{
    /** Whether to log the server connection info. */
    private boolean logServerIP = true;
    /** Whether to log the application name. */
    private boolean logAppName = true;
    /** The application name to log. */
    private String applicationName = "";

    /** Reference to the associated logname/module name. */
    private final String logName;

    /**
     * Ctr.
     * 
     * @param logName Reference to the logName to record as the module information
     */
    public ServerInfoSupplier(String logName) {
        this.logName = logName;
    }

    // @Override    -- Uncomment when we switch to Java 8 as minimal baseline.
    public String get() {
        // log server, port, app name, module name -- server:80/app/module
        StringBuilder appInfo = new StringBuilder();
        HttpServletRequest request = ESAPI.currentRequest();
        if (request != null && logServerIP) {
            appInfo.append(request.getLocalAddr()).append(":").append(request.getLocalPort());
        }
        if (logAppName) {
            appInfo.append("/").append(applicationName);
        }
        appInfo.append("/").append(logName);

        return appInfo.toString();
    }

    /**
     * Specify whether the instance should record the server connection info.
     * 
     * @param log {@code true} to record
     */
    public void setLogServerIp(boolean log) {
        this.logServerIP = log;
    }

    /**
     * Specify whether the instance should record the application name
     * 
     * @param log     {@code true} to record
     * @param appName String to record as the application name
     */
    public void setLogApplicationName(boolean log, String appName) {
        this.logAppName = log;
        this.applicationName = appName;
    }
}
