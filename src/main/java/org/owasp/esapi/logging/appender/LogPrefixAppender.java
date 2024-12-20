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

import org.owasp.esapi.Logger.EventType;

/**
 * LogAppender Implementation which can prefix the common logger information for
 * EventType, Client data, and server data.
 */
public class LogPrefixAppender implements LogAppender {
    /** Output format used to assemble return values. */
    private static final String RESULT_FORMAT = "[%s] %s"; //Assembled Prefix, MSG

    /** Whether or not to record user information. */
    private final boolean logUserInfo;
    /** Whether or not to record client information. */
    private final boolean logClientInfo;
    /** Whether or not to record server ip information. */
    private final boolean logServerIp;
    /** Whether or not to record application name. */
    private final boolean logApplicationName;
    /** Application Name to record. */
    private final String appName;
    /** Whether or not to print the prefix. */
    private final boolean logPrefix;

    /**
     * Constructor
     *
     * @param logUserInfo      Whether or not to record user information
     * @param logClientInfo      Whether or not to record client information
     * @param logServerIp        Whether or not to record server ip information
     * @param logApplicationName Whether or not to record application name
     * @param appName            Application Name to record.
     */
    @SuppressWarnings("JavadocReference")
    public LogPrefixAppender(boolean logUserInfo, boolean logClientInfo, boolean logServerIp, boolean logApplicationName, String appName) {
        this(logUserInfo, logClientInfo, logServerIp, logApplicationName, appName, true);
    }

    /**
     * Constructor
     *
     * @param logUserInfo        Whether or not to record user information
     * @param logClientInfo      Whether or not to record client information
     * @param logServerIp        Whether or not to record server ip information
     * @param logApplicationName Whether or not to record application name
     * @param appName            Application Name to record.
     * @param logPrefix          Whether or not to print the prefix
     */
    public LogPrefixAppender(boolean logUserInfo, boolean logClientInfo, boolean logServerIp, boolean logApplicationName, String appName, boolean logPrefix) {
        this.logUserInfo = logUserInfo;
        this.logClientInfo = logClientInfo;
        this.logServerIp = logServerIp;
        this.logApplicationName = logApplicationName;
        this.appName = appName;
        this.logPrefix = logPrefix;
    }

    @Override
    public String appendTo(String logName, EventType eventType, String message) {
        EventTypeLogSupplier eventTypeSupplier = new EventTypeLogSupplier(eventType);
        eventTypeSupplier.setLogEventType(this.logPrefix);

        UserInfoSupplier userInfoSupplier = new UserInfoSupplier();
        userInfoSupplier.setLogUserInfo(logUserInfo);

        ClientInfoSupplier clientInfoSupplier = new ClientInfoSupplier();
        clientInfoSupplier.setLogClientInfo(logClientInfo);

        ServerInfoSupplier serverInfoSupplier = new ServerInfoSupplier(logName);
        serverInfoSupplier.setLogServerIp(logServerIp);
        serverInfoSupplier.setLogApplicationName(logApplicationName, appName);
        serverInfoSupplier.setLogLogName(logPrefix);

        String eventTypeMsg = eventTypeSupplier.get().trim();
        String userInfoMsg = userInfoSupplier.get().trim();
        String clientInfoMsg = clientInfoSupplier.get().trim();
        String serverInfoMsg = serverInfoSupplier.get().trim();

        //If both user and client have content, then postfix the semicolon to the userInfoMsg at this point to simplify the StringBuilder operations later.
        userInfoMsg = (!userInfoMsg.isEmpty() && !clientInfoMsg.isEmpty()) ? userInfoMsg + ":" : userInfoMsg;

        //If both server has content, then prefix the arrow to the serverInfoMsg at this point to simplify the StringBuilder operations later.
        serverInfoMsg = (!serverInfoMsg.isEmpty()) ? "-> " + serverInfoMsg: serverInfoMsg;

        String[] optionalPrefixContent = new String[] {userInfoMsg + clientInfoMsg, serverInfoMsg};

        StringBuilder logPrefixBuilder = new StringBuilder();
        //EventType is always appended (unless we specifically asked not to Log Prefix)
        if (this.logPrefix) {
            logPrefixBuilder.append(eventTypeMsg);
        }

        for (String element : optionalPrefixContent) {
            if (!element.isEmpty()) {
                logPrefixBuilder.append(" ");
                logPrefixBuilder.append(element);
            }
        }

        String logPrefixContent = logPrefixBuilder.toString();
        return logPrefixContent.trim().isEmpty() ? message : String.format(RESULT_FORMAT, logPrefixContent, message);
    }
}
