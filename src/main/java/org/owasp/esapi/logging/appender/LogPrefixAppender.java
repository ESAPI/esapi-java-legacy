package org.owasp.esapi.logging.appender;

import org.owasp.esapi.Logger.EventType;

/**
 * LogAppender Implementation which can prefix the common logger information for
 * EventType, Client data, and server data.
 */
public class LogPrefixAppender implements LogAppender {
	/** Output format used to assemble return values. */
	private static final String RESULT_FORMAT = "[%s %s -> %s] %s";// EVENT_TYPE, CLIENT_INFO, SERVER_INFO, messageBody

	/** Whether or not to record client information. */
	private final boolean logClientInfo;
	/** Whether or not to record server ip information. */
	private final boolean logServerIp;
	/** Whether or not to record application name. */
	private final boolean logApplicationName;
	/** Application Name to record. */
	private final String appName;

	/**
	 * Ctr.
	 * 
	 * @param logClientInfo      Whether or not to record client information
	 * @param logServerIp        Whether or not to record server ip information
	 * @param logApplicationName Whether or not to record application name
	 * @param appName            Application Name to record.
	 */
	public LogPrefixAppender(boolean logClientInfo, boolean logServerIp, boolean logApplicationName, String appName) {
		this.logClientInfo = logClientInfo;
		this.logServerIp = logServerIp;
		this.logApplicationName = logApplicationName;
		this.appName = appName;
	}

	@Override
	public String appendTo(String logName, EventType eventType, String message) {
		EventTypeLogSupplier eventTypeSupplier = new EventTypeLogSupplier(eventType);

		ClientInfoSupplier clientInfoSupplier = new ClientInfoSupplier();
		clientInfoSupplier.setLogUserInfo(logClientInfo);

		ServerInfoSupplier serverInfoSupplier = new ServerInfoSupplier(logName);
		serverInfoSupplier.setLogServerIp(logServerIp);
		serverInfoSupplier.setLogApplicationName(logApplicationName, appName);

		String eventTypeMsg = eventTypeSupplier.get();
		String clientInfoMsg = clientInfoSupplier.get();
		String serverInfoMsg = serverInfoSupplier.get();

		return String.format(RESULT_FORMAT, eventTypeMsg, clientInfoMsg, serverInfoMsg, message);
	}
}
