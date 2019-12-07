package org.owasp.esapi.logging.appender;

import org.owasp.esapi.Logger.EventType;

public class LogPrefixAppender implements LogAppender {
	private final String RESULT_FORMAT="[%s %s -> %s] %s";
	
	private final boolean logClientInfo;
	private final boolean logServerIp;
	private final boolean logApplicationName;
	private final String appName;
	
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
		
		return String.format(RESULT_FORMAT, eventTypeMsg, clientInfoMsg,serverInfoMsg, message);
	}
}
