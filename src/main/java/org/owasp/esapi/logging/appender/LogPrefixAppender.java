package org.owasp.esapi.logging.appender;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger.EventType;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;

public class LogPrefixAppender implements LogAppender {
	private final String RESULT_FORMAT="[%s %s -> %s] %s";
	
	@Override
	public String appendTo(String logName, EventType eventType, String message) {
		boolean logClientInfo = true;
		boolean logApplicationName = ESAPI.securityConfiguration().getBooleanProp(DefaultSecurityConfiguration.LOG_APPLICATION_NAME);
		String appName = ESAPI.securityConfiguration().getStringProp(DefaultSecurityConfiguration.APPLICATION_NAME);
		boolean logServerIp = ESAPI.securityConfiguration().getBooleanProp(DefaultSecurityConfiguration.LOG_SERVER_IP);
		
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
