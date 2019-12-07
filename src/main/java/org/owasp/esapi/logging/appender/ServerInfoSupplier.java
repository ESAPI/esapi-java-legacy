package org.owasp.esapi.logging.appender;

import java.util.function.Supplier;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.ESAPI;

public class ServerInfoSupplier implements Supplier <String> {
	private boolean logServerIP = true;
	private boolean logAppName = true;
	private String applicationName = "";

	private final String logName;

	public ServerInfoSupplier(String logName) {
		this.logName = logName;
	}

	@Override
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
	
	public void setLogServerIp(boolean log) {
		this.logServerIP = log;
	}
	
	public void setLogApplicationName (boolean log, String appName) {
		this.logAppName = log;
		this.applicationName = appName;
	}
	
	

}
