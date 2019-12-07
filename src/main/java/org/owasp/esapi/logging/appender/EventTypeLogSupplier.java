package org.owasp.esapi.logging.appender;

import java.util.function.Supplier;

import org.owasp.esapi.Logger.EventType;

public class EventTypeLogSupplier implements Supplier<String> {

	private final EventType eventType;
	
	public EventTypeLogSupplier(EventType evtyp) {
		this.eventType = evtyp;
	}

	@Override
	public String get() {
		return eventType.toString();
	}

}
