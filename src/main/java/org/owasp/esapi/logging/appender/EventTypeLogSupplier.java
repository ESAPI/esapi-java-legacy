package org.owasp.esapi.logging.appender;

import java.util.function.Supplier;

import org.owasp.esapi.Logger.EventType;

/**
 * Supplier implementation which returns a consistent String representation of
 * an EventType for logging
 *
 */
public class EventTypeLogSupplier implements Supplier<String> {
	/** EventType reference to supply log representation of. */
	private final EventType eventType;

	/**
	 * Ctr
	 * 
	 * @param evtyp EventType reference to supply log representation for
	 */
	public EventTypeLogSupplier(EventType evtyp) {
		this.eventType = evtyp;
	}

	@Override
	public String get() {
		return eventType.toString();
	}
}
