package org.owasp.esapi.logging.appender;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.owasp.esapi.Logger;
import org.owasp.esapi.Logger.EventType;

public class EventTypeLogSupplierTest {

	@Test
	public void testEventTypeLog() {
		EventType eventType = Logger.EVENT_UNSPECIFIED;
		EventTypeLogSupplier supplier = new EventTypeLogSupplier(eventType);
		
		assertEquals(eventType.toString(), supplier.get());
	}
}
