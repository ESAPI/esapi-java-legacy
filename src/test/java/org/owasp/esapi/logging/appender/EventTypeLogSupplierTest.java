package org.owasp.esapi.logging.appender;

import org.junit.Test;
import org.owasp.esapi.Logger;
import org.owasp.esapi.Logger.EventType;

public class EventTypeLogSupplierTest {

	@Test
	public void testEventTypeLog() {
		EventType eventType = Logger.EVENT_UNSPECIFIED;
		EventTypeLogSupplier supplier = new EventTypeLogSupplier(eventType);
		
		org.junit.Assert.assertEquals(eventType.toString(), supplier.get());
	}
}
