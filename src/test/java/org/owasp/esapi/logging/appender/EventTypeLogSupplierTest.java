package org.owasp.esapi.logging.appender;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.owasp.esapi.Logger;
import org.owasp.esapi.Logger.EventType;

@RunWith(Parameterized.class)
public class EventTypeLogSupplierTest {

    @Parameters (name="{0} -> {1}")
    public static Collection<Object[]> assembleTests() {
        List<Object[]> paramSets = new ArrayList<>();
        paramSets.add(new Object[] {Logger.EVENT_FAILURE,Logger.EVENT_FAILURE.toString()});
        paramSets.add(new Object[] {Logger.EVENT_SUCCESS,Logger.EVENT_SUCCESS.toString()});
        paramSets.add(new Object[] {Logger.EVENT_UNSPECIFIED,Logger.EVENT_UNSPECIFIED.toString()});
        paramSets.add(new Object[] {Logger.SECURITY_AUDIT,Logger.SECURITY_AUDIT.toString()});
        paramSets.add(new Object[] {Logger.SECURITY_FAILURE,Logger.SECURITY_FAILURE.toString()});
        paramSets.add(new Object[] {Logger.SECURITY_SUCCESS,Logger.SECURITY_SUCCESS.toString()});
        paramSets.add(new Object[] {null, Logger.EVENT_UNSPECIFIED.toString()});
        
        return paramSets;
    }
    
    private final EventType eventType;
    private final String expectedResult;
    
    public EventTypeLogSupplierTest(EventType eventType, String result) {
        this.eventType = eventType;
        this.expectedResult = result;
    }
	@Test
	public void testEventTypeLog() {
		EventTypeLogSupplier supplier = new EventTypeLogSupplier(eventType);
		assertEquals(expectedResult, supplier.get());
	}
	
}
