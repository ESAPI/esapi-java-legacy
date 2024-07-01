package org.owasp.esapi.logging.appender;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.owasp.esapi.Logger;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@RunWith(Parameterized.class)
public class EventTypeLogSupplierIgnoreEventTypeTest {

    @Parameterized.Parameters (name="{0} -> {1}")
    public static Collection<Object[]> assembleTests() {
        List<Object[]> paramSets = new ArrayList<>();
        paramSets.add(new Object[] {Logger.EVENT_FAILURE,""});
        paramSets.add(new Object[] {Logger.EVENT_SUCCESS,""});
        paramSets.add(new Object[] {Logger.EVENT_UNSPECIFIED,""});
        paramSets.add(new Object[] {Logger.SECURITY_AUDIT,""});
        paramSets.add(new Object[] {Logger.SECURITY_FAILURE,""});
        paramSets.add(new Object[] {Logger.SECURITY_SUCCESS,""});
        paramSets.add(new Object[] {null, ""});

        return paramSets;
    }

    private final Logger.EventType eventType;
    private final String expectedResult;

    public EventTypeLogSupplierIgnoreEventTypeTest(Logger.EventType eventType, String result) {
        this.eventType = eventType;
        this.expectedResult = result;
    }

    @Test
    public void testEventTypeLogIgnoreEventType() {
        EventTypeLogSupplier supplier = new EventTypeLogSupplier(eventType);
        supplier.setLogEventType(false);
        assertEquals(expectedResult, supplier.get());
    }
}
