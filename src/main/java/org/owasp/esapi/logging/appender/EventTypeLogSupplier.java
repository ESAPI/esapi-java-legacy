/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @created 2019
 */

package org.owasp.esapi.logging.appender;

import java.util.function.Supplier;

import org.owasp.esapi.Logger;
import org.owasp.esapi.Logger.EventType;

/**
 * Supplier implementation which returns a consistent String representation of
 * an EventType for logging
 *
 */
public class EventTypeLogSupplier implements Supplier<String>
{
    /** EventType reference to supply log representation of. */
    private final EventType eventType;
    /** Whether to log or not the event type */
    private boolean logEventType = true;

    /**
     * Ctr
     *
     * @param eventType EventType reference to supply log representation for
     */
    public EventTypeLogSupplier(EventType eventType) {
        this.eventType = eventType == null ? Logger.EVENT_UNSPECIFIED : eventType;
    }

    // @Override    -- Uncomment when we switch to Java 8 as minimal baseline.
    public String get() {
        return logEventType ? eventType.toString() : "";
    }

    public void setLogEventType(boolean logEventType) {
        this.logEventType = logEventType;
    }
}
