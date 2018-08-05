package org.owasp.esapi.logging.slf4j;

import org.slf4j.Logger;
import org.slf4j.Marker;

public interface Slf4JLogHandler {
    boolean isEnabled(Logger logger);
    void log(Logger logger, Marker marker, String msg);
    void log(Logger logger, Marker marker, String msg, Throwable th);
}
