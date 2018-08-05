package org.owasp.esapi.logging.slf4j;

import org.owasp.esapi.Logger.EventType;
import org.slf4j.Logger;

public interface Slf4JLogBridge {
    void log(Logger logger, int esapiLevel, EventType type, String message) ;
    void log(Logger logger, int esapiLevel, EventType type, String message, Throwable throwable) ;
      
}
