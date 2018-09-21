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
 * @created 2018
 */

package org.owasp.esapi.logging.slf4j;

import org.slf4j.Logger;
import org.slf4j.Marker;
/**
 * Enumeration capturing the propagation of SLF4J level events.
 *
 */
public enum Slf4JLogLevelHandlers implements Slf4JLogLevelHandler {
    ERROR {
        @Override
        public boolean isEnabled(Logger logger) {
            return logger.isErrorEnabled();
        }

        @Override
        public void log(Logger logger, Marker marker, String msg) {
            logger.error(marker, msg);
        }

        @Override
        public void log(Logger logger, Marker marker, String msg, Throwable th) {
            logger.error(marker, msg, th);
        }
    },
    WARN {
        @Override
        public boolean isEnabled(Logger logger) {
            return logger.isWarnEnabled();
        }

        @Override
        public void log(Logger logger, Marker marker, String msg) {
            logger.warn(marker, msg);
        }

        @Override
        public void log(Logger logger, Marker marker, String msg, Throwable th) {
            logger.warn(marker, msg, th);
        }
    },
    INFO {
        @Override
        public boolean isEnabled(Logger logger) {
            return logger.isInfoEnabled();
        }

        @Override
        public void log(Logger logger, Marker marker, String msg) {
            logger.info(marker, msg);
        }

        @Override
        public void log(Logger logger, Marker marker, String msg, Throwable th) {
            logger.info(marker, msg, th);
        }
    },
    DEBUG {
        @Override
        public boolean isEnabled(Logger logger) {
            return logger.isDebugEnabled();
        }

        @Override
        public void log(Logger logger, Marker marker, String msg) {
            logger.debug(marker, msg);   
        }

        @Override
        public void log(Logger logger, Marker marker, String msg, Throwable th) {
            logger.debug(marker, msg, th);
        }
    },
    TRACE{

        @Override
        public boolean isEnabled(Logger logger) {
            return logger.isTraceEnabled();
        }

        @Override
        public void log(Logger logger, Marker marker, String msg) {
            logger.trace(marker, msg);
        }

        @Override
        public void log(Logger logger, Marker marker, String msg, Throwable th) {
            logger.trace(marker, msg, th);
        }

    };
    @Override
    public abstract boolean isEnabled(Logger logger);
    @Override
    public abstract void log(Logger logger, Marker marker, String msg);
    @Override
    public abstract void log(Logger logger, Marker marker, String msg, Throwable th);
}
