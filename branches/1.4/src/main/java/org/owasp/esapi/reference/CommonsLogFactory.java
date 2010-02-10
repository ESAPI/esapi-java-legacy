package org.owasp.esapi.reference;

import java.util.HashMap;
import org.apache.commons.logging.Log;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.LogFactory;
import org.owasp.esapi.Logger;

public class CommonsLogFactory implements LogFactory {

	private String applicationName;

	private HashMap loggersMap = new HashMap();

	/**
	 * Sole constructor for Commons Logging-based implementation of
	 * ESAPI's <code>LogFactory</code> interface.
	 * 
	 * @param applicationName
	 */
	public CommonsLogFactory(String applicationName) {
		this.applicationName = applicationName;
	}



	/* (non-Javadoc)
	 * @see org.owasp.esapi.LogFactory#getLogger(java.lang.Class)
	 */
	public Logger getLogger(Class clazz) {

		// If a logger for this class already exists, we return the same one, otherwise we create a new one.

    	Logger classLogger = (Logger) loggersMap.get(clazz);

    	if (classLogger == null) {
    		classLogger = new CommonsLogger(applicationName, clazz.getName());
    		loggersMap.put(clazz, classLogger);
    	}

		return classLogger;
	}

	/* (non-Javadoc)
	 * @see org.owasp.esapi.LogFactory#getLogger(java.lang.String)
	 */

	public Logger getLogger(String moduleName) {

		// If a logger for this module already exists, we return the same one, otherwise we create a new one.
    	Logger moduleLogger = (Logger) loggersMap.get(moduleName);

    	if (moduleLogger == null) {
    		moduleLogger = new CommonsLogger(applicationName, moduleName);
    		loggersMap.put(moduleName, moduleLogger);    		
    	}

		return moduleLogger;
	}

	private static class CommonsLogger implements Logger {

		private Log commonsLog = null;

		/**
		 * Sole constructor for Aetna's Commons Logging-based implementation of
		 * ESAPI's <code>Logger</code> interface.
		 * 
		 * @param applicationName
		 * @param moduleName
		 */

		private CommonsLogger(String applicationName, String moduleName) {
            commonsLog = org.apache.commons.logging.LogFactory.getLog(applicationName + ":" + moduleName);
        }

		/* (non-Javadoc)
		 * @see org.owasp.esapi.Logger#setLevel(int)
		 */
		public void setLevel(int level) {
			throw new UnsupportedOperationException();
		}

		/* (non-Javadoc)
		 * @see org.owasp.esapi.Logger#isTraceEnabled()
		 */
		public boolean isTraceEnabled() {
			return commonsLog.isTraceEnabled();
		}

		/* (non-Javadoc)
		 * @see org.owasp.esapi.Logger#isDebugEnabled()
		 */
		public boolean isDebugEnabled() {
			return commonsLog.isDebugEnabled();
		}

		/* (non-Javadoc)
		 * @see org.owasp.esapi.Logger#isInfoEnabled()
		 */

		public boolean isInfoEnabled() {
			return commonsLog.isInfoEnabled();
		}

		/* (non-Javadoc)
		 * @see org.owasp.esapi.Logger#isWarningEnabled()
		 */
		public boolean isWarningEnabled() {
			return commonsLog.isWarnEnabled();
		}

		/* (non-Javadoc)
		 * @see org.owasp.esapi.Logger#isErrorEnabled()
		 */
		public boolean isErrorEnabled() {
			return commonsLog.isErrorEnabled();
		}

		/* (non-Javadoc)
		 * @see org.owasp.esapi.Logger#isFatalEnabled()
		 */
		public boolean isFatalEnabled() {
			return commonsLog.isFatalEnabled();
		}
		
        /* (non-Javadoc)
         * @see org.owasp.esapi.Logger#trace(org.owasp.esapi.Logger.EventType, boolean, java.lang.String, java.lang.Throwable)
         */
        public void trace(EventType type, boolean success, String message, Throwable throwable) {
            if (isTraceEnabled())
            	commonsLog.trace(cleanAndFormat(type, success, message), throwable);
        }

        /* (non-Javadoc)
         * @see org.owasp.esapi.Logger#trace(org.owasp.esapi.Logger.EventType, boolean, java.lang.String)
         */
        public void trace(EventType type, boolean success, String message) {
        	if (isTraceEnabled())
        		commonsLog.trace(cleanAndFormat(type, success, message));
        }

        /* (non-Javadoc)
         * @see org.owasp.esapi.Logger#debug(org.owasp.esapi.Logger.EventType, boolean, java.lang.String, java.lang.Throwable)
         */
        public void debug(EventType type, boolean success, String message, Throwable throwable) {
            if (isDebugEnabled())
            	commonsLog.debug(cleanAndFormat(type, success, message), throwable);
        }

        /* (non-Javadoc)
         * @see org.owasp.esapi.Logger#debug(org.owasp.esapi.Logger.EventType, boolean, java.lang.String)
         */
        public void debug(EventType type, boolean success, String message) {
        	if (isDebugEnabled())
        		commonsLog.debug(cleanAndFormat(type, success, message));
        }

        /* (non-Javadoc)
         * @see org.owasp.esapi.Logger#info(org.owasp.esapi.Logger.EventType, boolean, java.lang.String, java.lang.Throwable)
         */
        public void info(EventType type, boolean success, String message, Throwable throwable) {
        	if (isInfoEnabled())
        		commonsLog.info(cleanAndFormat(type, success, message), throwable);
        }

        /* (non-Javadoc)
         * @see org.owasp.esapi.Logger#info(org.owasp.esapi.Logger.EventType, boolean, java.lang.String)
         */
        public void info(EventType type, boolean success, String message) {
            if (isInfoEnabled())
            	commonsLog.info(cleanAndFormat(type, success, message));
        }

        /* (non-Javadoc)
         * @see org.owasp.esapi.Logger#warning(org.owasp.esapi.Logger.EventType, boolean, java.lang.String, java.lang.Throwable)
         */
        public void warning(EventType type, boolean success, String message, Throwable throwable) {
            if (isWarningEnabled())
            	commonsLog.warn(cleanAndFormat(type, success, message), throwable);
        }

        /* (non-Javadoc)
         * @see org.owasp.esapi.Logger#warning(org.owasp.esapi.Logger.EventType, boolean, java.lang.String)
         */
        public void warning(EventType type, boolean success, String message) {
        	if (isWarningEnabled())
        		commonsLog.warn(cleanAndFormat(type, success, message));
        }

        /* (non-Javadoc)
         * @see org.owasp.esapi.Logger#error(org.owasp.esapi.Logger.EventType, boolean, java.lang.String, java.lang.Throwable)
         */
        public void error(EventType type, boolean success, String message, Throwable throwable) {
        	if (isErrorEnabled())
        		commonsLog.error(cleanAndFormat(type, success, message), throwable);
        }
        
        /* (non-Javadoc)
         * @see org.owasp.esapi.Logger#error(org.owasp.esapi.Logger.EventType, boolean, java.lang.String)
         */
        public void error(EventType type, boolean success, String message) {
        	if (isErrorEnabled())
        		commonsLog.error(cleanAndFormat(type, success, message));
        }

        /* (non-Javadoc)
         * @see org.owasp.esapi.Logger#fatal(org.owasp.esapi.Logger.EventType, boolean, java.lang.String, java.lang.Throwable)
         */
        public void fatal(EventType type, boolean success, String message, Throwable throwable) {
            if (isFatalEnabled())
            	commonsLog.fatal(cleanAndFormat(type, success, message), throwable);
        }
        
        /* (non-Javadoc)
         * @see org.owasp.esapi.Logger#fatal(org.owasp.esapi.Logger.EventType, boolean, java.lang.String)
         */
        public void fatal(EventType type, boolean success, String message) {
        	if (isFatalEnabled())
        		commonsLog.fatal(cleanAndFormat(type, success, message));
        }
        
       
        private String cleanAndFormat(EventType type, boolean success, String message) {
        	// Ensure there's something to log.
            if (message == null) message = "";
            // Ensure no CRLF injection into logs for forging records.
            String clean = message.replace('\n', '_').replace('\r', '_');
            if ((ESAPI.securityConfiguration()).getLogEncodingRequired()) {
            	clean = ESAPI.encoder().encodeForHTML(message);
                if (!message.equals(clean)) clean += " (Encoded)";
            }
            // Create the message to log
            return new StringBuffer(type.toString()).append("-").append(success ? "SUCCESS" : "FAILURE").append(" -- ").append(clean).toString();
        }
	}
}