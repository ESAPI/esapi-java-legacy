/**
 * 
 */
package org.owasp.esapi.reference;

import java.util.logging.Level;

import javax.servlet.http.HttpSession;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.LogFactory;
import org.owasp.esapi.Logger;
import org.owasp.esapi.User;

/**
 * Reference implementation of the LogFactory and Logger interfaces. This implementation uses the Java logging package, and marks each
 * log message with the currently logged in user and the word "SECURITY" for security related events.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.LogFactory
 */
public class JavaLogFactory implements LogFactory {

	private String applicationName;
	
	public JavaLogFactory(String applicationName) {
		this.applicationName = applicationName;
	}
	
	/* (non-Javadoc)
     * @see org.owasp.esapi.LogFactory#getLogger(java.lang.Class)
     */
    public Logger getLogger(Class clazz) {
	    return new JavaLogger(applicationName, clazz.getName());
    }

	/* (non-Javadoc)
     * @see org.owasp.esapi.LogFactory#getLogger(java.lang.String)
     */
    public Logger getLogger(String name) {
    	return new JavaLogger(applicationName, name);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.Logger
     */
    private static class JavaLogger implements org.owasp.esapi.Logger {

    	/** The jlogger object used by this class to log everything. */
        private java.util.logging.Logger jlogger = null;

        /** The application name. */
        private String applicationName = null;

        /** The module name. */
        private String moduleName = null;

        /* A custom logging level defined between Level.SEVERE and Level.WARNING in logger. */
        private static class JavaLoggerLevel extends Level {

        	public static final Level ERROR_LEVEL = new JavaLoggerLevel( "ERROR", Level.SEVERE.intValue() - 1);
        	
			protected JavaLoggerLevel(String name, int value) {
				super(name, value);
			}
        }
        
        /**
         * Public constructor should only ever be called via the appropriate LogFactory
         * 
         * @param applicationName the application name
         * @param moduleName the module name
         */
        public JavaLogger(String applicationName, String moduleName) {
            this.applicationName = applicationName;
            this.moduleName = moduleName;
            this.jlogger = java.util.logging.Logger.getLogger(applicationName + ":" + moduleName);
            // Beware getting info from SecurityConfiguration, since it logs.
            this.jlogger.setLevel( Level.WARNING );  // The default level for this logger is .WARNING
        }

        /**
         * Dynamically set the logging severity level. All events of this level and higher will be logged from this point forward. 
         * All events below this level will be discarded.
         */
        public void setLevel(int level)
        {
        	switch (level) {
        		case Logger.OFF:     this.jlogger.setLevel( Level.OFF ); break;
        		case Logger.FATAL:   this.jlogger.setLevel( Level.SEVERE ); break;
        		case Logger.ERROR:   this.jlogger.setLevel( JavaLoggerLevel.ERROR_LEVEL ); break; // This is a custom level.
        		case Logger.WARNING: this.jlogger.setLevel( Level.WARNING ); break;
        		case Logger.INFO:    this.jlogger.setLevel( Level.INFO ); break;
        		case Logger.DEBUG:   this.jlogger.setLevel( Level.FINE ); break;
        		case Logger.TRACE:   this.jlogger.setLevel( Level.FINEST ); break;
        		case Logger.ALL:     this.jlogger.setLevel( Level.ALL ); break;
        		default: this.error(Logger.SECURITY, false, "Invalid logging level sent to JavaLogger.setLevel. Value was: " + level);
        	}
        }
        
        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.Logger#trace(EventType, boolean, String, java.lang.Throwable)
         */
        public void trace(EventType type, boolean success, String message, Throwable throwable) {
            log(Level.FINEST, type, success, message, throwable);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.Logger#trace(EventType, boolean, java.lang.String)
         */
        public void trace(EventType type, boolean success, String message) {
            log(Level.FINEST, type, success, message, null);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.Logger#debug(EventType, boolean, java.lang.String, java.lang.Throwable)
         */
        public void debug(EventType type, boolean success, String message, Throwable throwable) {
            log(Level.FINE, type, success, message, throwable);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.Logger#debug(EventType, boolean, java.lang.String)
         */
        public void debug(EventType type, boolean success, String message) {
            log(Level.FINE, type, success, message, null);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.Logger#info(EventType, boolean, java.lang.String,
         * java.lang.Throwable)
         */
        public void info(EventType type, boolean success, String message) {
            log(Level.INFO, type, success, message, null);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.Logger#info(EventType, boolean, java.lang.String,
         * java.lang.Throwable)
         */
        public void info(EventType type, boolean success, String message, Throwable throwable) {
            log(Level.INFO, type, success, message, throwable);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.Logger#warning(EventType, boolean, java.lang.String,
         * java.lang.Throwable)
         */
        public void warning(EventType type, boolean success, String message, Throwable throwable) {
            log(Level.WARNING, type, success, message, throwable);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.Logger#warning(EventType, boolean, java.lang.String)
         */
        public void warning(EventType type, boolean success, String message) {
            log(Level.WARNING, type, success, message, null);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.Logger#error(EventType, boolean, java.lang.String, java.lang.Throwable)
         */
        public void error(EventType type, boolean success, String message, Throwable throwable) {
            log(Level.SEVERE, type, success, message, throwable);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.Logger#error(EventType, boolean, java.lang.String)
         */
        public void error(EventType type, boolean success, String message) {
            log(Level.SEVERE, type, success, message, null);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.Logger#fatal(EventType, boolean, java.lang.String,
         * java.lang.Throwable)
         */
        public void fatal(EventType type, boolean success, String message, Throwable throwable) {
            log(Level.SEVERE, type, success, message, throwable);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.Logger#fatal(EventType, boolean, java.lang.String)
         */
        public void fatal(EventType type, boolean success, String message) {
            log(Level.SEVERE, type, success, message, null);
        }

        /**
         * Log the message after optionally encoding any special characters that might inject 
         * into an HTML based log viewer.
         * 
         * @param level the severity level of the security event
         * @param type the type of the event (SECURITY, FUNCTIONALITY, etc.)
         * @param success whether this was a failed or successful event
         * @param message the message
         * @param throwable the throwable
         */
        private void log(Level level, EventType type, boolean success, String message, Throwable throwable) {
            User user = ESAPI.authenticator().getCurrentUser();
            
            // create a random session number for the user to represent the user's 'session', if it doesn't exist already
            String userSessionIDforLogging = "unknown";
            try {
                HttpSession session = ESAPI.httpUtilities().getCurrentRequest().getSession();
                userSessionIDforLogging = (String)session.getAttribute("ESAPI_SESSION");
                // if there is no session ID for the user yet, we create one and store it in the user's session
	            if ( userSessionIDforLogging == null ) {
	            	userSessionIDforLogging = ""+ ESAPI.randomizer().getRandomInteger(0, 1000000);
	            	session.setAttribute("ESAPI_SESSION", userSessionIDforLogging);
	            }
            } catch( NullPointerException e ) {
            	// continue
            }
            
            // ensure there's something to log
            if ( message == null ) {
            	message = "";
            }
            
            // ensure no CRLF injection into logs for forging records
            String clean = message.replace( '\n', '_' ).replace( '\r', '_' );
            if ( ((DefaultSecurityConfiguration)ESAPI.securityConfiguration()).getLogEncodingRequired() ) {
            	clean = ESAPI.encoder().encodeForHTML(message);
                if (!message.equals(clean)) {
                    clean += " (Encoded)";
                }
            }
            
            // convert the stack trace into something that can be logged
            if ( throwable != null ) {
            	String fqn = throwable.getClass().getName();
            	int index = fqn.lastIndexOf('.');
            	if ( index > 0 ) fqn = fqn.substring(index + 1);
            	StackTraceElement ste = throwable.getStackTrace()[0];
            	clean += "\n    " + fqn + " @ " + ste.getClassName() + "." + ste.getMethodName() + "(" + ste.getFileName() 
            		+ ":" + ste.getLineNumber() + ")";
            }
            
            // create the message to log
            String msg = "";
            if ( user != null ) {
            	msg = type + "-" + (success ? "SUCCESS: " : "FAILURE: ") + user.getAccountName() + "("+ userSessionIDforLogging +")(" + user.getLastHostAddress() 
            	+ ") -- " + clean;
            }
            
            jlogger.logp(level, applicationName, moduleName, msg);
        }

    	/* (non-Javadoc)
         * @see org.owasp.esapi.Logger#isDebugEnabled()
         */
        public boolean isDebugEnabled() {
    	    return jlogger.isLoggable(Level.FINE);
        }

    	/* (non-Javadoc)
         * @see org.owasp.esapi.Logger#isErrorEnabled()
         */
        public boolean isErrorEnabled() {
    	    return jlogger.isLoggable(JavaLoggerLevel.ERROR_LEVEL);
        }

    	/* (non-Javadoc)
         * @see org.owasp.esapi.Logger#isFatalEnabled()
         */
        public boolean isFatalEnabled() {
    	    return jlogger.isLoggable(Level.SEVERE);
        }

    	/* (non-Javadoc)
         * @see org.owasp.esapi.Logger#isInfoEnabled()
         */
        public boolean isInfoEnabled() {
    	    return jlogger.isLoggable(Level.INFO);
        }

    	/* (non-Javadoc)
         * @see org.owasp.esapi.Logger#isTraceEnabled()
         */
        public boolean isTraceEnabled() {
    	    return jlogger.isLoggable(Level.FINEST);
        }

    	/* (non-Javadoc)
         * @see org.owasp.esapi.Logger#isWarningEnabled()
         */
        public boolean isWarningEnabled() {
    	    return jlogger.isLoggable(Level.WARNING);
        }

    }
}
