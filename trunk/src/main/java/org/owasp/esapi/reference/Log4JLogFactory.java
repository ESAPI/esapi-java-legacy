package org.owasp.esapi.reference;

import java.util.HashMap;
import org.apache.log4j.Level;

import javax.servlet.http.HttpSession;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.LogFactory;
import org.owasp.esapi.Logger;
import org.owasp.esapi.User;

/**
 * Reference implementation of the LogFactory and Logger interfaces. This implementation uses the Apache Log4J package, and marks each
 * log message with the currently logged in user and the word "SECURITY" for security related events. See the 
 * <a href="JavaLogFactory.JavaLogger.html">JavaLogFactory.JavaLogger</a> Javadocs for the details on the JavaLogger reference implementation.
 * 
 * @author Mike H. Fauzy (mike.fauzy@aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Jim Manico (jim.manico .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.LogFactory
 * @see org.owasp.esapi.reference.Log4JLogFactory.Log4JLogger
 */
public class Log4JLogFactory implements LogFactory {

	private String applicationName;
	
	@SuppressWarnings("unchecked")
	private HashMap loggersMap = new HashMap();
	
	/**
	* Null argument constructor for this implementation of the LogFactory interface
	* needed for dynamic configuration.
	*/
	public Log4JLogFactory() {}
	
	/**
	* Constructor for this implementation of the LogFactory interface.
	* 
	* @param applicationName The name of this application this logger is being constructed for.
	*/
	public Log4JLogFactory(String applicationName) { 
		this.applicationName = applicationName;
	}
	
	/**
	* {@inheritDoc}
	*/
	public void setApplicationName(String newApplicationName) {
		applicationName = newApplicationName;
	}
	
	/**
	* {@inheritDoc}
	*/
    @SuppressWarnings("unchecked")
	public Logger getLogger(Class clazz) {
    	
    	// If a logger for this class already exists, we return the same one, otherwise we create a new one.
    	Logger classLogger = (Logger) loggersMap.get(clazz);
    	
    	if (classLogger == null) {
    		classLogger = new Log4JLogger(applicationName, clazz.getName());
    		loggersMap.put(clazz, classLogger);
    	}
		return classLogger;
    }

    /**
	* {@inheritDoc}
	*/
    @SuppressWarnings("unchecked")
	public Logger getLogger(String moduleName) {
    	
    	// If a logger for this module already exists, we return the same one, otherwise we create a new one.
    	Logger moduleLogger = (Logger) loggersMap.get(moduleName);
    	
    	if (moduleLogger == null) {
    		moduleLogger = new Log4JLogger(applicationName, moduleName);
    		loggersMap.put(moduleName, moduleLogger);    		
    	}
		return moduleLogger;
    }
        
    /**
     * Reference implementation of the Logger interface.
     * 
     * It implements most of the recommendations defined in the Logger interface description. It does not
     * filter out any sensitive data specific to the current application or organization, such as credit 
     * cards, social security numbers, etc.  
     * 
     * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
     * @since June 1, 2007
     * @see org.owasp.esapi.LogFactory
     */
    private static class Log4JLogger implements org.owasp.esapi.Logger {

    	/** The jlogger object used by this class to log everything. */
        private org.apache.log4j.Logger jlogger = null;

        /** The application name using this log. */
        private String applicationName = null;

        /** The module name using this log. */
        private String moduleName = null;
        
        /**
         * Public constructor should only ever be called via the appropriate LogFactory
         * 
         * @param applicationName the application name
         * @param moduleName the module name
         */
        private Log4JLogger(String applicationName, String moduleName) {
            this.applicationName = applicationName;
            this.moduleName = moduleName;
            this.jlogger = org.apache.log4j.Logger.getLogger(applicationName + ":" + moduleName);
        }

        /**
         * {@inheritDoc}
         * Note: In this implementation, this change is not persistent,
         * meaning that if the application is restarted, the log level will revert to the level defined in the 
         * ESAPI SecurityConfiguration properties file.
         */
        public void setLevel(int level)
        {
        	try {
        		jlogger.setLevel(convertESAPILeveltoLoggerLevel( level ));
        	}
        	catch (IllegalArgumentException e) {
       			this.error(Logger.SECURITY_FAILURE, "", e);    		
        	}
         }
        
        /**
         * Converts the ESAPI logging level (a number) into the levels used by Java's logger.
         * @param level The ESAPI to convert.
         * @return The Log4J logging Level that is equivalent.
         * @throws IllegalArgumentException if the supplied ESAPI level doesn't make a level that is currently defined.
         */
        private static Level convertESAPILeveltoLoggerLevel(int level)
        {
        	switch (level) {
        		case Logger.OFF:     return Level.OFF;
        		case Logger.FATAL:   return Level.FATAL;
        		case Logger.ERROR:   return Level.ERROR;
        		case Logger.WARNING: return Level.WARN;
        		case Logger.INFO:    return Level.INFO;
        		case Logger.DEBUG:   return Level.DEBUG; //fine
        		case Logger.TRACE:   return Level.TRACE; //finest
        		case Logger.ALL:     return Level.ALL;       		
        		default: {
        			throw new IllegalArgumentException("Invalid logging level. Value was: " + level);
        		}
        	}
        }

        /**
    	* {@inheritDoc}
    	*/
        public void trace(EventType type, String message, Throwable throwable) {
            log(Level.TRACE, type, message, throwable);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void trace(EventType type, String message) {
            log(Level.TRACE, type, message, null);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void debug(EventType type, String message, Throwable throwable) {
            log(Level.DEBUG, type, message, throwable);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void debug(EventType type, String message) {
            log(Level.DEBUG, type, message, null);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void info(EventType type, String message) {
            log(Level.INFO, type, message, null);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void info(EventType type, String message, Throwable throwable) {
            log(Level.INFO, type, message, throwable);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void warning(EventType type, String message, Throwable throwable) {
            log(Level.WARN, type, message, throwable);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void warning(EventType type, String message) {
            log(Level.WARN, type, message, null);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void error(EventType type, String message, Throwable throwable) {
            log(Level.ERROR, type, message, throwable);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void error(EventType type, String message) {
            log(Level.ERROR, type, message, null);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void fatal(EventType type, String message, Throwable throwable) {
            log(Level.FATAL, type, message, throwable);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void fatal(EventType type, String message) {
            log(Level.FATAL, type, message, null);
        }

        /**
         * Log the message after optionally encoding any special characters that might be dangerous when viewed
         * by an HTML based log viewer. Also encode any carriage returns and line feeds to prevent log 
         * injection attacks. This logs all the supplied parameters plus the user ID, user's source IP, a logging
         * specific session ID, and the current date/time.
         * 
         * It will only log the message if the current logging level is enabled, otherwise it will 
         * discard the message. 
         * 
         * @param level the severity level of the security event
         * @param type the type of the event (SECURITY, FUNCTIONALITY, etc.)
         * @param success whether this was a failed or successful event
         * @param message the message
         * @param throwable the throwable
         */
        private void log(Level level, EventType type, String message, Throwable throwable) {
        	
        	// Before we waste time preparing this event for the log, we check to see if it needs to be logged
        	if (!jlogger.isEnabledFor( level )) return;
        	
        	User user = ESAPI.authenticator().getCurrentUser();
            
            // create a random session number for the user to represent the user's 'session', if it doesn't exist already
            String userSessionIDforLogging = "unknown";

            try {
                HttpSession session = ESAPI.httpUtilities().getCurrentRequest().getSession( false );
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
            
            // create the message to log
            String msg = "";
            if ( user != null && type != null) {
            	msg = type + " " + user.getAccountName()+ ":" + user.getAccountId() + "@"+ user.getLastHostAddress() +":" + userSessionIDforLogging + " " + clean;
            }
            if(throwable == null) {
            	jlogger.log(level, applicationName + " " + moduleName + " " + msg);
            } else {
            	jlogger.log(level, applicationName + " " + moduleName + " " + msg, throwable);
            }
        }

        /**
    	* {@inheritDoc}
    	*/
        public boolean isDebugEnabled() {
    	    return jlogger.isEnabledFor(Level.DEBUG);
        }

        /**
    	* {@inheritDoc}
    	*/
        public boolean isErrorEnabled() {
    	    return jlogger.isEnabledFor(Level.ERROR);
        }

        /**
    	* {@inheritDoc}
    	*/
        public boolean isFatalEnabled() {
    	    return jlogger.isEnabledFor(Level.FATAL);
        }

        /**
    	* {@inheritDoc}
    	*/
        public boolean isInfoEnabled() {
    	    return jlogger.isEnabledFor(Level.INFO);
        }

        /**
    	* {@inheritDoc}
    	*/
        public boolean isTraceEnabled() {
            return jlogger.isEnabledFor(Level.TRACE);
        }

        /**
    	* {@inheritDoc}
    	*/
        public boolean isWarningEnabled() {
    	    return jlogger.isEnabledFor(Level.WARN);
        }
    }
}
