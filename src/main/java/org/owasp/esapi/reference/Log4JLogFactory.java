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
 * <a href="JavaLogFactory.Log4JLogger.html">JavaLogFactory.Log4JLogger</a> Javadocs for the details on the Log4JLogger reference implementation.
 * 
 * At class initialization time, the file log4j.properties or log4j.xml file will be loaded from the classpath. This configuration file is 
 * fundamental to make log4j work for you. Please see http://logging.apache.org/log4j/1.2/manual.html for more information. 
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
	
	private HashMap loggersMap = new HashMap();
	
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

        // Initialize the current logging level to the value defined in the configuration properties file
        /** The current level that logging is set to. */ 
        private static Level currentLevel = 
        	convertESAPILeveltoLoggerLevel( ESAPI.securityConfiguration().getLogLevel() );
        
        /**
         * Public constructor should only ever be called via the appropriate LogFactory
         * 
         * @param applicationName the application name
         * @param moduleName the module name
         */
        private Log4JLogger(String applicationName, String moduleName) {

            this.jlogger = org.apache.log4j.Logger.getLogger(applicationName + ":" + moduleName);
            
            // Set the logging level defined in the config file.
            // Beware getting info from SecurityConfiguration, since it logs. We made sure it doesn't log in the
            // constructor and the getLogLevel() method, so this should work.
            this.jlogger.setLevel( Log4JLogger.currentLevel );
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
        		Log4JLogger.currentLevel = convertESAPILeveltoLoggerLevel( level );
        	}
        	catch (IllegalArgumentException e) {
       			this.error(Logger.SECURITY, false, "", e);    		
        	}
         }
        
        /**
         * Converts the ESAPI logging level (a number) into the levels used by Log4J.
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
        		case Logger.DEBUG:   return Level.DEBUG;
        		case Logger.TRACE:   return Level.TRACE;
        		case Logger.ALL:     return Level.ALL;       		
        		default: {
        			throw new IllegalArgumentException("Invalid logging level. Value was: " + level);
        		}
        	}
        }

        /**
    	* {@inheritDoc}
    	*/
        public void trace(EventType type, boolean success, String message, Throwable throwable) {
            log(Level.TRACE, type, success, message, throwable);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void trace(EventType type, boolean success, String message) {
            log(Level.TRACE, type, success, message, null);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void debug(EventType type, boolean success, String message, Throwable throwable) {
            log(Level.DEBUG, type, success, message, throwable);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void debug(EventType type, boolean success, String message) {
            log(Level.DEBUG, type, success, message, null);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void info(EventType type, boolean success, String message) {
            log(Level.INFO, type, success, message, null);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void info(EventType type, boolean success, String message, Throwable throwable) {
            log(Level.INFO, type, success, message, throwable);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void warning(EventType type, boolean success, String message, Throwable throwable) {
            log(Level.WARN, type, success, message, throwable);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void warning(EventType type, boolean success, String message) {
            log(Level.WARN, type, success, message, null);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void error(EventType type, boolean success, String message, Throwable throwable) {
            log(Level.ERROR, type, success, message, throwable);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void error(EventType type, boolean success, String message) {
            log(Level.ERROR, type, success, message, null);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void fatal(EventType type, boolean success, String message, Throwable throwable) {
            log(Level.FATAL, type, success, message, throwable);
        }

        /**
    	* {@inheritDoc}
    	*/
        public void fatal(EventType type, boolean success, String message) {
            log(Level.FATAL, type, success, message, null);
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
        private void log(Level level, EventType type, boolean success, String message, Throwable throwable) {

        	// Set the current logging level to the current value since it 'might' have been changed for some other log.
        	this.jlogger.setLevel( Log4JLogger.currentLevel );
        	
        	// Before we waste all kinds of time preparing this event for the log, let check to see if its loggable
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
            if ( (ESAPI.securityConfiguration()).getLogEncodingRequired() ) {
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
            	msg = type + "-" + (success ? "SUCCESS" : "FAILURE" ) + " " + user.getAccountName() + "@"+ user.getLastHostAddress() +":" + userSessionIDforLogging + " -- " + clean;
            }
            
            jlogger.log(level, msg, throwable);
        }

        /**
    	* {@inheritDoc}
    	*/
        public boolean isDebugEnabled() {
            this.jlogger.setLevel( Log4JLogger.currentLevel );
    	    return jlogger.isDebugEnabled();
        }

        /**
    	* {@inheritDoc}
    	*/
        public boolean isErrorEnabled() {
            this.jlogger.setLevel( Log4JLogger.currentLevel );
    	    return jlogger.isEnabledFor(Level.ERROR);
        }

        /**
    	* {@inheritDoc}
    	*/
        public boolean isFatalEnabled() {
            this.jlogger.setLevel( Log4JLogger.currentLevel );
    	    return jlogger.isEnabledFor(Level.FATAL);
        }

        /**
    	* {@inheritDoc}
    	*/
        public boolean isInfoEnabled() {
            this.jlogger.setLevel( Log4JLogger.currentLevel );
    	    return jlogger.isInfoEnabled();
        }

        /**
    	* {@inheritDoc}
    	*/
        public boolean isTraceEnabled() {
            this.jlogger.setLevel( Log4JLogger.currentLevel );
    	    return jlogger.isTraceEnabled();
        }

        /**
    	* {@inheritDoc}
    	*/
        public boolean isWarningEnabled() {
            this.jlogger.setLevel( Log4JLogger.currentLevel );
    	    return jlogger.isEnabledFor(Level.WARN);
        }
    }
}
