/**
 * 
 */
package org.owasp.esapi.reference;

import java.util.HashMap;
import java.util.logging.Level;

import javax.servlet.http.HttpSession;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.LogFactory;
import org.owasp.esapi.Logger;
import org.owasp.esapi.User;

/**
 * Reference implementation of the LogFactory and Logger interfaces. This implementation uses the Java logging package, and marks each
 * log message with the currently logged in user and the word "SECURITY" for security related events. See the 
 * <a href="JavaLogFactory.JavaLogger.html">JavaLogFactory.JavaLogger</a> Javadocs for the details on the JavaLogger reference implementation.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.LogFactory
 * @see org.owasp.esapi.reference.JavaLogFactory.JavaLogger
 */
public class JavaLogFactory implements LogFactory {

	private String applicationName;
	
	private HashMap loggersMap = new HashMap();
	
	public JavaLogFactory(String applicationName) {
		this.applicationName = applicationName;
	}
	
	/* (non-Javadoc)
     * @see org.owasp.esapi.LogFactory#getLogger(java.lang.Class)
     */
    public Logger getLogger(Class clazz) {
    	
    	// If a logger for this class already exists, we return the same one, otherwise we create a new one.
    	Logger classLogger = (Logger) loggersMap.get(clazz);
    	
    	if (classLogger == null) {
    		classLogger = new JavaLogger(applicationName, clazz.getName());
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
    		moduleLogger = new JavaLogger(applicationName, moduleName);
    		loggersMap.put(moduleName, moduleLogger);    		
    	}
		return moduleLogger;
    }


    /**
     *  A custom logging level defined between Level.SEVERE and Level.WARNING in logger.
     */
    public static class JavaLoggerLevel extends Level {

    	public static final Level ERROR_LEVEL = new JavaLoggerLevel( "ERROR", Level.SEVERE.intValue() - 1);
    	
		protected JavaLoggerLevel(String name, int value) {
			super(name, value);
		}
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
    private static class JavaLogger implements org.owasp.esapi.Logger {

    	/** The jlogger object used by this class to log everything. */
        private java.util.logging.Logger jlogger = null;

        /** The application name using this log. */
        private String applicationName = null;

        /** The module name using this log. */
        private String moduleName = null;

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
        private JavaLogger(String applicationName, String moduleName) {
            this.applicationName = applicationName;
            this.moduleName = moduleName;
            this.jlogger = java.util.logging.Logger.getLogger(applicationName + ":" + moduleName);
            // This set the default logging level. It isn't necessary now that the configuration value is used.
            //this.jlogger.setLevel( Level.WARNING );  // The default level for this logger is Level.WARNING
            
            // Set the logging level defined in the config file.
            // Beware getting info from SecurityConfiguration, since it logs. We made sure it doesn't log in the
            // constructor and the getLogLevel() method, so this should work.
            this.jlogger.setLevel( JavaLogger.currentLevel );

            // The following is sort of how you would log to a file, but it doesn't quite work yet
            // Since it can't always lock when there are multiple logs all pointing to the same file.
            /*
            try {
            	this.jlogger.addHandler( new FileHandler("C:\\ESAPI\\DaveLog", true) );
            } catch (IOException e) {
            	this.jlogger.log(Level.SEVERE, "Couldn't set log file to DaveLog", e);
            }
            
            System.out.println("Dave: new logger created for app: " + applicationName + " and module: " + moduleName);
            */
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
        		JavaLogger.currentLevel = convertESAPILeveltoLoggerLevel( level );
        	}
        	catch (IllegalArgumentException e) {
       			this.error(Logger.SECURITY, false, "", e);    		
        	}
         }
        
        /**
         * Converts the ESAPI logging level (a number) into the levels used by Java's logger.
         * @param level The ESAPI to convert.
         * @return The Java logging Level that is equivalent.
         * @throws IllegalArgumentException if the supplied ESAPI level doesn't make a level that is currently defined.
         */
        private static Level convertESAPILeveltoLoggerLevel(int level)
        {
        	switch (level) {
        		case Logger.OFF:     return Level.OFF;
        		case Logger.FATAL:   return Level.SEVERE;
        		case Logger.ERROR:   return JavaLoggerLevel.ERROR_LEVEL; // This is a custom level.
        		case Logger.WARNING: return Level.WARNING;
        		case Logger.INFO:    return Level.INFO;
        		case Logger.DEBUG:   return Level.FINE;
        		case Logger.TRACE:   return Level.FINEST;
        		case Logger.ALL:     return Level.ALL;       		
        		default: {
        			throw new IllegalArgumentException("Invalid logging level. Value was: " + level);
        		}
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
        	this.jlogger.setLevel( JavaLogger.currentLevel );
        	
        	// Before we waste all kinds of time preparing this event for the log, let check to see if its loggable
        	if (!jlogger.isLoggable( level )) return;
       	
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
            
            jlogger.logp(level, applicationName, moduleName, msg);
        }

    	/* (non-Javadoc)
         * @see org.owasp.esapi.Logger#isDebugEnabled()
         */
        public boolean isDebugEnabled() {
            this.jlogger.setLevel( JavaLogger.currentLevel );
    	    return jlogger.isLoggable(Level.FINE);
        }

    	/* (non-Javadoc)
         * @see org.owasp.esapi.Logger#isErrorEnabled()
         */
        public boolean isErrorEnabled() {
            this.jlogger.setLevel( JavaLogger.currentLevel );
    	    return jlogger.isLoggable(JavaLoggerLevel.ERROR_LEVEL);
        }

    	/* (non-Javadoc)
         * @see org.owasp.esapi.Logger#isFatalEnabled()
         */
        public boolean isFatalEnabled() {
            this.jlogger.setLevel( JavaLogger.currentLevel );
    	    return jlogger.isLoggable(Level.SEVERE);
        }

    	/* (non-Javadoc)
         * @see org.owasp.esapi.Logger#isInfoEnabled()
         */
        public boolean isInfoEnabled() {
            this.jlogger.setLevel( JavaLogger.currentLevel );
    	    return jlogger.isLoggable(Level.INFO);
        }

    	/* (non-Javadoc)
         * @see org.owasp.esapi.Logger#isTraceEnabled()
         */
        public boolean isTraceEnabled() {
            this.jlogger.setLevel( JavaLogger.currentLevel );
    	    return jlogger.isLoggable(Level.FINEST);
        }

    	/* (non-Javadoc)
         * @see org.owasp.esapi.Logger#isWarningEnabled()
         */
        public boolean isWarningEnabled() {
            this.jlogger.setLevel( JavaLogger.currentLevel );
    	    return jlogger.isLoggable(Level.WARNING);
        }

    }
}
