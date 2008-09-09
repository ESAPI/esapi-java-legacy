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
 * @see org.owasp.esapi.Logger
 */
public class JavaLogFactory implements LogFactory {

	private String applicationName;
	
	public JavaLogFactory(String applicationName) {
		this.applicationName = applicationName;
	}
	
	/* (non-Javadoc)
     * @see org.owasp.esapi.interfaces.ILogFactory#getLogger(java.lang.Class)
     */
    public Logger getLogger(Class clazz) {
	    return new JavaLogger(applicationName, clazz.getName());
    }

	/* (non-Javadoc)
     * @see org.owasp.esapi.interfaces.ILogFactory#getLogger(java.lang.String)
     */
    public Logger getLogger(String name) {
    	return new JavaLogger(applicationName, name);
    }

    private static class JavaLogger implements org.owasp.esapi.Logger {

        /** The jlogger. */
        private java.util.logging.Logger jlogger = null;

        /** The application name. */
        private String applicationName = null;

        /** The module name. */
        private String moduleName = null;
        
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
            this.jlogger.setLevel( Level.ALL );
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.interfaces.ILogger#logTrace(short, java.lang.String, java.lang.String, java.lang.Throwable)
         */
        public void trace(String type, String message, Throwable throwable) {
            log(Level.FINEST, type, message, throwable);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.interfaces.ILogger#logTrace(java.lang.String, java.lang.String)
         */
        public void trace(String type, String message) {
            log(Level.FINEST, type, message, null);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.interfaces.ILogger#logDebug(short, java.lang.String, java.lang.String, java.lang.Throwable)
         */
        public void debug(String type, String message, Throwable throwable) {
            log(Level.FINE, type, message, throwable);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.interfaces.ILogger#logDebug(java.lang.String, java.lang.String)
         */
        public void debug(String type, String message) {
            log(Level.FINE, type, message, null);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.interfaces.ILogger#logError(short, java.lang.String, java.lang.String, java.lang.Throwable)
         */
        public void error(String type, String message, Throwable throwable) {
            log(Level.SEVERE, type, message, throwable);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.interfaces.ILogger#logError(java.lang.String, java.lang.String)
         */
        public void error(String type, String message) {
            log(Level.SEVERE, type, message, null);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.interfaces.ILogger#logSuccess(short, java.lang.String, java.lang.String,
         * java.lang.Throwable)
         */
        public void info(String type, String message) {
            log(Level.INFO, type, message, null);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.interfaces.ILogger#logSuccess(short, java.lang.String, java.lang.String,
         * java.lang.Throwable)
         */
        public void info(String type, String message, Throwable throwable) {
            log(Level.INFO, type, message, throwable);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.interfaces.ILogger#logWarning(short, java.lang.String, java.lang.String,
         * java.lang.Throwable)
         */
        public void warning(String type, String message, Throwable throwable) {
            log(Level.WARNING, type, message, throwable);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.interfaces.ILogger#logWarning(java.lang.String, java.lang.String)
         */
        public void warning(String type, String message) {
            log(Level.WARNING, type, message, null);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.interfaces.ILogger#logCritical(short, java.lang.String, java.lang.String,
         * java.lang.Throwable)
         */
        public void fatal(String type, String message, Throwable throwable) {
            log(Level.SEVERE, type, message, throwable);
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.owasp.esapi.interfaces.ILogger#logCritical(java.lang.String, java.lang.String)
         */
        public void fatal(String type, String message) {
            log(Level.SEVERE, type, message, null);
        }

        /**
         * Log the message after optionally encoding any special characters that might inject into an HTML based log viewer.
         * 
         * @param message the message
         * @param level the level
         * @param type the type
         * @param throwable the throwable
         */
        private void log(Level level, String type, String message, Throwable throwable) {
            User user = ESAPI.authenticator().getCurrentUser();
            
            // get a random session number
            String counter = "unknown";
            try {
                HttpSession session = ESAPI.httpUtilities().getCurrentRequest().getSession();
	            counter = (String)session.getAttribute("ESAPI_SESSION" );
	            if ( counter == null ) {
	            	counter = ""+ ESAPI.randomizer().getRandomInteger(0, 100000);
	            	session.setAttribute("ESAPI_SESSION", counter);
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
            if ( throwable != null ) {
            	String fqn = throwable.getClass().getName();
            	int index = fqn.lastIndexOf('.');
            	if ( index > 0 ) fqn = fqn.substring(index + 1);
            	StackTraceElement ste = throwable.getStackTrace()[0];
            	clean += "\n    " + fqn + " @ " + ste.getClassName() + "." + ste.getMethodName() + "(" + ste.getFileName() + ":" + ste.getLineNumber() + ")";
            }
            String msg = "";
            if ( user != null ) {
            	msg = type + ": " + user.getAccountName() + "("+ counter +")(" + user.getLastHostAddress() + ") -- " + clean;
            }
            
            // jlogger.logp(level, applicationName, moduleName, msg, throwable);
            jlogger.logp(level, applicationName, moduleName, msg);
        }

    	/* (non-Javadoc)
         * @see org.owasp.esapi.interfaces.ILogger#isDebugEnabled()
         */
        public boolean isDebugEnabled() {
    	    return jlogger.isLoggable(Level.FINE);
        }

    	/* (non-Javadoc)
         * @see org.owasp.esapi.interfaces.ILogger#isErrorEnabled()
         */
        public boolean isErrorEnabled() {
    	    return jlogger.isLoggable(Level.SEVERE);
        }

    	/* (non-Javadoc)
         * @see org.owasp.esapi.interfaces.ILogger#isFatalEnabled()
         */
        public boolean isFatalEnabled() {
    	    return jlogger.isLoggable(Level.SEVERE);
        }

    	/* (non-Javadoc)
         * @see org.owasp.esapi.interfaces.ILogger#isInfoEnabled()
         */
        public boolean isInfoEnabled() {
    	    return jlogger.isLoggable(Level.INFO);
        }

    	/* (non-Javadoc)
         * @see org.owasp.esapi.interfaces.ILogger#isTraceEnabled()
         */
        public boolean isTraceEnabled() {
    	    return jlogger.isLoggable(Level.FINEST);
        }

    	/* (non-Javadoc)
         * @see org.owasp.esapi.interfaces.ILogger#isWarningEnabled()
         */
        public boolean isWarningEnabled() {
    	    return jlogger.isLoggable(Level.WARNING);
        }

    }
}
