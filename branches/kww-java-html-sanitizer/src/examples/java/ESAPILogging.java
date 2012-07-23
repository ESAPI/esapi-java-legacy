import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;

// Purpose: Short code snippet to show how ESAPI logging works.
//
// Usage: java -classpath <cp> ESAPILogging
//        where <cp> is proper classpath, which minimally include esapi.jar & log4j.jar
public class ESAPILogging {

    public static void main(String[] args) {

        try {
            Logger logger = ESAPI.getLogger("ESAPILogging");
            
            logger.warning(Logger.SECURITY_FAILURE, "This is a warning.");
            logger.always(Logger.SECURITY_AUDIT, "This is an audit log. It always logs.");
        } catch(Throwable t) {
            System.err.println("Caught: " + t.getClass().getName() +
                               "; exception msg: " + t);
            t.printStackTrace(System.err);
        }
    }
}
