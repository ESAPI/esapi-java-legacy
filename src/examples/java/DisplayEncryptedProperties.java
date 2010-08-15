import java.io.*;
import java.util.*;
import org.owasp.esapi.EncryptedProperties;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.reference.crypto.DefaultEncryptedProperties;

// Purpose: Short code snippet to show how to display encrypted property files
//          that were encrypted using ESAPI's EncryptedProperties class.
//
// Usage: java -classpath <cp> DisplayEncryptedProperties encryptedPropFileName
//        where <cp> is proper classpath, which minimally include esapi.jar & log4j.jar
public class DisplayEncryptedProperties {

    public DisplayEncryptedProperties() {
    }

    public void loadProperties(String encryptedPropertiesFilename,
                                  Properties props )
        throws IOException
    {
         EncryptedProperties loader = new DefaultEncryptedProperties();
         loader.load( new FileInputStream(
                                    new File( encryptedPropertiesFilename) ) );

         try {
             props.setProperty( "database.driver",
                                loader.getProperty( "database.driver" ) );
             props.setProperty( "jdbc.url",
                                loader.getProperty( "database.url" ) );
             props.setProperty( "jdbc.username",
                                loader.getProperty( "database.username" ) );
             props.setProperty( "jdbc.password",
                                loader.getProperty( "database.password" ) );
         } catch( EncryptionException ee ) {
             ee.printStackTrace();
         }
    }

    public void showProperties(Properties props) throws Exception
    {
        String value = null;
        value = props.getProperty( "database.driver");
        System.out.println("database.driver=" + value);
        value = props.getProperty( "jdbc.url");
        System.out.println("jdbc.database=" + value);
        value = props.getProperty( "jdbc.username");
        System.out.println("jdbc.username=" + value);
        value = props.getProperty( "jdbc.password");
        System.out.println("jdbc.password=" + value);
    }


    public static void main(String[] args) {

        try {
            DisplayEncryptedProperties dep = new DisplayEncryptedProperties();
            Properties props = new Properties();

            String encryptedPropFname = "encrypted.properties";
            if ( args.length == 1 ) {
                encryptedPropFname = args[0];
            }

            dep.loadProperties(encryptedPropFname, props);
            dep.showProperties(props);

        } catch(Throwable t) {
            System.err.println("Caught: " + t.getClass().getName() +
                               "; exception msg: " + t);
            t.printStackTrace(System.err);
        }
    }
}
