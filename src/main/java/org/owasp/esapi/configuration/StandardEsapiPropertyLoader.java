package org.owasp.esapi.configuration;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.ConfigurationException;

import java.io.*;
import java.util.Properties;

/**
 * Loader capable of loading single security configuration property from standard java properties configuration file.
 */
public class StandardEsapiPropertyLoader implements EsapiPropertyLoader, Comparable<EsapiPropertyLoader>  {

    private String filename;

    private int priority;

    protected Properties properties;

    public StandardEsapiPropertyLoader(String filename, int priority) throws FileNotFoundException {
        this.filename = filename;
        this.priority = priority;
        properties = new Properties();

        File file = new File(filename);
        if (file.exists() && file.isFile()) {
            loadPropertiesFromFile();
        } else {
            throw new FileNotFoundException();
        }
    }

    @Override
    public int getIntProp(String propertyName) throws ConfigurationException {
        String property = properties.getProperty( propertyName );
        if ( property == null ) {
            throw new ConfigurationException("Property : " + propertyName + "not found in default configuration");
        }
        try {
            return Integer.parseInt( property );
        } catch( NumberFormatException e ) {
            throw new ConfigurationException("Incorrect type of : " + propertyName + ". Value " + property +
                    "cannot be converted to integer");
        }
    }

    @Override
    public byte[] getByteArrayProp(String propertyName) throws ConfigurationException {
        String property = properties.getProperty( propertyName );
        if ( property == null ) {
            throw new ConfigurationException("Property : " + propertyName + "not found in default configuration");
        }
        try {
            return ESAPI.encoder().decodeFromBase64(property);
        } catch( IOException e ) {
            throw new ConfigurationException("Incorrect type of : " + propertyName + ". Value " + property +
                    "cannot be converted to byte array");
        }
    }

    @Override
    public Boolean getBooleanProp(String propertyName) throws ConfigurationException {
        String property = properties.getProperty( propertyName );
        if ( property == null ) {
            throw new ConfigurationException("Property : " + propertyName + "not found in default configuration");
        }
        if ( property.equalsIgnoreCase("true") || property.equalsIgnoreCase("yes" ) ) {
            return true;
        }
        if ( property.equalsIgnoreCase("false") || property.equalsIgnoreCase( "no" ) ) {
            return false;
        } else {
            throw new ConfigurationException("Incorrect type of : " + propertyName + ". Value " + property +
                    "cannot be converted to boolean");
        }
    }

    @Override
    public String getStringProp(String propertyName) throws ConfigurationException {
        String property = properties.getProperty( propertyName );
        if ( property == null ) {
            throw new ConfigurationException("Property : " + propertyName + "not found in default configuration");
        }
        return property;
    }

    @Override
    public int priority() {
        return priority;
    }

    @Override
    public int compareTo(EsapiPropertyLoader compared) {
        if (this.priority > compared.priority()) {
            return 1;
        } else if (this.priority < compared.priority()) {
            return -1;
        }
        return 0;
    }

    private void loadPropertiesFromFile() {
        InputStream input = null;
        try {
            input = new FileInputStream(filename);
            properties.load(input);
        } catch (IOException ex) {
            System.err.println("Loading " + filename + " via file I/O failed. Exception was: " + ex);
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

}
