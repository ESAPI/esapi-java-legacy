package org.owasp.esapi.configuration;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.ConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Loader capable of loading single security configuration property from xml configuration file.
 */
public class XmlEsapiPropertyLoader implements EsapiPropertyLoader, Comparable<EsapiPropertyLoader>  {

    private int priority;

//    protected Map<String, String> properties;
    protected Properties properties;

    public XmlEsapiPropertyLoader(String filename, int priority) throws FileNotFoundException {
        this.priority = priority;
//        properties = new HashMap<String, String>();
        properties = new Properties();

        File file = new File(filename);
        if (file.exists() && file.isFile()) {
            loadPropertiesFromFile(file);
        } else {
            throw new FileNotFoundException();
        }
    }

    @Override
    public int getIntProp(String propertyName) throws ConfigurationException {
        String property = properties.getProperty(propertyName);
        if (property == null) {
            throw new ConfigurationException("Property : " + propertyName + " not found in default configuration");
        }
        try {
            return Integer.parseInt(property);
        } catch (NumberFormatException e) {
            throw new ConfigurationException("Incorrect type of : " + propertyName + ". Value " + property +
                    "cannot be converted to integer");
        }
    }

    @Override
    public byte[] getByteArrayProp(String propertyName) throws ConfigurationException {
        String property = properties.getProperty(propertyName);
        if (property == null) {
            throw new ConfigurationException("Property : " + propertyName + " not found in default configuration");
        }
        try {
            return ESAPI.encoder().decodeFromBase64(property);
        } catch (IOException e) {
            throw new ConfigurationException("Incorrect type of : " + propertyName + ". Value " + property +
                    "cannot be converted to byte array");
        }
    }

    @Override
    public Boolean getBooleanProp(String propertyName) throws ConfigurationException {
        String property = properties.getProperty(propertyName);
        if (property == null) {
            throw new ConfigurationException("Property : " + propertyName + " not found in default configuration");
        }
        if (property.equalsIgnoreCase("true") || property.equalsIgnoreCase("yes" )) {
            return true;
        }
        if (property.equalsIgnoreCase("false") || property.equalsIgnoreCase("no")) {
            return false;
        } else {
            throw new ConfigurationException("Incorrect type of : " + propertyName + ". Value " + property +
                    "cannot be converted to boolean");
        }
    }

    @Override
    public String getStringProp(String propertyName) throws ConfigurationException {
        String property = properties.getProperty(propertyName);
        if (property == null) {
            throw new ConfigurationException("Property : " + propertyName + " not found in default configuration");
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

    private void loadPropertiesFromFile(File file) throws ConfigurationException {
        try {
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(file);

            //optional, but recommended
            doc.getDocumentElement().normalize();

            NodeList nodeList = doc.getElementsByTagName("property");
            for (int i = 0; i < nodeList.getLength(); i++) {
                Node node = nodeList.item(i);
                if (node.getNodeType() == Node.ELEMENT_NODE) {
                    Element element = (Element) node;
                    String propertyKey = element.getAttribute("name");
                    String propertyValue = element.getTextContent();
                    properties.put(propertyKey, propertyValue);
                }
            }
        } catch (Exception e) {
            throw new ConfigurationException("Invalid xml configuration file content");
        }
    }

//    private void loadPropertiesFromFile(File file) {
//        InputStream input = null;
//        try {
//            input = new FileInputStream(file);
//            properties.loadFromXML(input);
//        } catch (IOException ex) {
//            System.err.println("Loading " + file.getName() + " via file I/O failed. Exception was: " + ex);
//        } finally {
//            if (input != null) {
//                try {
//                    input.close();
//                } catch (IOException e) {
//                    e.printStackTrace();
//                }
//            }
//        }
//    }

}
