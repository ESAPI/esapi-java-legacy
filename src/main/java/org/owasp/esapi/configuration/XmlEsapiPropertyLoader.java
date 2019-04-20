package org.owasp.esapi.configuration;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.ConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Loader capable of loading single security configuration property from xml configuration file.
 *
 * @since 2.2
 */
public class XmlEsapiPropertyLoader extends AbstractPrioritizedPropertyLoader {

    public XmlEsapiPropertyLoader(String filename, int priority) {
        super(filename, priority);
    }

    /**
     * {@inheritDoc}
     */
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
                    "cannot be converted to integer", e);
        }
    }

    /**
     * {@inheritDoc}
     */
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
                    "cannot be converted to byte array", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Boolean getBooleanProp(String propertyName) throws ConfigurationException {
        String property = properties.getProperty(propertyName);
        if (property == null) {
            throw new ConfigurationException("Property : " + propertyName + " not found in default configuration");
        }
        if (property.equalsIgnoreCase("true") || property.equalsIgnoreCase("yes")) {
            return true;
        }
        if (property.equalsIgnoreCase("false") || property.equalsIgnoreCase("no")) {
            return false;
        } else {
            throw new ConfigurationException("Incorrect type of : " + propertyName + ". Value " + property +
                    "cannot be converted to boolean");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getStringProp(String propertyName) throws ConfigurationException {
        String property = properties.getProperty(propertyName);
        if (property == null) {
            throw new ConfigurationException("Property : " + propertyName + " not found in default configuration");
        }
        return property;
    }

    /**
     * Methods loads configuration from .xml file. 
     * @param file
     */
    protected void loadPropertiesFromFile(File file) throws ConfigurationException {
        try {
            validateAgainstXSD(new FileInputStream(file));

            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(file);
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
            throw new ConfigurationException("Configuration file : " + filename + " has invalid schema." + e.getMessage(), e);
        }
    }

    private void validateAgainstXSD(InputStream xml) throws Exception {
        InputStream xsd = getClass().getResourceAsStream("/ESAPI-properties.xsd");
        SchemaFactory factory =
                SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        Schema schema = factory.newSchema(new StreamSource(xsd));
        Validator validator = schema.newValidator();
        validator.validate(new StreamSource(xml));
    }

}
