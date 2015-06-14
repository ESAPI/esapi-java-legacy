package org.owasp.esapi.configuration;

import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.errors.ConfigurationException;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;

import java.io.FileNotFoundException;
import java.util.TreeSet;

import static org.owasp.esapi.configuration.EsapiPropertyLoaderFactory.createPropertyLoader;
import static org.owasp.esapi.configuration.consts.EsapiPropertiesStore.DEVTEAM_ESAPI_CFG;
import static org.owasp.esapi.configuration.consts.EsapiPropertiesStore.OPTEAM_ESAPI_CFG;

/**
 * Manager used for loading security configuration properties. Does all the logic to obtain the correct property from
 * correct source.
 */
public class EsapiPropertyManager implements EsapiPropertyLoader {

    private TreeSet<AbstractPrioritizedPropertyLoader> loaders;
    private SecurityConfiguration defaultSecurityConfiguration;

    public EsapiPropertyManager() {
        initLoaders();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getIntProp(String propertyName) throws ConfigurationException {
        for (AbstractPrioritizedPropertyLoader loader : loaders) {
            try {
                return loader.getIntProp(propertyName);
            } catch (ConfigurationException e) {
                System.err.println("Property not found in " + loader.toString());
            }
        }
        return defaultSecurityConfiguration.getIntProp(propertyName);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getByteArrayProp(String propertyName) throws ConfigurationException {
        for (AbstractPrioritizedPropertyLoader loader : loaders) {
            try {
                return loader.getByteArrayProp(propertyName);
            } catch (ConfigurationException e) {
                System.err.println("Property not found in " + loader.toString());
            }
        }
        return defaultSecurityConfiguration.getByteArrayProp(propertyName);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Boolean getBooleanProp(String propertyName) throws ConfigurationException {
        for (AbstractPrioritizedPropertyLoader loader : loaders) {
            try {
                return loader.getBooleanProp(propertyName);
            } catch (ConfigurationException e) {
                System.err.println("Property not found in " + loader.toString());
            }
        }
        return defaultSecurityConfiguration.getBooleanProp(propertyName);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getStringProp(String propertyName) throws ConfigurationException {
        for (AbstractPrioritizedPropertyLoader loader : loaders) {
            try {
                return loader.getStringProp(propertyName);
            } catch (ConfigurationException e) {
                System.err.println("Property not found in " + loader.name());
            }
        }
        return defaultSecurityConfiguration.getStringProp(propertyName);
    }

    private void initLoaders() {
        loaders = new TreeSet<AbstractPrioritizedPropertyLoader>();

        try {
            loaders.add(createPropertyLoader(DEVTEAM_ESAPI_CFG));
        } catch (FileNotFoundException e) {
            System.err.println(e.getMessage());
        }
        try {
            loaders.add(createPropertyLoader(OPTEAM_ESAPI_CFG));
        } catch (FileNotFoundException e) {
            System.err.println(e.getMessage());
        }

        // legacy default security configuration
        defaultSecurityConfiguration = DefaultSecurityConfiguration.getInstance();
    }


}
