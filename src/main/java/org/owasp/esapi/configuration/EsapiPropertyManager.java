package org.owasp.esapi.configuration;

import org.owasp.esapi.errors.ConfigurationException;

import java.util.TreeSet;

import static org.owasp.esapi.configuration.EsapiPropertyLoaderFactory.createPropertyLoader;
import static org.owasp.esapi.configuration.consts.EsapiPropertiesStore.*;

/**
 * Manager used for loading security configuration properties. Does all the logic to obtain the correct property from
 * correct source.
 */
public class EsapiPropertyManager implements EsapiPropertyLoader {

    protected TreeSet<AbstractPrioritizedPropertyLoader> loaders;

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
        throw new ConfigurationException("Could not find property " + propertyName + " in configuration");
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
        throw new ConfigurationException("Could not find property " + propertyName + " in configuration");
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
        throw new ConfigurationException("Could not find property " + propertyName + " in configuration");
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
        throw new ConfigurationException("Could not find property " + propertyName + " in configuration");
    }

    private void initLoaders() {
        loaders = new TreeSet<AbstractPrioritizedPropertyLoader>();

        try {
            loaders.add(createPropertyLoader(DEVTEAM_ESAPI_CFG));
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        try {
            loaders.add(createPropertyLoader(OPTEAM_ESAPI_CFG));
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        try {
            loaders.add(createPropertyLoader(LEGACY_ESAPI_CFG));
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }


}
