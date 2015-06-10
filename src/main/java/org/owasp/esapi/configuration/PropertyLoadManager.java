package org.owasp.esapi.configuration;

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
public class PropertyLoadManager {


    private TreeSet<EsapiPropertyLoader> loaders;
    
    public PropertyLoadManager() {
        initLoaders();
    }

    // example for get String property
    public String getStringProperty(String propertyName) throws ConfigurationException {
        for (EsapiPropertyLoader loader : loaders) {
            String propertyValue = loader.getStringProp(propertyName);
            if (propertyValue != null) {
                return propertyValue;
            }
        }
        return null;
    }

    private void initLoaders() {
        loaders = new TreeSet<EsapiPropertyLoader>();

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
        loaders.add(new DefaultSecurityConfiguration());
    }


}
