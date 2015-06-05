package org.owasp.esapi.configuration;

import org.owasp.esapi.configuration.consts.EsapiPropertiesStore;
import org.owasp.esapi.errors.ConfigurationException;

import static org.owasp.esapi.configuration.consts.EsapiStoreType.PROPERTIES;
import static org.owasp.esapi.configuration.consts.EsapiStoreType.XML;

/**
 * Factory class that takes care of initialization of proper instance of EsapiPropertyLoader
 * based on EsapiPropertiesStore
 */
public class EsapiPropertyLoaderFactory {
    
    public static EsapiPropertyLoader createPropertyLoader(EsapiPropertiesStore store) throws ConfigurationException {
        if (store.storeType().equals(XML)) {
            return new StandardEsapiPropertyLoader(store.filename(), store.priority());
        }
        if (store.storeType().equals(PROPERTIES)) {
            return new XmlEsapiPropertyLoader(store.filename(), store.priority());
        } else {
            throw new ConfigurationException("Configuration storage type [" + store.storeType().name() + "] is not " +
                    "supported");
        }
    }
}
