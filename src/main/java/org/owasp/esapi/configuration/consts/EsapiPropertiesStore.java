package org.owasp.esapi.configuration.consts;

import static org.owasp.esapi.configuration.consts.EsapiStoreType.PROPERTIES;

/**
 * Interface for storing esapi security configuration properties files related constants.
 */
public enum EsapiPropertiesStore {

    DEVTEAM_ESAPI_CFG("org.owasp.esapi.resources.devteam", PROPERTIES, 1),
    OPTEAM_ESAPI_CFG("org.owasp.esapi.resources.opsteam", PROPERTIES, 2);

    private String filename;
    private EsapiStoreType storeType;
    private int priority;
    
    EsapiPropertiesStore(String filename, EsapiStoreType storeType, int priority) {
        this.filename = filename;
        this.storeType = storeType;
        this.priority = priority;
    }

    public String filename() {
        return filename;
    }
    
    public EsapiStoreType storeType() {
        return storeType;
    }
    
    public int priority() {
        return priority;
    }
}
