package org.owasp.esapi.configuration.consts;


/**
 * Supported esapi configuration file types.
 */
public enum EsapiConfigurationType {
    PROPERTIES("properties"), XML("xml");

    String typeName;

    EsapiConfigurationType(String typeName) {
        this.typeName = typeName;
    }

    public String getTypeName() {
        return typeName;
    }
}
