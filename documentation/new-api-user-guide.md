<b>ESAPI security API enhancements - user guide</b>

This document describes following changes to ESAPI security API:

1. API simplification
2. XML configuration support.
3. Multiple configuration files support.

<b>API simplification </b>

* New interface is introduced: EsapiPropertyLoader, which contains four methods for extraction of configuration
properties:

```java
public int getIntProp(String propertyName) throws ConfigurationException;
public byte[] getByteArrayProp(String propertyName) throws ConfigurationException;
public Boolean getBooleanProp(String propertyName) throws ConfigurationException;
public String getStringProp(String propertyName) throws ConfigurationException;
```

SecurityConfiguration interface is extended with this new contract.

As DefaultSecurityConfiguration implements the new contract.

<b>XML configuration support</b>

XML configuration storage is supported. Example of configuration file can be found in test resources. 
XmlEsapiPropertyLoader is designed to load these configuration files into properties.

<b>Multiple configuration files support</b>

EsapiPropertyManager is the new API implementation for getting properties, which uses prioritized property loaders 
(each one connected with specific configuration file) and DefaultSecurityConfiguration as default mechanism. This 
allows to have multiple configuration files existing with priority connected to each one.

The priority is used to determine in which configuration file we should look for given property, the property loader 
with higher priority will be used first. Each property loader is tied with specific configuration file, so the name 
of file must be exactly the same as property loader expects it. Each configuration filename, file type and priority 
are hardcoded in EsapiPropertiesStore enum, which EsapiPropertyManager uses during initialization.

If given property is not found in any of two configurations, it uses DefaultSecurityConfiguration to get the 
property. This way the backward compatibility with old mechanism is possible when using EsapiPropertyManager as API 
for getting esapi properties.

It is not mandatory to actually have any configuration file existing. In that case, DefaultSecurityConfiguration 
will be used to obtain property from currently used ESAPI.properties file.