# ESAPI security configuration API enhancements - user guide

## Motivation
High number of open Google Issues against security configuration component highlighted problem with ESAPI configuration. Moreover, the rules for how and where the ESAPI.properties file is found are overly complicated making questions about it one of the most frequently asked questions. 

The ESAPI interface for its configuration (SecurityConfiguration) is overly complicated; it has a 'getter' method specific to almost every ESAPI configuration property. This complication leads to a unduly intricate, non-modular reference implementation (DefaultSecurityConfiguration) that makes it difficult to extend in terms of new functionality. 

A new, simpler security configuration interface and implementation is needed. Such an implementation would not only be useful for ESAPI 2.x, but could very well be used to build the configurator needed by ESAPI 3. 

This document describes following changes to ESAPI security API:

1. API simplification
2. XML configuration support.
3. Multiple configuration files support.

## API simplification

New interface is introduced: EsapiPropertyLoader, which contains four methods for extraction of configuration
properties:

```
public int getIntProp(String propertyName) throws ConfigurationException;
public byte[] getByteArrayProp(String propertyName) throws ConfigurationException;
public Boolean getBooleanProp(String propertyName) throws ConfigurationException;
public String getStringProp(String propertyName) throws ConfigurationException;
```

SecurityConfiguration interface is extended with this new contract. Old methods are deprecated now.

DefaultSecurityConfiguration implements the new contract. New contract methods implementations work as described in 
'Multiple configuration files support' paragraph.

## XML configuration support

XML configuration storage is supported. XmlEsapiPropertyLoader is designed to consume this type of configuration files.

XML configuration is validated against xsd schema named ESAPI-properties.xsd held in configuration/esapi. If 
validation against schema fails, ConfigurationException is thrown and error is logged that it is impossible to load 
file because of incorrect xml structure. This exception is caught by EsapiPropertyManager, so it does not make 
configuration initialization to fail, only this specific file will not be loaded.

In comparison to java properties file, xml structure contains additional information about property type: string, boolean, int or byteArray. This attribute is required and validated by xsd schema. If there is attempt of getting property with incorrect method (type missmatch) - exception will be thrown.

### Example:
XML file structure:
```
<?xml version="1.0" encoding="UTF-8"?>
<properties>
    <property name="string_property" type="string">test_string_property</property>
    <property name="int_property" type="int">5</property>
    <property name="invalid_int_property" type="int">invalid int</property>
    <property name="boolean_property" type="boolean">true</property>
    <property name="boolean_yes_property" type="boolean">yes</property>
    <property name="boolean_no_property" type="boolean">no</property>
    <property name="invalid_boolean_property" type="boolean">invalid boolean</property>
</properties>
```

The choice of the type of configuration file is currently available only for esapi developers.  // this has to be changed


## Multiple configuration files support

EsapiPropertyManager is the new implementation for getting properties, which uses prioritized property loaders 
(each one connected with specific configuration file). This allows to have multiple configuration files existing with
 priority connected to each one. DefaultSecurityConfiguration uses this mechanism in new methods for getting properties.

The priority is used to determine in which configuration file we should look for given property, the config file 
with higher priority will be used first. Each property loader is tied with specific configuration file, so the name 
of file must be exactly the same as property loader expects it. Configuration files must be inserted into 
configuration/esapi directory. Files names and types are currently hardcoded and both files have to defined like this:

* org.owasp.esapi.resources.devteam.properties (lower priority dev file)
* org.owasp.esapi.resources.opsteam.properties (higher priority ops file)

If given property is not found in any of two configurations, EsapiPropertyManager uses currently existing ESAPI
.properties file to get the property.

### Example

Consider we have two new files specified with following content:

* org.owasp.esapi.resources.opsteam.properties (higher priority):
    
    propA = valueA2
    propB = valueB2

* org.owasp.esapi.resources.devteam.properties (lower priority):

    propA = valueA1
    propC = valueC1

* ESAPI.properties (legacy file):

    propA = valueA3


1. In above example, when we want to get any property value, PropertyManager looks for it in file with highest priority. If it fails to find property or it has incorrect type, the ConfigurationException is thrown, which is caught in PropertyManager. Also we log error that property was not found in this file.
2. If step 1 failed (ConfigurationException was thrown), we repeat it for lower priority file.
3. If step 2 also failed, we use ESAPI.properties to obtain property. If we fail this time, ConfigurationException 
is thrown outside of PropertyManager to signal that the property is not configured in any configuration
file and now user has to deal with this situation.

