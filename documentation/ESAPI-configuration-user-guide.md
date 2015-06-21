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

## Multiple configuration files support

EsapiPropertyManager is the new implementation for getting properties, which uses prioritized property loaders 
(each one connected with specific configuration file). This allows to have multiple configuration files existing with
priority connected to each one. At this moment, there are two configuration files possible to use, path to them is 
set through following java system properties:
 
* org.owasp.esapi.opsteam = <full_path_to_file> (higher priority config)
* org.owasp.esapi.devteam = <full_path_to_file> (lower priority config)

DefaultSecurityConfiguration uses this mechanism through new API for getting 
properties.

It is not mandatory to have both files configured or even any of them for DefaultSecurityConfiguration to work. It 
can still use ESAPI.properties to search for property. In case of any of the configurations or both of the existing, 
ESAPI.properties has LOWEST priority, so it will be searched as last.

### Example properties extraction through DefaultSecurityConfiguration

```java
ESAPI.securityConfiguration().getBooleanProp("propertyXXX);
```
 
In above example, following happens:
  
1. org.owasp.esapi.opsteam configuration is used to get propertyXXX and return it as boolean.
2. If (1) fails to find property, org.owasp.esapi.devteam is used to get propertyXXX and return it as boolean.
3. If (2) fails to find property, ESAPI.properties is used to get propertyXXX and return it as boolean.
4. If (3) fails to find property, unchecked ConfigurationException will be thrown.

ConfigurationException will be also thrown if propertyXXX will be found in one of the configuration, but it will be
impossible to convert it to boolean.

## XML configuration support

XML configuration storage is supported. Both org.owasp.esapi.opsteam and org.owasp.esapi.devteam can be xml files, 
but they must accord to xsd schema:

```xml
<xs:schema attributeFormDefault="unqualified" elementFormDefault="qualified" xmlns:xs="http://www.w3.org/2001/XMLSchema">
    <xs:element name="properties">
        <xs:complexType>
            <xs:sequence>
                <xs:element name="property" maxOccurs="unbounded" minOccurs="0">
                    <xs:complexType>
                        <xs:simpleContent>
                            <xs:extension base="xs:string">
                                <xs:attribute type="xs:string" name="name" use="optional"/>
                            </xs:extension>
                        </xs:simpleContent>
                    </xs:complexType>
                </xs:element>
            </xs:sequence>
        </xs:complexType>
    </xs:element>
</xs:schema>
```

### XML configuration example:
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