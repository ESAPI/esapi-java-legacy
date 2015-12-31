# ESAPI security configuration API enhancements - user guide

## Motivation
High number of open Google Issues against security configuration component
highlighted problem with ESAPI configuration. Moreover, the rules for how and
where the ESAPI.properties file is found are overly complicated making questions
about it one of the most frequently asked questions.

The ESAPI interface for its configuration (SecurityConfiguration) is overly
complicated; it has a 'getter' method specific to almost every ESAPI
configuration property. This complication leads to a unduly intricate,
non-modular reference implementation (DefaultSecurityConfiguration) that makes
it difficult to extend in terms of new functionality; e.g., when desiring to
introduce a new ESAPI property name in ESAPI.properties.

A new, simpler security configuration interface and implementation is needed.
Such an implementation would not only be useful for ESAPI 2.x, but could very
well be used to build the configurator needed by ESAPI 3.

This document describes following changes to ESAPI security API:

1. API simplification
2. XML configuration support.
3. Multiple configuration files support.

## API simplification

New interface is introduced: EsapiPropertyLoader, which contains four general
methods for extraction of configuration properties:

```
public int getIntProp(String propertyName) throws ConfigurationException;
public byte[] getByteArrayProp(String propertyName) throws ConfigurationException;
public Boolean getBooleanProp(String propertyName) throws ConfigurationException;
public String getStringProp(String propertyName) throws ConfigurationException;
```

SecurityConfiguration interface is extended with this new contract. Old methods
have been deprecated as a result, in favor of these new methods. (TBD how long
until these deprecated methods are removed, but it will be a minumum of 2 years
or 1 major release [e.g., 3.x], whichever comes first. Also, we may not
necessarily remove all of them at once, depending on community feedback.)

DefaultSecurityConfiguration implements the new contract. New contract methods implementations work as described in 
'Multiple configuration files support' paragraph.

## Multiple configuration files support

EsapiPropertyManager is the new implementation for getting properties, which uses prioritized property loaders (each one associated with a specific configuration file). This allows to have multiple configuration files existing with priority connected to each one. At this moment, there
are two configuration files possible to use, the path to them is set through following Java
system properties:
 
* org.owasp.esapi.opsteam = <full_path_to_file> (higher priority config)
* org.owasp.esapi.devteam = <full_path_to_file> (lower priority config)

The first is intended for deployment by an operations team responsible for
enforcing security for configuration management enterprise-wide. The intent here
is to allow this operations team to enforce global / company-wide policies such
as the minimum encryption key size or permitted cryptographic algorithms.

The second is intended for deployment by development teams and is more likely to
be useful and be tailored for each individual project based on project needs.

If an ESAPI property is set via the configuration file identified by
org.owasp.esapi.opsteam then that property takes precedence over any property
set by the configuration file identified by org.owasp.esapi.devteam system
property. (A warning message will be logged if a property defined in the higher
priority configuration file is also defined in the configuration file of lower
priority.)

The DefaultSecurityConfiguration class now uses this mechanism through the new
API for retrieving  properties.

It is not mandatory to have both files configured or even any of them for
DefaultSecurityConfiguration to work property. It can still use the single
ESAPI.properties to search for a property. In case of any of the configurations
or both of the existing,  ESAPI.properties has LOWEST priority, so it will be
searched as last.

### Example properties extraction through DefaultSecurityConfiguration

```java
ESAPI.securityConfiguration().getBooleanProp("propertyXXX");
```

where "propertyXXX" is some property name relevant to ESAPI (and
in this case, one that would hold a boolean value). See ESAPI.properties
for a list of current property names known to ESAPI.
 
In above example, following happens:
  
1. org.owasp.esapi.opsteam configuration is used to get propertyXXX and return it as boolean.
2. If (1) fails to find property, org.owasp.esapi.devteam is used to get propertyXXX and return it as boolean.
3. If (2) fails to find property, ESAPI.properties is used to get propertyXXX and return it as boolean.
4. If (3) fails to find property, unchecked ConfigurationException will be thrown.

A ConfigurationException will be also thrown if propertyXXX was found in one
of the configurations, but it is impossible to convert it to boolean value.

## XML configuration support

XML configuration storage is supported. Both org.owasp.esapi.opsteam and
org.owasp.esapi.devteam can be XML files, but they must comply to the
following XSD schema:

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
