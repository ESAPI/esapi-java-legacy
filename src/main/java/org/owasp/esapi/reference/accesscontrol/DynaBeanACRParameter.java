package org.owasp.esapi.reference.accesscontrol;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Date;
import java.util.Iterator;

import org.apache.commons.beanutils.LazyDynaMap;
import org.owasp.esapi.reference.accesscontrol.policyloader.PolicyParameters;

/**
 * A DynaBean comes from the apache bean utils. It is basically a 
 * convenient way to dynamically assign getters and setters. Essentially, 
 * the way we use DynaBean is a HashMap that can be set to read only.
 * @author Mike H. Fauzy
 */
public class DynaBeanACRParameter implements PolicyParameters {
	protected LazyDynaMap policyProperties;
	
	public DynaBeanACRParameter() {
		policyProperties = new LazyDynaMap();
	}
	
	/* (non-Javadoc)
	 * @see org.owasp.esapi.reference.accesscontrol.policyloader.PolicyParameters#get(java.lang.String)
	 */
	public Object get(String key) {
		return policyProperties.get(key);
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return The true/false value of the specified key. False if not found.
	 */
	public boolean getBoolean(String key) {
		return ((Boolean)get(key)).booleanValue();
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return The byte value of the specified key.
	 */
	public byte getByte(String key) {
		return ((Byte)get(key)).byteValue();
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return The char value of the specified key.
	 */
	public char getChar(String key) {
		return ((Character)get(key)).charValue();
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return The int value of the specified key.
	 */
	public int getInt(String key) {
		return ((Integer)get(key)).intValue();
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return The long value of the specified key.
	 */
	public long getLong(String key) {
		return ((Long)get(key)).longValue();
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return The float value of the specified key.
	 */
	public float getFloat(String key) {
		return ((Float)get(key)).floatValue();
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return The double value of the specified key.
	 */
	public double getDouble(String key) {
		return ((Double)get(key)).doubleValue();
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return The BigDecimal value of the specified key.
	 */
	public BigDecimal getBigDecimal(String key) {
		return (BigDecimal)get(key);
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return The BigInteger value of the specified key.
	 */
	public BigInteger getBigInteger(String key) {
		return (BigInteger)get(key);
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return The Date value of the specified key.
	 */
	public Date getDate(String key) {
		return (Date)get(key);
	}
	
	/**
	 * Convenience method to avoid common casts. Note that the time object
	 * is the same as a date object
	 * @param key
	 * @return The Date value of the specified key.
	 */
	public Date getTime(String key) {
		return (Date)get(key);
	}
	
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return The String value of the specified key. null if the key is not defined.
	 */
	public String getString(String key) {
		return (String)get(key);
	}
	
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return The String value of the specified key. If the key is not defined, the default value is returned instead.
	 */
	public String getString(String key, String defaultValue) {
		return (String)get(key) == null ? defaultValue : (String)get(key);
	}
	
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return The String[] value of the specified key.
	 */
	public String[] getStringArray(String key) {
		return (String[])get(key);
	}
	
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return The value of the specified key, returned generically as an Object. 
	 */
	public Object getObject(String key) {
		return get(key);
	}	

	/* (non-Javadoc)
	 * @see org.owasp.esapi.reference.accesscontrol.policyloader.PolicyParameters#set(java.lang.String, java.lang.Object)
	 */
	public void set(String key, Object value) throws IllegalArgumentException {
		policyProperties.set(key, value);
	}
	/* (non-Javadoc)
	 * @see org.owasp.esapi.reference.accesscontrol.policyloader.PolicyParameters#put(java.lang.String, java.lang.Object)
	 */
	public void put(String key, Object value) throws IllegalArgumentException {
		set(key, value);
	}
	
	/**
	 * This makes the map itself read only, but the mutability of objects 
	 * that this map contains is not affected. Specifically, properties 
	 * cannot be added or removed and the reference cannot be changed to 
	 * a different object, but this does not change whether the values that the 
	 * object contains can be changed. 
	 */
	public void lock() {
		policyProperties.setRestricted(true);
	}
	
	public String toString() {
		StringBuilder sb = new StringBuilder();
		Iterator keys = policyProperties.getMap().keySet().iterator();
		String currentKey;
		while(keys.hasNext()) {
			currentKey = (String)keys.next();
			sb.append(currentKey);
			sb.append("=");
			sb.append(policyProperties.get(currentKey));
			if(keys.hasNext()) {
				sb.append(",");
			}
		}
		return sb.toString();
	}
}
