package org.owasp.esapi.reference.accesscontrol;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Date;

import org.apache.commons.beanutils.*;
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
	 * @return
	 */
	public boolean getBoolean(String key) {
		return ((Boolean)get(key)).booleanValue();
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return
	 */
	public byte getByte(String key) {
		return ((Byte)get(key)).byteValue();
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return
	 */
	public char getChar(String key) {
		return ((Character)get(key)).charValue();
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return
	 */
	public int getInt(String key) {
		return ((Integer)get(key)).intValue();
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return
	 */
	public long getLong(String key) {
		return ((Long)get(key)).longValue();
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return
	 */
	public float getFloat(String key) {
		return ((Float)get(key)).floatValue();
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return
	 */
	public double getDouble(String key) {
		return ((Double)get(key)).doubleValue();
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return
	 */
	public BigDecimal getBigDecimal(String key) {
		return (BigDecimal)get(key);
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return
	 */
	public BigInteger getBigInteger(String key) {
		return (BigInteger)get(key);
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return
	 */
	public Date getDate(String key) {
		return (Date)get(key);
	}
	
	/**
	 * Convenience method to avoid common casts. Note that the time object
	 * is the same as a date object
	 * @param key
	 * @return
	 */
	public Date getTime(String key) {
		return (Date)get(key);
	}
	
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return
	 */
	public String getString(String key) {
		return (String)get(key);
	}
	/**
	 * Convenience method to avoid common casts.
	 * @param key
	 * @return
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
	
}
