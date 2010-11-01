package org.owasp.esapi.reference.accesscontrol.policyloader;

public interface PolicyParameters {

	/**
	 * Follows the contract for java.util.Map;
	 * @param key
	 * @return
	 * @see java.util.Map
	 */
	public abstract Object get(String key);

	/**
	 * This works just like a Map, except it will throw an exception if lock()
	 * has been called. 
	 * @param key
	 * @param value
	 * @throws IllegalArgumentException if this DynaBeanACRParameter instance 
	 * has already been locked.
	 */
	public abstract void set(String key, Object value)
			throws IllegalArgumentException;

	/**
	 * This is a convenience method for developers that prefer to think of this
	 * as a map instead of being bean-like. 
	 * 
	 * @see set(String, Object)
	 */
	public abstract void put(String key, Object value)
			throws IllegalArgumentException;

	/**
	 * This makes the map itself read only, but the mutability of objects 
	 * that this map contains is not affected. Specifically, properties 
	 * cannot be added or removed and the reference cannot be changed to 
	 * a different object, but this does not change whether the values that the 
	 * object contains can be changed.
	 */
	public abstract void lock();
	
}