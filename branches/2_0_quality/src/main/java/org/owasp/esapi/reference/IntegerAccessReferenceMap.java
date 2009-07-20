/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi.reference;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

import org.owasp.esapi.AccessReferenceMap;
import org.owasp.esapi.errors.AccessControlException;

/**
 * Reference implementation of the AccessReferenceMap interface. This
 * implementation generates integers for indirect references.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 * @since June 1, 2007
 * @see org.owasp.esapi.AccessReferenceMap
 */
public class IntegerAccessReferenceMap implements AccessReferenceMap {

	private static final long serialVersionUID = 5311769278372489771L;

	/** The itod (indirect to direct) */
	HashMap itod = new HashMap();

	/** The dtoi (direct to indirect) */
	HashMap dtoi = new HashMap();

	int count = 1;
	
	/**
	 * This AccessReferenceMap implementation uses integers to
	 * create a layer of indirection.
	 */
	public IntegerAccessReferenceMap() {
		// call update to set up the references
	}

	/**
	 * Instantiates a new access reference map with a set of direct references.
	 * 
	 * @param directReferences
	 *            the direct references
	 */
	public IntegerAccessReferenceMap(Set directReferences) {
		update(directReferences);
	}

	/**
	* {@inheritDoc}
	*/
	public Iterator iterator() {
		TreeSet sorted = new TreeSet(dtoi.keySet());
		return sorted.iterator();
	}
	
	/**
	* {@inheritDoc}
	*/
	public String addDirectReference(Object direct) {
		if ( dtoi.keySet().contains( direct ) ) {
			return (String)dtoi.get( direct );
		}
		String indirect = getUniqueReference();
		itod.put(indirect, direct);
		dtoi.put(direct, indirect);
		return indirect;
	}
	
	/**
	 * Returns a reference guaranteed to be unique.
	 * 
	 * @return 
	 * 		a unique reference 
	 */
	private synchronized String getUniqueReference() {
		return "" + count++;  // returns a string version of the counter
	}
	
	/**
	* {@inheritDoc}
	*/
	public String removeDirectReference(Object direct) throws AccessControlException {
		String indirect = (String)dtoi.get(direct);
		if ( indirect != null ) {
			itod.remove(indirect);
			dtoi.remove(direct);
		}
		return indirect;
	}

	/**
	* {@inheritDoc}
	*/
	final public void update(Set directReferences) {
		HashMap dtoi_old = (HashMap) dtoi.clone();
		dtoi.clear();
		itod.clear();

		Iterator i = directReferences.iterator();
		while (i.hasNext()) {
			Object direct = i.next();

			// get the old indirect reference
			String indirect = (String) dtoi_old.get(direct);

			// if the old reference is null, then create a new one that doesn't
			// collide with any existing indirect references
			if (indirect == null) {
				indirect = getUniqueReference();
			}
			itod.put(indirect, direct);
			dtoi.put(direct, indirect);
		}
	}

	/**
	* {@inheritDoc}
	*/
	public String getIndirectReference(Object directReference) {
		return (String) dtoi.get(directReference);
	}

	/**
	* {@inheritDoc}
	*/
	public Object getDirectReference(String indirectReference) throws AccessControlException {
		if (itod.containsKey(indirectReference)) {
			return itod.get(indirectReference);
		}
		throw new AccessControlException("Access denied", "Request for invalid indirect reference: " + indirectReference);
	}
}
