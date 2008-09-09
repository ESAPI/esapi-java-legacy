/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/esapi.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the LGPL. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.interfaces.IRandomizer;

/**
 * Reference implementation of the IAccessReferenceMap interface. This
 * implementation generates random 6 character alphanumeric strings for indirect
 * references. It is possible to use simple integers as indirect references, but
 * the random string approach provides a certain level of protection from CSRF
 * attacks, because an attacker would have difficulty guessing the indirect
 * reference.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 * @since June 1, 2007
 * @see org.owasp.esapi.interfaces.IAccessReferenceMap
 */
public class AccessReferenceMap implements org.owasp.esapi.interfaces.IAccessReferenceMap {

	/** The itod. */
	HashMap itod = new HashMap();

	/** The dtoi. */
	HashMap dtoi = new HashMap();

	/** The random. */
	IRandomizer random = ESAPI.randomizer();

	/**
	 * This AccessReferenceMap implementation uses short random strings to
	 * create a layer of indirection. Other possible implementations would use
	 * simple integers as indirect references.
	 */
	public AccessReferenceMap() {
		// call update to set up the references
	}

	/**
	 * Instantiates a new access reference map.
	 * 
	 * @param directReferences
	 *            the direct references
	 */
	public AccessReferenceMap(Set directReferences) {
		update(directReferences);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IAccessReferenceMap#iterator()
	 */
	public Iterator iterator() {
		TreeSet sorted = new TreeSet(dtoi.keySet());
		return sorted.iterator();
	}
	
	/**
	 * Adds a direct reference and a new random indirect reference, overwriting any existing values.
	 * @param direct
	 */
	public void addDirectReference(String direct) {
		String indirect = random.getRandomString(6, Encoder.CHAR_ALPHANUMERICS);
		itod.put(indirect, direct);
		dtoi.put(direct, indirect);
	}
	
	
	// FIXME: add addDirectRef and removeDirectRef to IAccessReferenceMap
	// FIXME: add test code for add/remove direct ref
	
	/**
	 * Remove a direct reference and the corresponding indirect reference.
	 * @param direct
	 */
	public void removeDirectReference(String direct) throws AccessControlException {
		String indirect = (String)dtoi.get(direct);
		if ( indirect != null ) {
			itod.remove(indirect);
			dtoi.remove(direct);
		}
	}

	/*
	 * This preserves any existing mappings for items that are still in the new
	 * list. You could regenerate new indirect references every time, but that
	 * might mess up anything that previously used an indirect reference, such
	 * as a URL parameter.
	 */
	/**
	 * Update.
	 * 
	 * @param directReferences
	 *            the direct references
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
				do {
					indirect = random.getRandomString(6, Encoder.CHAR_ALPHANUMERICS);
				} while (itod.keySet().contains(indirect));
			}
			itod.put(indirect, direct);
			dtoi.put(direct, indirect);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IAccessReferenceMap#getIndirectReference(java.lang.String)
	 */
	public String getIndirectReference(Object directReference) {
		return (String) dtoi.get(directReference);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IAccessReferenceMap#getDirectReference(java.lang.String)
	 */
	public Object getDirectReference(String indirectReference) throws AccessControlException {
		if (itod.containsKey(indirectReference)) {
			return itod.get(indirectReference);
		}
		throw new AccessControlException("Access denied", "Request for invalid indirect reference: " + indirectReference);
	}
}
