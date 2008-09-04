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
package org.owasp.esapi;

import java.util.Iterator;
import java.util.Set;

import org.owasp.esapi.errors.AccessControlException;


/**
 * The AccessReferenceMap interface is used to map from a set of internal
 * direct object references to a set of indirect references that are safe to
 * disclose publicly. This can be used to help protect database keys,
 * filenames, and other types of direct object references. As a rule, developers
 * should not expose their direct object references as it enables attackers to
 * attempt to manipulate them.
 * <P>
 * <img src="doc-files/AccessReferenceMap.jpg" height="600">
 * <P>
 * <P>
 * Indirect references are handled as strings, to facilitate their use in HTML.
 * Implementations can generate simple integers or more complicated random
 * character strings as indirect references. Implementations should probably add
 * a constructor that takes a list of direct references.
 * <P>
 * Note that in addition to defeating all forms of parameter tampering attacks,
 * there is a side benefit of the AccessReferenceMap. Using random strings as indirect object
 * references, as opposed to simple integers makes it impossible for an attacker to
 * guess valid identifiers. So if per-user AccessReferenceMaps are used, then request
 * forgery (CSRF) attacks will also be prevented.
 * 
 * <pre>
 * Set fileSet = new HashSet();
 * fileSet.addAll(...); // add direct references (e.g. File objects)
 * AccessReferenceMap map = new AccessReferenceMap( fileSet );
 * // store the map somewhere safe - like the session!
 * String indRef = map.getIndirectReference( file1 );
 * String href = &quot;http://www.aspectsecurity.com/esapi?file=&quot; + indRef );
 * ...
 * // if the indirect reference doesn't exist, it's likely an attack
 * // getDirectReference throws an AccessControlException
 * // you should handle as appropriate
 * String indref = request.getParameter( &quot;file&quot; );
 * File file = (File)map.getDirectReference( indref );
 * </pre>
 * 
 * <P>
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public interface AccessReferenceMap {

	/**
	 * Get an iterator through the direct object references. No guarantee is made as 
	 * to the order of items returned.
	 * 
	 * @return the iterator
	 */
	Iterator iterator();

	/**
	 * Get a safe indirect reference to use in place of a potentially sensitive
	 * direct object reference. Developers should use this call when building
	 * URL's, form fields, hidden fields, etc... to help protect their private
	 * implementation information.
	 * 
	 * @param directReference
	 *            the direct reference
	 * 
	 * @return the indirect reference
	 */
	String getIndirectReference(Object directReference);

	/**
	 * Get the original direct object reference from an indirect reference.
	 * Developers should use this when they get an indirect reference from a
	 * request to translate it back into the real direct reference. If an
	 * invalid indirectReference is requested, then an AccessControlException is
	 * thrown.
	 * 
	 * @param indirectReference
	 *            the indirect reference
	 * 
	 * @return the direct reference
	 * 
	 * @throws AccessControlException if no direct reference exists for the 
	 * 				specified indirect reference
	 */
	Object getDirectReference(String indirectReference) throws AccessControlException;

	/**
	 * Adds a direct reference to the AccessReferenceMap and generates an associated indirect reference. 
	 * @param direct 
	 * 		the direct reference
	 * 
	 * @return the corresponding indirect reference
	 */
	String addDirectReference(Object direct);
	
	/**
	 * Removes a direct reference and its associated indirect reference from the AccessReferenceMap.
	 * @param direct 
	 * 		the direct reference to remove
	 * 
	 * @return the corresponding indirect reference
	 * 
	 * @throws AccessControlException
	 */
	String removeDirectReference(Object direct) throws AccessControlException;

	/**
	 * Updates the access reference map with a new set of directReferences, maintaining
	 * any existing indirectReferences associated with items that are in the new list. 
	 * @param directReferences
	 */
	void update(Set directReferences);

}
