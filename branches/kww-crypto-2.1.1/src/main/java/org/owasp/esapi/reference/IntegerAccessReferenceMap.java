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

import java.util.Set;

/**
 * Reference implementation of the AccessReferenceMap interface. This
 * implementation generates integers for indirect references.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 * @author Chris Schmidt (chrisisbeef@gmail.com)
 * @since June 1, 2007
 * @see org.owasp.esapi.AccessReferenceMap
 */
public class IntegerAccessReferenceMap extends AbstractAccessReferenceMap<String> {

	private static final long serialVersionUID = 5311769278372489771L;

	int count = 1;

	/**
	 * TODO Javadoc
	 */
	public IntegerAccessReferenceMap()
	{
	}

	/**
	 * TODO Javadoc
	 */
	public IntegerAccessReferenceMap(int initialSize)
	{
		super(initialSize);
	}

	/**
	 * TODO Javadoc
	 */
	public IntegerAccessReferenceMap(Set<Object> directReferences)
	{
		super(directReferences.size());
		update(directReferences);
	}

	/**
	 * TODO Javadoc
	 */
	public IntegerAccessReferenceMap(Set<Object> directReferences, int initialSize)
	{
		super(initialSize);
		update(directReferences);
	}

	/**
	 * TODO Javadoc
	 * Note: this is final as redefinition by subclasses
	 * can lead to use before initialization issues as
	 * {@link #RandomAccessReferenceMap(Set)} and
	 * {@link #RandomAccessReferenceMap(Set,int)} both call it
	 * internally.
	 */
	protected final synchronized String getUniqueReference() {
		return "" + count++;  // returns a string version of the counter
	}

}
