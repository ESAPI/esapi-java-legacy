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

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.EncoderConstants;

import java.util.Set;

/**
 * Reference implementation of the AccessReferenceMap interface. This
 * implementation generates random 6 character alphanumeric strings for indirect
 * references. It is possible to use simple integers as indirect references, but
 * the random string approach provides a certain level of protection from CSRF
 * attacks, because an attacker would have difficulty guessing the indirect
 * reference.
 *
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 * @author Chris Schmidt (chrisisbeef@gmail.com)
 * @see org.owasp.esapi.AccessReferenceMap
 * @since June 1, 2007
 */
public class RandomAccessReferenceMap extends AbstractAccessReferenceMap<String>
{

   private static final long serialVersionUID = 8544133840739803001L;

   public RandomAccessReferenceMap(int initialSize)
   {
      super(initialSize);
   }

   /**
    * This AccessReferenceMap implementation uses short random strings to
    * create a layer of indirection. Other possible implementations would use
    * simple integers as indirect references.
    */
   public RandomAccessReferenceMap()
   {
      // call update to set up the references
   }

   public RandomAccessReferenceMap(Set<Object> directReferences)
   {
      super(directReferences, directReferences.size());
   }

   public RandomAccessReferenceMap(Set<Object> directReferences, int initialSize)
   {
      super(directReferences, initialSize);
   }

   /**
    * {@inheritDoc}
    */
   protected synchronized String getUniqueReference()
   {
      String candidate;
      do
      {
         candidate = ESAPI.randomizer().getRandomString(6, EncoderConstants.CHAR_ALPHANUMERICS);
      }
      while (itod.keySet().contains(candidate));
      return candidate;
   }
}
