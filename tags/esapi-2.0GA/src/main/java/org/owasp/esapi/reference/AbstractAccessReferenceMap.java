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

import org.owasp.esapi.AccessReferenceMap;
import org.owasp.esapi.errors.AccessControlException;

import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Abstract Implementation of the AccessReferenceMap that is backed by ConcurrentHashMaps to
 * provide a thread-safe implementation of the AccessReferenceMap. Implementations of this
 * abstract class should implement the #getUniqueReference() method.
 *
 * @author  Chris Schmidt (chrisisbeef@gmail.com)
 * @since   July 21, 2009
 */
public abstract class AbstractAccessReferenceMap<K> implements AccessReferenceMap<K>
{
   private static final long serialVersionUID = 238742764284682230L;

   /** The Indirect to Direct Map */
   protected Map<K,Object> itod;
   /** The Direct to Indirect Map */
   protected Map<Object,K> dtoi;

   /**
    * Instantiates a new access reference map. Note that this will create the underlying Maps with an initialSize
    * of {@link ConcurrentHashMap#DEFAULT_INITIAL_CAPACITY} and that resizing a Map is an expensive process. Consider
    * using a constructor where the initialSize is passed in to maximize performance of the AccessReferenceMap.
    *
    * @see #AbstractAccessReferenceMap(java.util.Set, int)
    * @see #AbstractAccessReferenceMap(int)
    */
   public AbstractAccessReferenceMap() {
      itod = new ConcurrentHashMap<K, Object>();
      dtoi = new ConcurrentHashMap<Object,K>();
   }

   /**
    * Instantiates a new access reference map with the specified size allotment
    * to reduce Map resizing overhead.
    *
    * @param initialSize
    *          The initial size of the underlying maps
    */
   public AbstractAccessReferenceMap( int initialSize ) {
      itod = new ConcurrentHashMap<K, Object>(initialSize);
      dtoi = new ConcurrentHashMap<Object,K>(initialSize);
   }

   /**
    * Instantiates a new access reference map with a set of direct references.
    *
    * @param directReferences
    *            the direct references
    * @deprecated This constructor internally calls the abstract method
    *	{@link #getUniqueReference()}. Since this is a constructor, any
    *	subclass that implements getUniqueReference() has not had it's
    *	own constructor run. This leads to strange bugs because subclass
    *	internal state is initializaed after calls to getUniqueReference()
    *	have already happened. If this constructor is desired in a
    *	subclass, consider running {@link #update(Set)} in the subclass
    *	constructor instead.
    */
   @Deprecated
   public AbstractAccessReferenceMap( Set<Object> directReferences ) {
      itod = new ConcurrentHashMap<K, Object>(directReferences.size());
      dtoi = new ConcurrentHashMap<Object,K>(directReferences.size());
      update(directReferences);
   }

   /**
    * Instantiates a new access reference map with the specified size allotment
    * and initializes the map with the passed in references. Note that if you pass
    * in an initialSize that is less than the size of the passed in set, the map will
    * need to be resized while it is being loaded with the references so it is
    * best practice to verify that the size being passed in is always larger than
    * the size of the set that is being passed in.
    *
    * @param directReferences
    *          The references to initialize the access reference map
    * @param initialSize
    *          The initial size to set the map to.
    *
    * @deprecated This constructor internally calls the abstract method
    *	{@link #getUniqueReference()}. Since this is a constructor, any
    *	subclass that implements getUniqueReference() has not had it's
    *	own constructor run. This leads to strange bugs because subclass
    *	internal state is initializaed after calls to getUniqueReference()
    *	have already happened. If this constructor is desired in a
    *	subclass, consider running {@link #update(Set)} in the subclass
    *	constructor instead.
    */
   @Deprecated
   public AbstractAccessReferenceMap( Set<Object> directReferences, int initialSize ) {
      itod = new ConcurrentHashMap<K, Object>(initialSize);
      dtoi = new ConcurrentHashMap<Object,K>(initialSize);
      update(directReferences);
   }

   /**
    * Returns a Unique Reference Key to be associated with a new directReference being
    * inserted into the AccessReferenceMap.
    *
    * @return Reference Identifier
    */
   protected abstract K getUniqueReference();

   /**
   * {@inheritDoc}
   */
   public synchronized Iterator iterator() {
      TreeSet sorted = new TreeSet(dtoi.keySet());
      return sorted.iterator();
   }

   /**
   * {@inheritDoc}
   */
   public <T> K addDirectReference(T direct) {
      if ( dtoi.keySet().contains( direct ) ) {
         return dtoi.get( direct );
      }
      K indirect = getUniqueReference();
      itod.put(indirect, direct);
      dtoi.put(direct, indirect);
      return indirect;
   }

   /**
   * {@inheritDoc}
   */
   public <T> K removeDirectReference(T direct) throws AccessControlException
   {
      K indirect = dtoi.get(direct);
      if ( indirect != null ) {
         itod.remove(indirect);
         dtoi.remove(direct);
      }
      return indirect;
   }

   /**
   * {@inheritDoc}
   */
   public final synchronized void update(Set directReferences) {
      Map<Object,K> new_dtoi = new ConcurrentHashMap<Object,K>( directReferences.size() );
      Map<K,Object> new_itod = new ConcurrentHashMap<K,Object>( directReferences.size() );

      for ( Object o : directReferences ) {
         K indirect = dtoi.get( o );

         if ( indirect == null ) {
            indirect = getUniqueReference();
         }
         new_dtoi.put( o, indirect );
         new_itod.put( indirect, o );
      }
      dtoi = new_dtoi;
      itod = new_itod;
   }

   /**
   * {@inheritDoc}
   */
   public <T> K getIndirectReference(T directReference) {
      return dtoi.get(directReference);
   }

   /**
   * {@inheritDoc}
   */
   public <T> T getDirectReference(K indirectReference) throws AccessControlException {
      if (itod.containsKey(indirectReference) ) {
         try
         {
            return (T) itod.get(indirectReference);
         }
         catch (ClassCastException e)
         {
            throw new AccessControlException("Access denied.", "Request for incorrect type reference: " + indirectReference);
         }
      }
      throw new AccessControlException("Access denied", "Request for invalid indirect reference: " + indirectReference);
   }
}
