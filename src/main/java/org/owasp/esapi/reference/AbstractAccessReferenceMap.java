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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.owasp.esapi.AccessReferenceMap;
import org.owasp.esapi.errors.AccessControlException;

/**
 * Abstract Implementation of the AccessReferenceMap.
 * <br>
 * Implementation offers default synchronization on all public API 
 * to assist with thread safety.
 * <br>
 * For complex interactions spanning multiple calls, it is recommended 
 * to add a synchronized block around all invocations to maintain intended data integrity.
 * 
 * <pre>
 * public MyClassUsingAARM {
 *  private AbstractAccessReferenceMap<Object> aarm;
 * 
 *  public void replaceAARMDirect(Object oldDirect, Object newDirect) {
 *     synchronized (aarm) {
 *        aarm.removeDirectReference(oldDirect);
 *        aarm.addDirectReference(newDirect);
 *     }
 *  }
 * }
 * </pre>
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
    * of {@link HashMap#DEFAULT_INITIAL_CAPACITY} and that resizing a Map is an expensive process. Consider
    * using a constructor where the initialSize is passed in to maximize performance of the AccessReferenceMap.
    *
    * @see #AbstractAccessReferenceMap(java.util.Set, int)
    * @see #AbstractAccessReferenceMap(int)
    */
   public AbstractAccessReferenceMap() {
      itod = new HashMap<K, Object>();
      dtoi = new HashMap<Object,K>();
   }

   /**
    * Instantiates a new access reference map with the specified size allotment
    * to reduce Map resizing overhead.
    *
    * @param initialSize
    *          The initial size of the underlying maps
    */
   public AbstractAccessReferenceMap( int initialSize ) {
      itod = new HashMap<K, Object>(initialSize);
      dtoi = new HashMap<Object,K>(initialSize);
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
      itod = new HashMap<K, Object>(directReferences.size());
      dtoi = new HashMap<Object,K>(directReferences.size());
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
      itod = new HashMap<K, Object>(initialSize);
      dtoi = new HashMap<Object,K>(initialSize);
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
   public synchronized <T> K addDirectReference(T direct) {
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
   public synchronized <T> K removeDirectReference(T direct) throws AccessControlException
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
       Map<Object,K> new_dtoi = new HashMap<Object,K>( directReferences.size() );
       Map<K,Object> new_itod = new HashMap<K,Object>( directReferences.size() );
       
       Set<Object> newDirect = new HashSet<>(directReferences);
       Set<Object> dtoiCurrent = new HashSet<>(dtoi.keySet());

       //Preserve all keys that are in the new set
       dtoiCurrent.retainAll(newDirect);
       
       //Transfer existing values into the new map
       for (Object current: dtoiCurrent) {
           K idCurrent = dtoi.get(current);
           new_dtoi.put(current, idCurrent);
           new_itod.put(idCurrent, current);
       }
       
       //Trim the new map to only new values
       newDirect.removeAll(dtoiCurrent);
       
       //Add new values with new indirect keys to the new map
       for (Object newD : newDirect) {
           K idCurrent;
           do {
               idCurrent = getUniqueReference();
               //Unlikey, but just in case we generate the exact same key multiple times...
           } while (dtoi.containsValue(idCurrent));
           
           new_dtoi.put(newD, idCurrent);
           new_itod.put(idCurrent, newD);
       }
    
       dtoi = new_dtoi;
       itod = new_itod;
   }

   /**
   * {@inheritDoc}
   */
   public synchronized <T> K getIndirectReference(T directReference) {
      return dtoi.get(directReference);
   }

   /**
   * {@inheritDoc}
   */
   public synchronized <T> T getDirectReference(K indirectReference) throws AccessControlException {
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
