package org.owasp.esapi.reference;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.powermock.reflect.Whitebox;


public class AbstractAccessReferenceMapTest {

    @Test
    public void testConcurrentAddDirectReference() throws Exception {
        @SuppressWarnings("unchecked")
        final AbstractAccessReferenceMap<Object> map = Mockito.mock(AbstractAccessReferenceMap.class, Mockito.withSettings().useConstructor()
                .defaultAnswer(Mockito.CALLS_REAL_METHODS)
                );
        Object indirectObj = new Object();
        Mockito.when(map.getUniqueReference()).thenReturn(indirectObj);

        final HashMap<?,?> itod= Whitebox.getInternalState(map, "itod");

        final Object toAdd = new Object();

        Runnable addReference1 = new Runnable() {
            @Override
            public void run() {
                map.addDirectReference(toAdd);
            }
        };
        Runnable addReference2 = new Runnable() {
            @Override
            public void run() {
                map.addDirectReference(toAdd);
            }
        };

        Runnable lockItod = new Runnable() {
            public void run() {
                synchronized (itod) {
                    try {
                        Thread.sleep(2000);
                    } catch (InterruptedException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }

                } 
            }
        };

        Thread lockIndirectRefs = new Thread(lockItod, "Lock Indirect Refs");
        Thread addRef1Thread = new Thread(addReference1, "Add Ref 1");
        Thread addRef2Thread = new Thread(addReference2, "Add Ref 2");
        lockIndirectRefs.start();
        addRef1Thread.start();
        addRef2Thread.start();

        addRef1Thread.join();
        addRef2Thread.join();
        lockIndirectRefs.join();

        Mockito.verify(map,Mockito.times(1)).getUniqueReference();
    }
    
    @Test
    public void verifyNoDuplicateKeysOnUpdateReplace() {
        @SuppressWarnings("unchecked")
        final AbstractAccessReferenceMap<Object> map = Mockito.mock(AbstractAccessReferenceMap.class, Mockito.withSettings().useConstructor()
                .defaultAnswer(Mockito.CALLS_REAL_METHODS)
                );
        Object indirectObj1 = new Object();
        Object indirectObj2 = new Object();
        Mockito.when(map.getUniqueReference()).thenReturn(indirectObj1); 
        
        Object direct1 = new Object();
        Object direct2 = new Object();
        
        map.addDirectReference(direct1);
        
        Mockito.reset(map);
        
        Set<Object> newDirectElements = new HashSet<>();
        newDirectElements.add(direct2);
        newDirectElements.add(direct1);
        
        Mockito.when(map.getUniqueReference()).thenReturn(indirectObj1).thenReturn(indirectObj2); 
        
        map.update(newDirectElements);
        
        //Needs to be called 2 times to get past the first duplicate key. This verifies that we're inserting unique pairs.
        Mockito.verify(map, Mockito.times(2)).getUniqueReference();
        
        Assert.assertEquals(indirectObj1, map.getIndirectReference(direct1));
        Assert.assertEquals(indirectObj2, map.getIndirectReference(direct2));
    }
}
