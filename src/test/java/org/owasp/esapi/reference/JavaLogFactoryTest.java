package org.owasp.esapi.reference;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;

import org.junit.Assert;
import org.junit.Test;
import org.owasp.esapi.Logger;


public class JavaLogFactoryTest {

    @Test
    public void testConcurrentLogRequest() throws InterruptedException {
        final ConcurrentHashMap<Integer, Logger> logCapture = new ConcurrentHashMap<>();
        List<Thread> threads = new ArrayList<>();
        final CountDownLatch forceConcurrency = new CountDownLatch(1);
        for (int x = 0 ; x < 10; x ++) {
            final int requestIndex = x;
            Runnable requestLogByClass = new Runnable() {
                @Override
                public void run() {
                   try {
                    forceConcurrency.await();
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                   logCapture.put(requestIndex, JavaLogFactory.getInstance().getLogger(JavaLogFactoryTest.class));
                }
            };
            
            Runnable requestLogByModule = new Runnable() {
                @Override
                public void run() {
                   try {
                    forceConcurrency.await();
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                   logCapture.put(requestIndex, JavaLogFactory.getInstance().getLogger(JavaLogFactoryTest.class.getName()));
                }
            };
            
            threads.add(new Thread(requestLogByClass, "Request Log By Class " + x));
            
            threads.add(new Thread(requestLogByModule, "Request Log By Name " + x));
            
            
        }
        
        for (Thread thread : threads) {
            thread.start();
        }
        
        forceConcurrency.countDown();
        
        for (Thread thread: threads) {
            thread.join();
        }
        
        
        Set<Logger> uniqueLoggers = new HashSet<>(logCapture.values());
        
        Assert.assertEquals(1, uniqueLoggers.size());
        
    }
}
