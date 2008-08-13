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

import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Stack;
import java.util.WeakHashMap;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.User;
import org.owasp.esapi.SecurityConfiguration.Threshold;
import org.owasp.esapi.errors.EnterpriseSecurityException;
import org.owasp.esapi.errors.IntrusionException;

/**
 * Reference implementation of the IntrusionDetector interface. This
 * implementation monitors EnterpriseSecurityExceptions to see if any user
 * exceeds a configurable threshold in a configurable time period. For example,
 * it can monitor to see if a user exceeds 10 input validation issues in a 1
 * minute period. Or if there are more than 3 authentication problems in a 10
 * second period. More complex implementations are certainly possible, such as
 * one that establishes a baseline of expected behavior, and then detects
 * deviations from that baseline.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.IntrusionDetector
 */
public class DefaultIntrusionDetector implements org.owasp.esapi.IntrusionDetector {

	/** The logger. */
	private final Logger logger = ESAPI.getLogger("IntrusionDetector");

	private Map userEvents = new WeakHashMap();
	
	public DefaultIntrusionDetector() {
	}
	
	/**
	 * This implementation uses an exception store in each User object to track
	 * exceptions.
	 * 
	 * @param e
	 *            the e
	 * 
	 * @throws IntrusionException
	 *             the intrusion exception
	 * 
	 * @see org.owasp.esapi.IntrusionDetector#addException(org.owasp.esapi.errors.EnterpriseSecurityException)
	 */
	public void addException(Exception e) {
        if ( e instanceof EnterpriseSecurityException ) {
            logger.warning( Logger.SECURITY, ((EnterpriseSecurityException)e).getLogMessage(), e );
        } else {
            logger.warning( Logger.SECURITY, e.getMessage(), e );
        }

        // add the exception to the current user, which may trigger a detector 
		User user = ESAPI.authenticator().getCurrentUser();
        String eventName = e.getClass().getName();

        if ( e instanceof IntrusionException) {
            return;
        }
        
        // add the exception to the user's store, handle IntrusionException if thrown
		try {
			addSecurityEvent(user, eventName);
		} catch( IntrusionException ex ) {
            Threshold quota = ESAPI.securityConfiguration().getQuota(eventName);
            Iterator i = quota.actions.iterator();
            while ( i.hasNext() ) {
                String action = (String)i.next();
                String message = "User exceeded quota of " + quota.count + " per "+ quota.interval +" seconds for event " + eventName + ". Taking actions " + quota.actions;
                takeSecurityAction( action, message );
            }
		}
	}

    /**
     * Adds the event to the IntrusionDetector.
     * 
     * @param event the event
     * @param logMessage the message to log
     * @throws IntrusionException the intrusion exception
     */
    public void addEvent(String eventName, String logMessage) throws IntrusionException {
        logger.warning( Logger.SECURITY, "Security event " + eventName + " received : " + logMessage );

        // add the event to the current user, which may trigger a detector 
        User user = ESAPI.authenticator().getCurrentUser();
        try {
            addSecurityEvent(user, "event." + eventName);
        } catch( IntrusionException ex ) {
            Threshold quota = ESAPI.securityConfiguration().getQuota("event." + eventName);
            Iterator i = quota.actions.iterator();
            while ( i.hasNext() ) {
                String action = (String)i.next();
                String message = "User exceeded quota of " + quota.count + " per "+ quota.interval +" seconds for event " + eventName + ". Taking actions " + quota.actions;
                takeSecurityAction( action, message );
            }
        }
    }

    
    private void takeSecurityAction( String action, String message ) {
        if ( action.equals( "log" ) ) {
            logger.fatal( Logger.SECURITY, "INTRUSION - " + message );
        }
        User user = ESAPI.authenticator().getCurrentUser();
        if (user == User.ANONYMOUS)
        	return;
        if ( action.equals( "disable" ) ) {
            user.disable();
        }
        if ( action.equals( "logout" ) ) {
            user.logout();
        }
    }

	 /**
	 * Adds a security event to the user.
	 * 
	 * @param event the event
	 */
	private void addSecurityEvent(User user, String eventName) throws IntrusionException {
		Map events = (Map) userEvents.get(user.getAccountName());
		if (events == null) {
			events = new HashMap();
			userEvents.put(user.getAccountName(), events);
		}
		Event event = (Event)events.get( eventName );
		if ( event == null ) {
			event = new Event( eventName );
			events.put( eventName, event );
		}

		Threshold q = ESAPI.securityConfiguration().getQuota( eventName );
		if ( q.count > 0 ) {
			event.increment(q.count, q.interval);
		}
	}

    private static class Event {
        public String key;
        public Stack times = new Stack();
        public long count = 0;
        public Event( String key ) {
            this.key = key;
        }
        public void increment(int count, long interval) throws IntrusionException {
            Date now = new Date();
            times.add( 0, now );
            while ( times.size() > count ) times.remove( times.size()-1 );
            if ( times.size() == count ) {
                Date past = (Date)times.get( count-1 );
                long plong = past.getTime();
                long nlong = now.getTime(); 
                if ( nlong - plong < interval * 1000 ) {
                    throw new IntrusionException( "Threshold exceeded", "Exceeded threshold for " + key );
                }
            }
        }
    }
}
