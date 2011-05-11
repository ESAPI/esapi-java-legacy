package org.owasp.esapi.contrib.spring.authenticator.util;

import junit.framework.Assert;
import org.junit.Test;
import org.owasp.esapi.contrib.spring.util.DateUtils;

import java.util.Date;

public class TestDateUtils {
    private static final long FIVE_MINS = 1000L * 60 * 5;

    @Test
    public void testFutureDate() {
        Date futureDate = new Date(System.currentTimeMillis() + FIVE_MINS);
        Date pastDate = new Date(System.currentTimeMillis() - FIVE_MINS);
        Assert.assertTrue(DateUtils.isDateFuture(futureDate));
        Assert.assertFalse(DateUtils.isDateFuture(pastDate));
        Assert.assertFalse(DateUtils.isDateFuture(null));
    }

    @Test
    public void testPastDate() {
        Date futureDate = new Date(System.currentTimeMillis() + FIVE_MINS);
        Date pastDate = new Date(System.currentTimeMillis() - FIVE_MINS);
        Assert.assertFalse(DateUtils.isDatePast(futureDate));
        Assert.assertTrue(DateUtils.isDatePast(pastDate));
        Assert.assertFalse(DateUtils.isDatePast(null));
    }
}
