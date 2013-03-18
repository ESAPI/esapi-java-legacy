package org.owasp.esapi.contrib.spring.util;

import java.util.Date;

public class DateUtils {

    private DateUtils() {
    }

    /**
     * Returns true if the input date is in the past. Note that this method will
     * return false if a null input is passed.
     *
     * @param aDate The date to check
     * @return boolean True if the date is in the past
     */
    public static boolean isDatePast(Date aDate) {
        if (aDate == null)
            return false;

        Date nowDate = new Date();
        return nowDate.after(aDate);
    }

    /**
     * Returns true if the input date is in the future. Note that this method
     * will return false if a null input is passed.
     *
     * @param aDate The date to check
     * @return boolean True if the date is in the future
     */
    public static boolean isDateFuture(Date aDate) {
        if (aDate == null)
            return false;

        Date nowDate = new Date();
        return nowDate.before(aDate);
    }
}
