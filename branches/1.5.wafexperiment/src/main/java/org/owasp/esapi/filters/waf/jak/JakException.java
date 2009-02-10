/*
 * OWASP ESAPI WAF
 *
 * JAK 1.0
 * Copyright (c) 2004-2005 Ivan Ristic <ivanr@webkreator.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

package org.owasp.esapi.filters.waf.jak;

/**
 * This exception is used to carry the information about
 * the location of the problem around - the name of the
 * source and the line number.
 *
 */
public class JakException extends Exception {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	Directive directive = null;

    public JakException(String m) {
        super(m);
    }

    public JakException(String m, Directive d) {
        super(m);
        directive = d;
    }

    public JakException(String m, Exception e) {
        super(m, e);
    }

    public JakException(String m, Exception e, Directive d) {
        super(m, e);
        directive = d;
    }

    public String getSource() {
        if (directive != null)
            return directive.getSource();
        else
            return null;
    }

    public int getLineNumber() {
        if (directive != null)
            return directive.getLineNumber();
        else
            return -1;
    }

    public String getMessage() {
        if (directive != null) {
            return super.getMessage()
                + " [source "
                + getSource()
                + ", line "
                + getLineNumber()
                + "]";
        } else {
            return super.getMessage();
        }
    }
}