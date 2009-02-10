/*
 * OWASP ESAPI WAF
 *
 * ModSecurity for Java M3 (Milestone 3)
 * Copyright (c) 2004-2005 Ivan Ristic <ivanr@webkreator.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
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

package org.owasp.esapi.filters.waf;

import java.io.IOException;

public interface Inspector {
    public static final int PRE_REQUEST = 1;
    public static final int REQUEST_HEADERS = 2;
    public static final int REQUEST_BODY = 3;
    public static final int RESPONSE_HEADERS = 4;
    public static final int RESPONSE_BODY = 5;
    public static final int LOGGING = 6;

    public static final int ACTION_NONE = 0;
    public static final int ACTION_STOP = 1;
    public static final int ACTION_ALLOW = 2;
    public static final int ACTION_ALLOW_REQUEST = 3;
    public static final int ACTION_WARN = 4;

    public int inspect(int phase, HttpTransaction tran) throws IOException, Exception;
}