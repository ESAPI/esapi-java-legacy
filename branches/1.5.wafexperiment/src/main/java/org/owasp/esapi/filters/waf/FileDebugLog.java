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
import java.io.*;
import java.util.*;
import java.text.*;
import org.owasp.esapi.filters.waf.jak.*;

public class FileDebugLog implements JakModule, DirectiveHandler, DebugLog {

    private ModSecurity config;

    private String debugLog;

    private int debugLevel = 0;

    private PrintStream ps;

    public void handleDirective(Configuration config, Directive directive)
            throws JakException {

        if (directive.getName().compareTo("SecFilterDebugLog") == 0) {
            debugLog = directive.getToken(1);
            debugLog = this.config.getFilterConfig().getServletContext().getRealPath(debugLog);
        }
        else if (directive.getName().compareTo("SecFilterDebugLevel") == 0) {
            debugLevel = directive.getIntegerToken(1);
        } else {
            throw new JakException("Module FileDebugLog: don't know how to handle directive " + directive.getName());
        }
    }

    public void init(Configuration config) throws Exception {
        this.config = (ModSecurity)config;
        config.registerDirectiveTemplate("SecFilterDebugLog", DirectiveTemplate.TAKE1, this);
        config.registerDirectiveTemplate("SecFilterDebugLevel", DirectiveTemplate.TAKE1, this);
    }

	public void postInit() {}

	public void start() throws Exception {
	    if (debugLog != null) {
	        ps = new PrintStream(new FileOutputStream(debugLog, true));
	    }
	}

	public void stop() {
	    if (ps != null) {
	        ps.close();
	        ps = null;
	    }
	}

	public void destroy() {}

	public void log(int level, String msg, HttpTransaction tran) {
	    if ((debugLevel >= level)&&(ps != null)) {
	        SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy:HH:mm:ss z");
	        StringBuffer sb = new StringBuffer();
	        sb.append("[");
	        sb.append(sdf.format(new Date()));
	        sb.append("]");
	        sb.append("[" + level + "]");

            if (tran != null) {
                sb.append("[");
                sb.append(tran.msReq.getServletPath());
                sb.append("]");
            }

            sb.append(" " + msg);
            String message = sb.toString();
	        ps.println(message);
	    }
	}
}