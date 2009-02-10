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
import org.owasp.esapi.filters.waf.jak.*;

public class FileAuditLog implements JakModule, DirectiveHandler, Inspector {

    private ModSecurity config;

    private String auditLog;

    private boolean auditEngine = false;

    private PrintStream ps;

    public void handleDirective(Configuration config, Directive directive)
            throws JakException {

        if (directive.getName().compareTo("SecAuditEngine") == 0) {
            auditEngine = directive.getBooleanToken(1);
        }
        else if (directive.getName().compareTo("SecAuditLog") == 0) {
            auditLog = directive.getToken(1);
            auditLog = this.config.getFilterConfig().getServletContext().getRealPath(auditLog);
        } else {
            throw new JakException("Module FileAuditLog: don't know how to handle directive " + directive.getName());
        }
    }

    public void init(Configuration config) throws Exception {
        this.config = (ModSecurity)config;
        config.registerDirectiveTemplate("SecAuditEngine", DirectiveTemplate.FLAG, this);
        config.registerDirectiveTemplate("SecAuditLog", DirectiveTemplate.TAKE1, this);
    }

    public void postInit() {}

	public void start() throws Exception {
	    if (auditLog != null) {
	        ps = new PrintStream(new FileOutputStream(auditLog, true));
	    }
	}

	public void stop() {
	    if (ps != null) {
	        ps.close();
	        ps = null;
	    }
	}

	public void destroy() {}

	public int inspect(int phase, HttpTransaction tran) {
	    if (phase != Inspector.LOGGING) return Inspector.ACTION_NONE;
	    ps.println(tran.req.getRequestURI());
	    return Inspector.ACTION_NONE;
	}
}