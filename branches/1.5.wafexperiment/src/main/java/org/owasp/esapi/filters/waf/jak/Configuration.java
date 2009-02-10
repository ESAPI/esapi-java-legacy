/*
 *
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

import java.io.IOException;

// TODO public String getHome()

/**
 * Main configuration interface. It supports methods to
 * manipulate directives, directive templates, and modules.
 *
 */
public interface Configuration {
	public void registerDirectiveTemplate(DirectiveTemplate directive);
	public void registerDirectiveTemplate(String name, int argType, DirectiveHandler handler);
	public DirectiveTemplate getDirectiveTemplate(String name);
	public DirectiveTemplate getDirectiveTemplate(Directive directive);

	public void registerModule(String moduleName, Object module) throws JakException ;
	public Object getModule(String moduleName);
	public Object getModule(Class c);
	public String getModuleName(Object module);
	public Object[] getModules(Class c);

	public Directive getNextDirective() throws IOException, JakException;
	public void processDirective(Directive d) throws IOException, JakException;

	void addProvider(DirectiveProvider provider) throws IOException, JakException;
	public void processConfiguration() throws IOException, JakException;

	public void doPostInit() throws Exception;
	public void doStart() throws Exception;
	public void doStop();
	public void doDestroy();
}
