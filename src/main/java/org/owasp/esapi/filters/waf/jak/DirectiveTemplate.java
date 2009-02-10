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
 * DirectiveTemplate describes a configuration directive. It provides
 * the name, type and handler.
 *
 */
public class DirectiveTemplate {
    public final static int NO_ARGS = 0;
    public final static int TAKE1 = 1;
    public final static int TAKE2 = 2;
    public final static int TAKE3 = 3;
    public final static int TAKE12 = 4;
    public final static int TAKE23 = 5;
    public final static int FLAG = 6;
    public final static int ITERATE = 7;
    public final static int ITERATE2 = 8;
    public final static int RAW_ARGS = 9;

    private String name;

    private int argType;

    private DirectiveHandler handler;

	/**
	 * Creates a new directive template from the name, argument type and
	 * the handler.
	 *
	 * @param name
	 * @param argType
	 * @param handler
	 */
    public DirectiveTemplate(String name, int argType, DirectiveHandler handler) {
        this.name = name;
        this.argType = argType;
        this.handler = handler;
    }

	/**
	 * Verifies the directive arguments against the type specified
	 * in the template.
	 *
	 * @param d
	 * @throws JakException
	 */
    public void verifyArguments(Directive d) throws JakException {
        int tokenCount = d.getTokenCount();

        switch (argType) {
            case NO_ARGS :
                if (tokenCount != 0) {
                    throw new JakException("Expected no arguments for " + name + " but got " + tokenCount, d);
                }
                break;
            case TAKE1 :
                if (tokenCount != 1) {
                    throw new JakException("Expected one argument for " + name + " but got " + tokenCount, d);
                }
                break;
            case TAKE2 :
                if (tokenCount != 2) {
                    throw new JakException("Expected two arguments for " + name + " but got " + tokenCount, d);
                }
                break;
            case TAKE3 :
                if (tokenCount != 3) {
                    throw new JakException("Expected three arguments for " + name + " but got " + tokenCount, d);
                }
                break;
            case TAKE12 :
                if ((tokenCount != 1) && (tokenCount != 2)) {
                    throw new JakException("Expected one or two arguments for " + name + " but got " + tokenCount, d);
                }
                break;
            case TAKE23 :
                if ((tokenCount != 2) && (tokenCount != 3)) {
                    throw new JakException("Expected two or arguments for " + name + " but got " + tokenCount, d);
                }
                break;
            case FLAG :
            	if (tokenCount != 1) {
            		throw new JakException("Expected one parameters for " + name + " but got " + tokenCount, d);
            	}
            	if ((d.getToken(1).compareToIgnoreCase("on") != 0)&&(d.getToken(1).compareToIgnoreCase("off") != 0)) {
            		throw new JakException("Invalid value for a FLAG argument", d);
            	}
                break;
            case ITERATE :
            	if (tokenCount < 1) {
            		throw new JakException("One or more parameters required for " + name, d);
            	}
                break;
            case ITERATE2 :
            	if (tokenCount < 2) {
            		throw new JakException("Two or more parameters required for " + name, d);
            	}
                break;
            case RAW_ARGS :
            	// do nothing
                break;
        }
    }

    public int getArgType() {
        return argType;
    }

    public DirectiveHandler getHandler() {
        return handler;
    }

    public String getName() {
        return name;
    }

    public void setArgType(int i) {
        argType = i;
    }

    public void setHandler(DirectiveHandler handler) {
        this.handler = handler;
    }

    public void setName(String string) {
        name = string;
    }
}
