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
 * This class represents a single configuration directive. Its
 * job is mainly to hold the data together, and to parse a line
 * of text into individual tokens.
 *
 */
public class Directive {

    private String text;

    private String source;

    private int lineNumber;

    private String name;

    private String tokens[];

    public Directive(String text, String source, int lineNumber) {
        this.text = text; // store the original line as is
        this.source = source;
        this.lineNumber = lineNumber;

		text = text.trim();

        // special handling for container directives
        // we remove the ">" from the end
        if ((text.length() != 0)
            && (text.charAt(0) == '<')
            && (text.charAt(text.length() - 1) == '>')) {
            text = text.substring(0, text.length() - 1);
        }
        tokens = Tokenizer.toStringArray(text);
        if (tokens.length != 0) name = tokens[0];
    }

    public String getText() {
        return text;
    }

    public String getName() {
        return name;
    }

    public int getTokenCount() {
        return tokens.length - 1;
    }

    public String getToken(int count) {
        return tokens[count];
    }

    public boolean getBooleanToken(int count) {
        if (tokens[count].compareToIgnoreCase("on") == 0) return true;
        else return false;
    }

    public int getIntegerToken(int count) throws JakException {
        try {
            return Integer.parseInt(tokens[count]);
        } catch(NumberFormatException e) {
            throw new JakException("Expected integer but found: " + tokens[count], this);
        }
    }

    public String getSource() {
        return source;
    }

    public int getLineNumber() {
        return lineNumber;
    }
}
