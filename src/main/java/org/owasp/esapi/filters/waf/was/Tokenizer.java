/*
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

package org.owasp.esapi.filters.waf.was;

import java.io.IOException;
import java.io.Reader;
import java.io.StreamTokenizer;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

/**
 * Simple tokenizer that understands quoted parameters.
 *
 * @author Ivan Ristic
 */
public class Tokenizer {

	private StreamTokenizer streamTokenizer;

	/**
	 * Initialize a tokenizer from a String instance.
	 *
	 * @param input
	 */
	public Tokenizer(String input) {
		this(new StringReader(input));
	}

	/**
	 * Initialize a tokenizer from a Reader instance.
	 *
	 * @param input
	 */
	public Tokenizer(Reader input) {
		streamTokenizer = new StreamTokenizer(input);
		streamTokenizer.resetSyntax();
		streamTokenizer.wordChars(0, 255);
		streamTokenizer.quoteChar('"');
		streamTokenizer.whitespaceChars(' ', ' ');
		streamTokenizer.whitespaceChars('\t', '\t');
		streamTokenizer.whitespaceChars('\n', '\n');
		streamTokenizer.whitespaceChars('\r', '\r');
	}

	/**
	 * Determine whether there are more tokens available.
	 *
	 * @return true if there are more tokens and false otherwise
	 */
	public boolean hasMoreTokens() {
		try {
			streamTokenizer.nextToken();
		} catch(IOException e) {}

		return(streamTokenizer.ttype != StreamTokenizer.TT_EOF);
	}

	/**
	 * Returns the next token.
	 *
	 * @return the next token or null if a token is not available
	 */
	public String nextToken() {
		return streamTokenizer.sval;
	}

	/**
	 * Tokenizes the remainder of the input into an instance
	 * of the List.
	 *
	 * @return a list containing all tokens
	 */
	public List toList() {
		ArrayList list = new ArrayList();
		while(hasMoreTokens()) {
			list.add(nextToken());
		}
		return list;
	}

	/**
	 * A static utility method to tokenize a string and return
	 * all tokens in a list.
	 *
	 * @param input
	 * @return a list containing all tokens
	 */
	public static List toList(String input) {
		Tokenizer tokenizer = new Tokenizer(input);
		return tokenizer.toList();
	}

	public static String[] toStringArray(String input) {
		Tokenizer tokenizer = new Tokenizer(input);
		List l = tokenizer.toList();
		String[] r = new String[l.size()];
		for(int i = 0; i < l.size(); i++) {
			r[i] = (String)l.get(i);
		}
		return r;
	}
}

