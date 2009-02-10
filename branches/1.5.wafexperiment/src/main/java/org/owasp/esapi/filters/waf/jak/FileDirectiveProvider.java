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

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

/**
 * DirectiveProvider implementation that reads configuration
 * directives from a file on the local filesystem.
 *
 */
public class FileDirectiveProvider implements DirectiveProvider {

    private String filename;

    private BufferedReader reader;

    private int lineNumber = -1;

    private String lastLine;

    private boolean triedNext;

    public FileDirectiveProvider(String filename) {
        this.filename = filename;
    }

    public DirectiveProvider construct(String filename) {
        return new FileDirectiveProvider(filename);
    }

    public void open() throws IOException {
        try {
            reader = new BufferedReader(new FileReader(filename));
            lineNumber = 0;
            triedNext = false;
        } catch (FileNotFoundException fnfe) {
            throw new IOException("Could not open file " + filename + ": " + fnfe.getMessage());
        }
    }

    public void close() {
        try {
            reader.close();
            reader = null;
        } catch (Exception e) {
            // we don't care
        }
    }

    public int getLineNumber() {
        return lineNumber;
    }

    public String getSource() {
        return filename;
    }

    public boolean hasNext() throws IOException {
        while (triedNext == false) {
            lastLine = reader.readLine();

            // null means we've reached the end of the file
            if (lastLine == null) {
                triedNext = true;
            } else {
                // ignore empty lines and comments
                lastLine = lastLine.trim();
                if ((lastLine.length() != 0) && (lastLine.charAt(0) != '#')) {
                    triedNext = true;
                }
            }
        }

        return lastLine == null ? false : true;
    }

    public Directive getNext() throws IOException {
        if (triedNext == false) {
            hasNext();
        }

        if (lastLine != null) {
            triedNext = false;
            lineNumber++;
            return new Directive(lastLine, getSource(), getLineNumber());
        } else {
            return null;
        }
    }
}
