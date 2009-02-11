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
import java.util.*;
import javax.servlet.http.*;

import org.owasp.esapi.filters.waf.jak.*;
import org.owasp.esapi.filters.waf.*;
import org.owasp.esapi.filters.waf.util.*;

public class WasProtect implements JakModule, DirectiveHandler, Inspector {

    private ModSecurity context;

    private List recipes = new ArrayList();

    public void handleDirective(Configuration config, Directive directive)
            throws JakException {

        if (directive.getName().compareTo("LoadWasRecipe") == 0) {
            String filename = context.getFilterConfig().getServletContext().getRealPath(directive.getToken(1));
            context.log(2, "Loading WAS Protect recipe from file: " + filename);

            Recipe recipe = null;
            try {
                recipe = RecipeFactory.loadFromXml(filename, this);
            } catch(Exception e) {
                throw new JakException("WASProtect: XML parsing error: " + e.getMessage(), e, directive);
            }
            if (recipe == null) {
                throw new JakException("WASProtect: Internal error - recipe is null", directive);
            }
            recipes.add(recipe);
        }
        else {
            throw new JakException("WASProtect: don't know how to handle: " + directive.getName(), directive);
        }
    }

    public void init(Configuration config) throws Exception {
        this.context = (ModSecurity)config;
        config.registerDirectiveTemplate("LoadWasRecipe", DirectiveTemplate.TAKE1, this);
    }

    public void postInit() {}

	public void start() {}

	public void stop() {}

	public void destroy() {}

	public int inspect(int phase, HttpTransaction tran) throws IOException, Exception {
	    if ((phase == Inspector.PRE_REQUEST)||(phase == Inspector.LOGGING)) return Inspector.ACTION_NONE;

	    int stage = REQUEST_HEADERS;
	    switch(phase) {

	        case Inspector.REQUEST_HEADERS :
	            stage = RuleSet.STAGE_REQUEST_HEADERS;
	            break;

	        case Inspector.REQUEST_BODY :
	            stage = RuleSet.STAGE_REQUEST_BODY;
	            break;

	        case Inspector.RESPONSE_HEADERS :
	            stage = RuleSet.STAGE_RESPONSE_HEADERS;
	            break;

	        case Inspector.RESPONSE_BODY :
	            stage = RuleSet.STAGE_RESPONSE_BODY;
	            break;
	    }

        for(int i = 0; i < recipes.size(); i++) {
            Recipe recipe = (Recipe)recipes.get(i);
            int rc = recipe.inspect(stage, tran);
            switch(rc) {

                case Rule.ACTION_ERROR :

                	String page = context.getSecurityErrorPage();

                	if ( page == null ) {
                		tran.res.sendError(HttpServletResponse.SC_FORBIDDEN);
                	} else {
                		tran.res.sendRedirect(tran.req.getContextPath() + page);
                	}

                    tran.setRelevant(true);
                    return Inspector.ACTION_STOP;
                    // break;

                case Rule.ACTION_NONE :
                    // do nothing
                    break;

                default :
                    // TODO error
                    break;
            }
        }

        return Inspector.ACTION_NONE;
	}

	public void log(int level, String msg) {
	    context.log(level, msg, null);
	}

	public void log(int level, String msg, HttpTransaction tran) {
	    context.log(level, msg, tran);
	}

	public void submitEvent(InspectionResult ir) {
	    StringBuffer sb = new StringBuffer();
	    sb.append(Rule.actionToString(ir.rc));
	    sb.append(" [client ");
	    sb.append(ir.tran.msReq.getRemoteAddr());
	    sb.append("]");
        sb.append(" [uri ");
        sb.append(ir.tran.msReq.getServletPath());
        sb.append("]");

        String id = ir.recipe.getId();
        if (id != null) {
            sb.append(" [id ");
            sb.append(id);
            sb.append("]");
        }

        String message = ir.recipe.getMessage();
        if (message != null) {
            sb.append(" [message ");
            sb.append(message);
            sb.append("]");
        }

        sb.append(" ");
        sb.append(ir.msg);

	    context.log(1, sb.toString(), ir.tran);
	}

	public void checkNormalizationFunction(String function) throws Exception {
	    normalize(function, "");
	}

	public String normalize(String function, String text) throws Exception {
	    if (function.compareTo("convertToLowercase") == 0) return Decoder.convertToLowercase(text);
	    else
	    if (function.compareTo("removeSelfReferences") == 0) return Decoder.removeSelfReferences(text);
	    else
	    if (function.compareTo("convertBackslashes") == 0) return Decoder.convertBackSlashes(text);
	    else
	    if (function.compareTo("compressSlashes") == 0) return Decoder.compressSlashes(text);
	    else
	    if (function.compareTo("compressWhitespace") == 0) return Decoder.compressWhitespace(text);
	    else
	    if (function.compareTo("decodeEscaped") == 0) return Decoder.decodeEscaped(text);
	    else
	    if (function.compareTo("decodeURLEncoded") == 0) return Decoder.decodeURLEncoded(text);
	    else
	    if (function.compareTo("decodeURLEncodedAgain") == 0) {
	        text = Decoder.decodeURLEncoded(text);
	        return Decoder.decodeURLEncoded(text);
	    }
	    else {
	        throw new Exception("Unknown normalization function: " + function);
	    }
	}

	public List parseNormalizationString(String normalization) throws Exception {
	    return parseNormalizationString(normalization, null);
	}

	public List parseNormalizationString(String normalizationString, List parentFunctions) throws Exception {
	    ArrayList r = new ArrayList();
        boolean isRelative = false;

        String[] tokens = Tokenizer.toStringArray(normalizationString);
        for(int i = 0; i < tokens.length; i++) {
            // determine whether the string is relative or absolute
            if ((i == 0)&&((tokens[i].charAt(0) == '+')||(tokens[i].charAt(0) == '-'))) {
                isRelative = true;
                if (parentFunctions != null) r.addAll(parentFunctions);
            }

            if (isRelative) {
                if (tokens[i].charAt(0) == '+') {
                    String function = tokens[i].substring(1);

                    // add to the list if it's not already there
                    boolean isThere = false;
                    Iterator j = r.iterator();
                    while(j.hasNext()) {
                        String existing = (String)j.next();
                        if (existing.compareTo(function) == 0) {
                            isThere = true;
                            break;
                        }
                    }
                    if (isThere == false) {
                        checkNormalizationFunction(function);
                        r.add(function);
                    }
                }
                else if (tokens[i].charAt(0) == '-') {
                    String function = tokens[i].substring(1);

                    // remove from the list if it's there
                    Iterator j = r.iterator();
                    while(j.hasNext()) {
                        String existing = (String)j.next();
                        if (existing.compareTo(function) == 0) j.remove();
                    }
                }
                else {
                    throw new Exception("Mixing relative and absolute normalization functions is not allowed");
                }
            } else {
                if ((tokens[i].charAt(0) == '+')||(tokens[i].charAt(0) == '-')) {
                    throw new Exception("Mixing relative and absolute normalization functions is not allowed");
                }
                checkNormalizationFunction(tokens[i]);
                r.add(tokens[i]);
            }
        }

        return r;
	}
}