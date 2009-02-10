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

import java.util.*;
import java.util.regex.*;

import org.owasp.esapi.filters.waf.*;

public class Recipe {

    private String id;

    private String message;

    private String normalization = null;

    private List normalizationList = new ArrayList();

    private String path;

    private Pattern compiledPath;

    private List ruleSets = new ArrayList();

    private WasProtect context;

    public void setContext(WasProtect context) {
        this.context = context;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

    public void setPath(String path) throws PatternSyntaxException {
        this.path = path;
        compiledPath = Pattern.compile(path);
    }

    public void setNormalization(String normalization) throws Exception {
        normalizationList = context.parseNormalizationString(normalization);
        this.normalization = normalization;
    }

    public List getNormalizationList() {
        return normalizationList;
    }

    public void addRuleSet(RuleSet ruleSet) {
        ruleSets.add(ruleSet);
    }

    public int inspect(int stage, HttpTransaction tran) throws Exception {
        // Should this recipe be applied to the request path?
        if (compiledPath != null) {
            String requestPath = tran.msReq.getServletPath();
            Matcher m = compiledPath.matcher(requestPath);
            if (m.matches() == false) {
                context.log(4, "Recipe " + id + " not applicable to the request path", tran);
                return Rule.ACTION_NONE;
            }
        }

        context.log(4, "Recipe (" + id + ") starting inspection", tran);

        VariableResolver variableResolver = new VariableResolver(null, tran);

        int rc = Rule.ACTION_NONE;
        for(int i = 0; i < ruleSets.size(); i++) {
            RuleSet ruleSet = (RuleSet)ruleSets.get(i);
            if (ruleSet.getStage() == stage) {
                rc = ruleSet.inspect(variableResolver, tran);
                // Allowed values for rc are ACTION_NONE, ACTION_ERROR, ACTION_ALLOW
                if (rc == Rule.ACTION_ALLOW_RECIPE) {
                    context.log(4, "Ending Recipe with NONE because RuleSet returned ALLOW_RECIPE", tran);
                    return Rule.ACTION_NONE;
                }
                else if (rc != Rule.ACTION_NONE) return rc;
            }
        }

        return Rule.ACTION_NONE;
    }
}