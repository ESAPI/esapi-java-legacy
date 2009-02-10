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

//import java.util.*;
//import java.util.regex.*;
import org.owasp.esapi.filters.waf.*;

public class InspectionResult {

    int rc = Rule.ACTION_NONE;

    Variable variable;

    String variableValue;

    Rule rule;

    RuleSet ruleSet;

    Recipe recipe;

    HttpTransaction tran;

    String msg;

    public InspectionResult(Rule rule, HttpTransaction tran) {
        this.tran = tran;
        this.rule = rule;
        this.ruleSet = rule.getRuleSet();
        this.recipe = ruleSet.getRecipe();
    }
}