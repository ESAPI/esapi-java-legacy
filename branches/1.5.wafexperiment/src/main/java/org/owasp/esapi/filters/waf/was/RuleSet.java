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
import org.owasp.esapi.filters.waf.*;

public class RuleSet {
    public static final int CONDITION_OR = 1;
    public static final int CONDITION_AND = 2;

    public static final int STAGE_REQUEST_HEADERS = 1;
    public static final int STAGE_REQUEST_BODY = 2;
    public static final int STAGE_RESPONSE_HEADERS = 3;
    public static final int STAGE_RESPONSE_BODY = 4;

    private int stage = STAGE_REQUEST_BODY;

    private int condition = CONDITION_OR;

    private int action = Rule.ACTION_ERROR;

    private List rules = new ArrayList();

    private String normalization = null;

    private List normalizationList = new ArrayList();

    private WasProtect context;

    private Recipe recipe;

    public void setRecipe(Recipe recipe) {
        this.recipe = recipe;
        // re-set normalization to take into account
        // default functions configured in the parent
        // recipe
        try {
            setNormalization(normalization);
        } catch(Exception e) {
            // this should never occur because the
            // list of functions was already successfully
            // parsed once
            e.printStackTrace(System.err);
        }
    }

    public Recipe getRecipe() {
        return recipe;
    }

    public void setContext(WasProtect context) {
        this.context = context;
    }

    public void setAction(int action) {
        this.action = action;
    }

    public void setNormalization(String normalization) throws Exception {
        if (normalization == null) {
            normalizationList.clear();
            if (recipe != null) normalizationList.addAll(recipe.getNormalizationList());
            return;
        }
        normalizationList = context.parseNormalizationString(normalization, recipe.getNormalizationList());
        this.normalization = normalization;
    }

    public List getNormalizationList() {
        return normalizationList;
    }

    public int getAction() {
        return action;
    }

    public void setCondition(int condition) {
        this.condition = condition;
    }

    public void setStage(int stage) {
        this.stage = stage;
    }

    public int getStage() {
        return stage;
    }

    public void addRule(Rule rule) {
        rules.add(rule);
    }

    /**
     * Processes the rules in the set.
     */
    public int inspect(VariableResolver variableResolver, HttpTransaction tran) throws Exception {
        context.log(4, "New RuleSet inspection started", tran);

        Rule rule = null;
        InspectionResult ir = null;
        for (int i = 0; i < rules.size(); i++) {
            rule = (Rule)rules.get(i);
            ir = rule.inspect(variableResolver, tran);
            // Allowed ir.rc values are ACTION_NONE, ACTION_ALLOW_RECIPE,
            // ACTION_ALLOW_RULESET, ACTION_ERROR.
            context.log(4, "Rule result " + Rule.actionToString(ir.rc), tran);

            if (condition == CONDITION_AND) {
                switch(ir.rc) {

                    case Rule.ACTION_NONE :
                        // When the condition is AND if one rule fails
                        // to match the whole rule set fails to match.
                        context.log(4, "Ending RuleSet with NONE because condition is AND and Rule returned NONE", tran);
                        return Rule.ACTION_NONE;
                        // break;

                    case Rule.ACTION_ALLOW_RECIPE :
                        context.log(4, "Ending RuleSet with ALLOW because Rule returned ALLOW_RECIPE", tran);
                        return Rule.ACTION_ALLOW_RECIPE;

                    case Rule.ACTION_ALLOW_RULESET :
                        // ACTION_ALLOW_RULESET affects this ruleset only,
                        // it appears as ACTION_NONE from the outside.
                        context.log(4, "Ending RuleSet with NONE because Rule returned ALLOW_RULESET", tran);
                        return Rule.ACTION_NONE;
                        // break;

                    default :
                        // in all other cases proceed to the
                        // next rule in the set
                        break;
                }
            } else {
                switch(ir.rc) {

                    case Rule.ACTION_NONE :
                        // proceed to the next rule
                        break;

                    case Rule.ACTION_ALLOW_RECIPE :
                        context.log(4, "Ending RuleSet with ALLOW because Rule returned ALLOW_RECIPE", tran);
                        return Rule.ACTION_ALLOW_RECIPE;
                        // break;

                    case Rule.ACTION_ALLOW_RULESET :
                        // ACTION_ALLOW_RULESET affects this rule set only,
                        // it appears as ACTION_NONE from the outside.
                        context.log(4, "Ending RuleSet with NONE because Rule returned ALLOW_RULESET", tran);
                        return Rule.ACTION_NONE;
                        // break;

                    default :
                        context.submitEvent(ir);
                        return Rule.ACTION_ERROR;
                        // break;
                }
            }
        }

        // When the condition is AND we arrive here
        // when there is an error in the last rule
        // in the set.
        if (ir.rc == Rule.ACTION_ERROR) {
            context.submitEvent(ir);
            return Rule.ACTION_ERROR;
        }

        context.log(4, "Ending RuleSet with NONE (no more rules)", tran);
        return Rule.ACTION_NONE;
    }
}
