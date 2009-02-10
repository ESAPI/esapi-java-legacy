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

public class Rule {
    public static final int ACTION_NONE = 0;
    public static final int ACTION_NOTICE = 1;
    public static final int ACTION_WARNING = 2;
    public static final int ACTION_ERROR = 3;
    public static final int ACTION_ALLOW_RULESET = 4;
    public static final int ACTION_ALLOW_RECIPE = 5;

    public static final int OPERATOR_REGEX = 1;
    public static final int OPERATOR_NREGEX = 2;
    public static final int OPERATOR_LT = 3;
    public static final int OPERATOR_GT = 4;
    public static final int OPERATOR_EXISTS = 5;
    public static final int OPERATOR_NEXISTS = 6;
    public static final int OPERATOR_STRSTR = 7;
    public static final int OPERATOR_EQ = 8;
    public static final int OPERATOR_NEQ = 9;
    public static final int OPERATOR_GTE = 10;
    public static final int OPERATOR_LTE = 11;

    private int action = ACTION_ERROR;

    private int operator = OPERATOR_NREGEX;

    private String pattern = "";

    private Pattern compiledPattern;

    private String args;

    private String normalization = null;

    private List normalizationList = new ArrayList();

    private WasProtect context;

    private RuleSet ruleSet;

    public void setRuleSet(RuleSet ruleSet) {
        this.ruleSet = ruleSet;
        // re-set normalization to take into account
        // default functions configured in the parent
        // ruleset
        try {
            setNormalization(normalization);
        } catch(Exception e) {
            // this should never occur because the
            // list of functions was already successfully
            // parsed once
            e.printStackTrace(System.err);
        }
    }

    public RuleSet getRuleSet() {
        return ruleSet;
    }

    public void setContext(WasProtect context) {
        this.context = context;
    }

    public void setOperator(int operator) throws PatternSyntaxException {
        this.operator = operator;
        if (((operator == OPERATOR_REGEX)||(operator == OPERATOR_NREGEX))&&(pattern != null)) {
            compiledPattern = Pattern.compile(pattern);
        }
    }

    public void setArgs(String args) throws Exception {
        // TODO validate the args string
        this.args = args;
    }

    public void setPattern(String pattern) throws PatternSyntaxException {
        this.pattern = pattern;
        if ((operator == OPERATOR_REGEX)||(operator == OPERATOR_NREGEX)) {
            compiledPattern = Pattern.compile(pattern);
        }
    }

    public void setAction(int action) {
        this.action = action;
    }

    public void setNormalization(String normalization) throws Exception {
        if (normalization == null) {
            normalizationList.clear();
            if (ruleSet != null) normalizationList.addAll(ruleSet.getNormalizationList());
            return;
        }
        normalizationList = context.parseNormalizationString(normalization, ruleSet.getNormalizationList());
        this.normalization = normalization;
    }

    public List getNormalizationList() {
        return normalizationList;
    }

    public String normalizeVariable(String variable) {
        for(int i = 0, n = normalizationList.size(); i < n; i++) {
            String function = (String)normalizationList.get(i);
            try {
                variable = context.normalize(function, variable);
            } catch(Exception e) {
                // this should never happen
                e.printStackTrace(System.err);
            }
        }
        return variable;
    }

    public InspectionResult inspect(VariableResolver variableResolver, HttpTransaction tran) throws Exception {
        InspectionResult ir = new InspectionResult(this, tran);

        // Retrive variable collection.
        List variables = VariableFactory.createVariables(args, tran, VariableFactory.CONTEXT_REQUEST);

        // Apply the test to every variable in the collection.
        for(int i = 0, n = variables.size(); i < n; i++) {
            ir.variable = (Variable)variables.get(i);
            ir.variableValue = variableResolver.getValue(ir.variable);
            ir.variableValue = normalizeVariable(ir.variableValue);

            ir.rc = test(ir.variable, ir.variableValue, tran);
            context.log(5, "Variable " + ir.variable.fullName + "=" + ir.variableValue, tran);
            context.log(4, "Test result " + actionToString(ir.rc) + " [variable=" + ir.variable.fullName + ", operator=" + operatorToString(operator) + ", pattern=" + pattern + "]", tran);

            switch(ir.rc) {

                case ACTION_ERROR :
                    ir.msg = "Operator match: " + "variable=" + ir.variable.fullName + ", operator=" + operatorToString(operator) + ", pattern=" + pattern;
                    // continue on purpose

                case ACTION_ALLOW_RECIPE :
                case ACTION_ALLOW_RULESET :
                    return ir;
                    // break;

                case ACTION_WARNING :
                case ACTION_NOTICE :
                    // log the event ourselves
                    // and continue with the next variable
                    context.submitEvent(ir);
                    break;

                case ACTION_NONE :
                    // do nothing
                    break;

                default :
                    // TODO error unknown action
                    break;
            }
        }

        return ir;
    }


    // -- operator implementations ------------------------------

    public int test(Variable variable, String value, HttpTransaction tran) {
        int rc = ACTION_NONE;
        switch(operator) {
            case Rule.OPERATOR_REGEX :
                rc = test_regex(variable, value, tran);
                break;
            case Rule.OPERATOR_NREGEX :
                rc = test_nregex(variable, value, tran);
                break;
            case Rule.OPERATOR_LT :
                rc = test_lt(variable, value, tran);
                break;
            case Rule.OPERATOR_GT :
                rc = test_gt(variable, value, tran);
                break;
            case Rule.OPERATOR_EXISTS :
                rc = test_exists(variable, value, tran);
                break;
            case Rule.OPERATOR_NEXISTS :
                rc = test_nexists(variable, value, tran);
                break;
            case Rule.OPERATOR_STRSTR :
                rc = test_strstr(variable, value, tran);
                break;
            case Rule.OPERATOR_EQ :
                rc = test_eq(variable, value, tran);
                break;
            case Rule.OPERATOR_NEQ :
                rc = test_neq(variable, value, tran);
                break;
            case Rule.OPERATOR_GTE :
                rc = test_gte(variable, value, tran);
                break;
            case Rule.OPERATOR_LTE :
                rc = test_lte(variable, value, tran);
                break;
        }
        return rc;
    }

    public int test_regex(Variable variable, String value, HttpTransaction tran) {
        if (value == null) value = "";
        Matcher m = compiledPattern.matcher(value);
        // if (m.matches() == true) return action;
        if (m.find() == true) return action;
        else return ACTION_NONE;
    }

    public int test_nregex(Variable variable, String value, HttpTransaction tran) {
        if (value == null) value = "";
        Matcher m = compiledPattern.matcher(value);
        // if (m.matches() == false) return action;
        if (m.find() == false) return action;
        else return ACTION_NONE;
    }

    public int test_lt(Variable variable, String value, HttpTransaction tran) {
        int len1 = 0;
        if (value != null) len1 = Integer.parseInt(value);
        int len2 = Integer.parseInt(pattern);
        if (len1 < len2) return ACTION_NONE;
        else return action;
    }

    public int test_gt(Variable variable, String value, HttpTransaction tran) {
        int len1 = 0;
        if (value != null) len1 = Integer.parseInt(value);
        int len2 = Integer.parseInt(pattern);
        if (len1 > len2) return ACTION_NONE;
        else return action;
    }

    public int test_exists(Variable variable, String value, HttpTransaction tran) {
        if (value == null) return ACTION_NONE;
        else return action;
    }

    public int test_nexists(Variable variable, String value, HttpTransaction tran) {
        if (value == null) return action;
        else return ACTION_NONE;
    }

    public int test_strstr(Variable variable, String value, HttpTransaction tran) {
        if (value.indexOf(pattern) != -1) return action;
        else return ACTION_NONE;
    }

    public int test_eq(Variable variable, String value, HttpTransaction tran) {
        if (value.compareTo(pattern) == 0) return action;
        else return ACTION_NONE;
    }

    public int test_neq(Variable variable, String value, HttpTransaction tran) {
        if (value.compareTo(pattern) == 0) return ACTION_NONE;
        else return action;
    }

    public int test_gte(Variable variable, String value, HttpTransaction tran) {
        int len1 = 0;
        if (value != null) len1 = Integer.parseInt(value);
        int len2 = Integer.parseInt(pattern);
        if (len1 >= len2) return ACTION_NONE;
        else return action;
    }

    public int test_lte(Variable variable, String value, HttpTransaction tran) {
        int len1 = 0;
        if (value != null) len1 = Integer.parseInt(value);
        int len2 = Integer.parseInt(pattern);
        if (len1 <= len2) return ACTION_NONE;
        else return action;
    }

    public String toString() {
        return("Rule [action=" + action + ", operator=" + operator + ", args=" + args + ", pattern=" + pattern + "]");
    }

    public static String actionToString(int action) {
        switch(action) {

            case ACTION_NONE :
                return "NONE";

            case ACTION_ALLOW_RECIPE :
                return "ALLOW_RECIPE";

            case ACTION_ALLOW_RULESET :
                return "ALLOW_RULESET";

            case ACTION_ERROR :
                return "ERROR";

            case ACTION_WARNING :
                return "WARNING";

            case ACTION_NOTICE :
                return "NOTICE";

            default :
                return "UNKNOWN (" + action + ")";
        }
    }

    public static String operatorToString(int operator) {
        switch(operator) {
            case OPERATOR_REGEX :
                return "REGEX";
            case OPERATOR_NREGEX :
                return "NREGEX";
            case OPERATOR_LT :
                return "LT";
            case OPERATOR_GT :
                return "GT";
            case OPERATOR_EXISTS :
                return "EXISTS";
            case OPERATOR_NEXISTS :
                return "NEXISTS";
            default :
                return "UNKNOWN (" + operator + ")";
        }
    }
}


