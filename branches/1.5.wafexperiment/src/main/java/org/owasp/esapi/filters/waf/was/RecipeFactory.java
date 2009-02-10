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

import java.io.*;

import org.xml.sax.*;
import org.w3c.dom.*;
import org.apache.xerces.parsers.DOMParser;
import org.xml.sax.helpers.DefaultHandler;

import org.owasp.esapi.filters.waf.*;

class Validator extends DefaultHandler {
    public boolean validationError = false;
    public SAXParseException saxParseException = null;

    public void error(SAXParseException exception) throws SAXException {
        validationError = true;
        saxParseException = exception;
        System.err.println(exception.getMessage());
    }

    public void fatalError(SAXParseException exception) throws SAXException {
        validationError = true;
        saxParseException = exception;
        System.err.println(exception.getMessage());
    }

    public void warning(SAXParseException exception) throws SAXException {
        System.err.println(exception.getMessage());
    }
}

public class RecipeFactory {

    private static final String VALIDATION_FEATURE_ID = "http://xml.org/sax/features/validation";
    private static final String SCHEMA_VALIDATION_FEATURE_ID = "http://apache.org/xml/features/validation/schema";
    private static final String SCHEMA_FULL_CHECKING_FEATURE_ID = "http://apache.org/xml/features/validation/schema-full-checking";

    public static Recipe loadFromXml(String filename, WasProtect context) throws Exception {
        DOMParser parser = new DOMParser();

        Validator handler = new Validator();
        parser.setErrorHandler(handler);

        parser.setFeature(VALIDATION_FEATURE_ID, true);
        parser.setFeature(SCHEMA_VALIDATION_FEATURE_ID, true);
        // parser.setFeature(SCHEMA_FULL_CHECKING_FEATURE_ID, true);

        parser.parse(filename);
        Document doc = parser.getDocument();

        if (handler.validationError == true) throw new Exception("Schema validation failed");

        Node node = doc.getDocumentElement();
        return createRecipe(node, context);
    }

    public static Recipe createRecipe(Node node, WasProtect context) throws Exception {
        Recipe recipe = new Recipe();
        recipe.setContext(context);

        // handle attributes
        NamedNodeMap attributes = node.getAttributes();
        for (int i = 0; i < attributes.getLength(); i++) {
            Node attr = attributes.item(i);
            // TODO recipe ID must be unique
            if (attr.getNodeName().compareTo("id") == 0) recipe.setId(attr.getNodeValue());
            else
            if (attr.getNodeName().compareTo("message") == 0) recipe.setMessage(attr.getNodeValue());
            else
            if (attr.getNodeName().compareTo("path") == 0) recipe.setPath(attr.getNodeValue());
            else
            if (attr.getNodeName().compareTo("normalization") == 0) recipe.setNormalization(attr.getNodeValue());
        }

        // handle children
        NodeList children = node.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeName().compareTo("ruleSet") == 0) createRuleSet(recipe, child, context);
        }

        return recipe;
    }

    public static void createRuleSet(Recipe recipe, Node node, WasProtect context) throws Exception {
        RuleSet ruleSet = new RuleSet();
        ruleSet.setContext(context);
        recipe.addRuleSet(ruleSet);
        ruleSet.setRecipe(recipe);

        // handle attributes
        NamedNodeMap attributes = node.getAttributes();
        for (int i = 0; i < attributes.getLength(); i++) {
            Node attr = attributes.item(i);

            if (attr.getNodeName().compareTo("action") == 0) {
                String actionString = attr.getNodeValue();
                if (actionString.compareTo("error") == 0) ruleSet.setAction(Rule.ACTION_ERROR);
                else
                if (actionString.compareTo("warning") == 0) ruleSet.setAction(Rule.ACTION_WARNING);
                else
                if (actionString.compareTo("notice") == 0) ruleSet.setAction(Rule.ACTION_NOTICE);
                else
                if (actionString.compareTo("allowRecipe") == 0) ruleSet.setAction(Rule.ACTION_ALLOW_RECIPE);
                else
                if (actionString.compareTo("allowRuleSet") == 0) ruleSet.setAction(Rule.ACTION_ALLOW_RULESET);
            }

            if (attr.getNodeName().compareTo("condition") == 0) {
                String conditionString = attr.getNodeValue();
                if (conditionString.compareTo("and") == 0) ruleSet.setCondition(RuleSet.CONDITION_AND);
                else
                if (conditionString.compareTo("or") == 0) ruleSet.setCondition(RuleSet.CONDITION_OR);
            }

            if (attr.getNodeName().compareTo("stage") == 0) {
                String stageString = attr.getNodeValue();
                if (stageString.compareTo("requestHeaders") == 0) ruleSet.setStage(RuleSet.STAGE_REQUEST_HEADERS);
                else
                if (stageString.compareTo("requestBody") == 0) ruleSet.setStage(RuleSet.STAGE_REQUEST_BODY);
                else
                if (stageString.compareTo("responseBody") == 0) ruleSet.setStage(RuleSet.STAGE_RESPONSE_BODY);
            }

            if (attr.getNodeName().compareTo("normalization") == 0) {
                ruleSet.setNormalization(attr.getNodeValue());
            }
        }

        NodeList children = node.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeName().compareTo("rule") == 0) createRule(ruleSet, child, context);
        }
    }

    public static void createRule(RuleSet ruleSet, Node node, WasProtect context) throws Exception {
        Rule rule = new Rule();
        rule.setContext(context);
        ruleSet.addRule(rule);
        rule.setAction(ruleSet.getAction());
        rule.setRuleSet(ruleSet);

        // handle attributes
        NamedNodeMap attributes = node.getAttributes();
        for (int i = 0; i < attributes.getLength(); i++) {
            Node attr = attributes.item(i);
            if (attr.getNodeName().compareTo("value") == 0) rule.setPattern(attr.getNodeValue());

            if (attr.getNodeName().compareTo("arg") == 0) rule.setArgs(attr.getNodeValue());

            if (attr.getNodeName().compareTo("action") == 0) {
                String actionString = attr.getNodeValue();
                if (actionString.compareTo("error") == 0) rule.setAction(Rule.ACTION_ERROR);
                else
                if (actionString.compareTo("warning") == 0) rule.setAction(Rule.ACTION_WARNING);
                else
                if (actionString.compareTo("notice") == 0) rule.setAction(Rule.ACTION_NOTICE);
                else
                if (actionString.compareTo("allowRuleSet") == 0) rule.setAction(Rule.ACTION_ALLOW_RULESET);
                else
                if (actionString.compareTo("allowRecipe") == 0) rule.setAction(Rule.ACTION_ALLOW_RECIPE);
            }

            if (attr.getNodeName().compareTo("operator") == 0) {
                String operatorString = attr.getNodeValue();
                if (operatorString.compareTo("regex") == 0) rule.setOperator(Rule.OPERATOR_REGEX);
                else
                if (operatorString.compareTo("nregex") == 0) rule.setOperator(Rule.OPERATOR_NREGEX);
                else
                if (operatorString.compareTo("lt") == 0) rule.setOperator(Rule.OPERATOR_LT);
                else
                if (operatorString.compareTo("gt") == 0) rule.setOperator(Rule.OPERATOR_GT);
                else
                if (operatorString.compareTo("exists") == 0) rule.setOperator(Rule.OPERATOR_EXISTS);
                else
                if (operatorString.compareTo("nexists") == 0) rule.setOperator(Rule.OPERATOR_NEXISTS);
                else
                if (operatorString.compareTo("strstr") == 0) rule.setOperator(Rule.OPERATOR_STRSTR);
                else
                if (operatorString.compareTo("eq") == 0) rule.setOperator(Rule.OPERATOR_EQ);
                else
                if (operatorString.compareTo("neq") == 0) rule.setOperator(Rule.OPERATOR_NEQ);
                else
                if (operatorString.compareTo("gte") == 0) rule.setOperator(Rule.OPERATOR_GTE);
                else
                if (operatorString.compareTo("lte") == 0) rule.setOperator(Rule.OPERATOR_LTE);
            }

            if (attr.getNodeName().compareTo("normalization") == 0) {
                rule.setNormalization(attr.getNodeValue());
            }
        }
    }
}