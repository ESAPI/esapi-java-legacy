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

import java.io.IOException;
import java.util.*;


/**
 * Implementation of the Configuration interface. It supports
 * Apache-style directives: LoadModule, &lt;IfModule, and Include
 * (filesystem access only at the moment).
 *
 */
public class Jak implements Configuration {

    private DirectiveProvider currentProvider;

    private Map directives = new HashMap();

    private Map modules = new HashMap();

    private Stack providers = new Stack();

    /**
     * Handles the LoadModule configuration directive.
     *
     */
    public class LoadModuleHandler implements DirectiveHandler {
        public void handleDirective(Configuration config, Directive directive)
            throws JakException {
            String name = directive.getToken(1);

            // find the class and create an instance
            Object o = null;
            try {
                Class c = Class.forName(name);
                o = c.newInstance();
            } catch (ClassNotFoundException cnfe) {
                throw new JakException(
                    "Unable to find module " + name + ": class " + cnfe.getMessage() + " not found",
                    cnfe,
                    directive);
            } catch (Exception e) {
                throw new JakException(
                    "Unable to find module " + name + ": " + e.getMessage(),
                    e,
                    directive);
            }

            /* done in registerModule now
            // initialize the Jak module, if it
            // really is a Jak module
            if (o instanceof JakModule) {
                JakModule m = (JakModule)o;
                try {
                    m.init(config);
                } catch (Exception e) {
                    throw new JakException(
                        "Unable to initialize module " + name + ": " + e.getMessage(),
                        e,
                        directive);
                }
            }
            */

            // use the provided module name if available
            // otherwise register the module under its
            // class name (sans package)
            if (directive.getTokenCount() == 1) {
                name = name.substring(name.lastIndexOf(".") + 1);
            } else {
                name = directive.getToken(2);
            }
            config.registerModule(name, o);
        }
    }

    /**
     * Handles the &lt;IfModule configuration directive.
     *
     */
    public class IfModuleHandler implements DirectiveHandler {

        public void handleDirective(Configuration config, Directive directive)
            throws IOException, JakException {
            String name = directive.getToken(1);

            boolean processDirectives = true;
            if (config.getModule(name) == null)
                processDirectives = false;

            for (;;) {
                Directive d = config.getNextDirective();
                if (d == null) {
                    throw new JakException("The closing </IfModule> directive is missing");
                }

                if (d.getName().compareTo("</IfModule") == 0)
                    return;

                if (d.getName().compareTo("<IfModule") == 0) {
                	throw new JakException("Nested <IfModule> directives are not allowed", d);
                }

                if (processDirectives) {
                    config.processDirective(d);
                }
            }
        }
    }

    /**
     * Handles the Include configuration directive.
     *
     */
    public class IncludeHandler implements DirectiveHandler {

        public void handleDirective(Configuration config, Directive directive)
            throws JakException {
            String source = directive.getToken(1);

            try {
                addProvider(new FileDirectiveProvider(source));
            } catch (Exception fnfe) {
                throw new JakException(
                    "Failed to include source " + source + ": " + fnfe.getMessage(),
                    fnfe,
                    directive);
            }
        }
    }

    public Jak() {
        registerDirectiveTemplate("LoadModule", DirectiveTemplate.TAKE12, new LoadModuleHandler());
        registerDirectiveTemplate("<IfModule", DirectiveTemplate.TAKE1, new IfModuleHandler());
        registerDirectiveTemplate("Include", DirectiveTemplate.TAKE1, new IncludeHandler());
    }

    public Jak(String filename) throws Exception {
        this(new FileDirectiveProvider(filename));
    }

    public Jak(DirectiveProvider provider) throws Exception {
        this();

        addProvider(provider);
        processConfiguration();
    }

    public void processConfiguration() throws IOException, JakException {
        Directive d;
        while ((d = getNextDirective()) != null) {
            processDirective(d);
        }
    }

    public void addProvider(DirectiveProvider provider) throws IOException, JakException {
        // check for the recursion
        String newSource = provider.getSource();
        if ((currentProvider != null) && (newSource.compareTo(currentProvider.getSource()) == 0)) {
            throw new JakException("Configuration source " + newSource + " is already being used");
        }

        for (int i = 0; i < providers.size(); i++) {
            DirectiveProvider stackerProvider = (DirectiveProvider)providers.get(i);
            if (newSource.compareTo(stackerProvider.getSource()) == 0)
                throw new JakException(
                    "Configuration source " + newSource + " is already being used");
        }

        // from now on we read directives from the
        // new provider, pushing the old provider
        // on the stack for later
        if (currentProvider != null)
            providers.push(currentProvider);
        currentProvider = provider;
        currentProvider.open();
    }

    public Directive getNextDirective() throws IOException, JakException {
        // get the next directive from the current provider,
        // taking providers off the stack when it runs
        // out of directives
        for (;;) {
            if (currentProvider == null)
                return null;
            Directive d = currentProvider.getNext();
            if (d != null) {
                // System.out.println("Directive found: " + d.getName());
                return d;
            }

            // provider has run out of directives, close
            // it and pop the next one from the stack
            currentProvider.close();
            if (providers.size() != 0)
                currentProvider = (DirectiveProvider)providers.pop();
            else
                currentProvider = null;
        }
    }

    public void processDirective(Directive d) throws IOException, JakException {
        // do nothing for comments
        String text = d.getText().trim();
        if ((text.length() == 0) || (text.charAt(0) == '#'))
            return;

        // find the template for the directive
        DirectiveTemplate dt = getDirectiveTemplate(d);
        if (dt == null) {
            throw new JakException("Unknown directive: " + d.getName(), d);
        }

        dt.verifyArguments(d);

        switch (dt.getArgType()) {
            case DirectiveTemplate.ITERATE :
                for (int i = 1; i < d.getTokenCount(); i++) {
                    String directiveText = d.getName() + " " + d.getToken(i);
                    System.out.println(directiveText);
                    Directive dfake = new Directive("text", d.getSource(), d.getLineNumber());
                    dt.getHandler().handleDirective(this, dfake);
                }
                break;
            case DirectiveTemplate.ITERATE2 :
                for (int i = 2; i < d.getTokenCount(); i++) {
                    String directiveText = d.getName() + " " + d.getToken(1) + d.getToken(i);
                    System.out.println(directiveText);
                    Directive dfake = new Directive("text", d.getSource(), d.getLineNumber());
                    dt.getHandler().handleDirective(this, dfake);
                }
                break;
            default :
                dt.getHandler().handleDirective(this, d);
                break;
        }
    }

    public void registerDirectiveTemplate(DirectiveTemplate directive) {
        directives.put(directive.getName(), directive);
    }

    public void registerDirectiveTemplate(String name, int argType, DirectiveHandler handler) {
        registerDirectiveTemplate(new DirectiveTemplate(name, argType, handler));
    }

    public DirectiveTemplate getDirectiveTemplate(String name) {
        return (DirectiveTemplate)directives.get(name);
    }

    public DirectiveTemplate getDirectiveTemplate(Directive directive) {
        return (DirectiveTemplate)directives.get(directive.getName());
    }

    public void registerModule(String moduleName, Object module) throws JakException {
        if (module instanceof JakModule) {
            JakModule m = (JakModule)module;
            try {
                m.init(this);
            } catch (Exception e) {
                throw new JakException("Unable to initialize module " + moduleName + ": " + e.getMessage(), e);
            }
        }

        modules.put(moduleName, module);
    }

    public Object getModule(String moduleName) {
        return modules.get(moduleName);
    }

    public Object getModule(Class c) {
        Iterator iterator = modules.keySet().iterator();
        while(iterator.hasNext()) {
            Object module = iterator.next();
            if (c.isInstance(module)) return module;
        }
        return null;
    }

    public Object[] getModules(Class c) {
        int count = 0;
        Iterator iterator = modules.values().iterator();
        while(iterator.hasNext()) {
            Object module = iterator.next();
            // System.out.println("module=" + module);
            if (c.isInstance(module)) count++;
        }

        Object[] r = new Object[count];
        count = 0;
        iterator = modules.values().iterator();
        while(iterator.hasNext()) {
            Object module = iterator.next();
            if (c.isInstance(module)) r[count++] = module;
        }

        return r;
    }

    public String getModuleName(Object module) {
        Iterator iterator = modules.keySet().iterator();
        while(iterator.hasNext()) {
            Object o = iterator.next();
            if (modules.get(o) == module) return (String)o;
        }
        return null;
    }

    public void postInit() {}

    public void start() {}

	public void stop() {}

    public void destroy() {}

    public void doPostInit() throws Exception {
        Iterator iterator = modules.values().iterator();
        while(iterator.hasNext()) {
            Object o = iterator.next();
            if (o instanceof JakModule) {
                JakModule module = (JakModule)o;
                module.postInit();
            }
        }
    }

    public void doStart() throws Exception {
        Iterator iterator = modules.values().iterator();
        while(iterator.hasNext()) {
            Object o = iterator.next();
            if (o instanceof JakModule) {
                JakModule module = (JakModule)o;
                module.start();
            }
        }
    }

    public void doStop() {
        Iterator iterator = modules.values().iterator();
        while(iterator.hasNext()) {
            Object o = iterator.next();
            if (o instanceof JakModule) {
                JakModule module = (JakModule)o;
                module.stop();
            }
        }
    }

    public void doDestroy() {
        Iterator iterator = modules.values().iterator();
        while(iterator.hasNext()) {
            Object o = iterator.next();
            if (o instanceof JakModule) {
                JakModule module = (JakModule)o;
                module.destroy();
            }
        }
    }
}
