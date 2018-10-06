package org.owasp.esapi.configuration;


import java.io.File;
import java.util.Properties;

public abstract class AbstractPrioritizedPropertyLoader implements EsapiPropertyLoader,
        Comparable<AbstractPrioritizedPropertyLoader> {

    protected final String filename;
    protected Properties properties;

    private final int priority;

    public AbstractPrioritizedPropertyLoader(String filename, int priority) {
        this.priority = priority;
        this.filename = filename;
        initProperties();
    }

    /**
     * Get priority of this property loader. If two and more loaders can return value for the same property key,
     * the one with highest priority will be chosen.
     * @return priority of this property loader
     */
    public int priority() {
        return priority;
    }

    @Override
    public int compareTo(AbstractPrioritizedPropertyLoader compared) {
        if (this.priority > compared.priority()) {
            return 1;
        } else if (this.priority < compared.priority()) {
            return -1;
        }
        return 0;
    }

    public String name() {
        return filename;
    }

    /**
     * Initializes properties object and fills it with data from configuration file.
     */
    private void initProperties() {
        properties = new Properties();
        File file = new File(filename);
        if (file.exists() && file.isFile()) {
            loadPropertiesFromFile(file);
        } else {
            logSpecial("Configuration file " + filename + " does not exist");
        }
    }

    /**
     * Method that loads the data from configuration file to properties object.
     * @param file
     */
    protected abstract void loadPropertiesFromFile(File file);

    /**
     * Used to log errors to the console during the loading of the properties file itself. Can't use
     * standard logging in this case, since the Logger may not be initialized yet. Output is sent to
     * {@code PrintStream} {@code System.out}.  Output is discarded if the {@code System} property
     * "org.owasp.esapi.logSpecial.discard" is set to {@code true}.
     *
     * @param msg The message to log to the console.
     * @param t   Associated exception that was caught.
     */
    protected final void logSpecial(String msg, Throwable t) {
        // Note: It is really distasteful to tie this class to DefaultSecurityConfiguration
        //       like this, but the alternative is to move the logSpecial() and
        //       logToStdout() some utilities class and that is even more
        //       distasteful because it may encourage people to use these. -kwwall
        org.owasp.esapi.reference.DefaultSecurityConfiguration.logToStdout(msg, t);
    }

    /**
     * Used to log errors to the console during the loading of the properties file itself. Can't use
     * standard logging in this case, since the Logger may not be initialized yet. Output is sent to
     * {@code PrintStream} {@code System.out}.  Output is discarded if the {@code System} property
     * "org.owasp.esapi.logSpecial.discard" is set to {@code true}.
     *
     * @param msg The message to log to the console.
     */
    protected final void logSpecial(String msg) {
        logSpecial(msg, null);
    }
}
