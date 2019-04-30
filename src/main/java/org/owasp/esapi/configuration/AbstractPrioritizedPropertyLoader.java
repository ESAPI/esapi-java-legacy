package org.owasp.esapi.configuration;


import java.io.File;
import java.util.Properties;

/**
 * Abstrace class that supports two "levels" of priorities for ESAPI properties.
 * The higher level is the property file supported by an "operations" team and
 * the lower level is the property file intended to be supported by the
 * "development" team. ESAPI properties defined in the lower level properties
 * file cannot supersede properties defined in the higher level properties file.
 *
 * The intent os to place ESAPI properties related to enterprise-wide security
 * policy (e.g., the minimum sized encryption key,
 * <b>Encryptor.MinEncryptionKeyLength</b> in the higher level so the
 * development team cannot dumb down the policy, either accidentally or
 * intentionally. (This of course requires that the developers don't provide the
 * operations team the properties file for them to use. :) This is also good for
 * allowing the productions operations team to select property values for
 * properties such as <b>Encryptor.MasterKey</b> and <b>Encryptor.MasterSalt</b>
 * so that they are only on a "need-to-know" basis and don't accidentally get
 * committed to the development team's SCM repository.
 *
 * @since 2.2
 */
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
