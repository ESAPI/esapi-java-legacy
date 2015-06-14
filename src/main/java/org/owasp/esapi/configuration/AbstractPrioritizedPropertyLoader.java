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
    protected void initProperties() {
        properties = new Properties();
        File file = new File(filename);
        if (file.exists() && file.isFile()) {
            loadPropertiesFromFile(file);
        } else {
            System.err.println("Configuration file " + filename + " does not exist");
        }
    }

    /**
     * Method that loads the data from configuration file to properties object.
     * @param file
     */
    protected abstract void loadPropertiesFromFile(File file);
}
