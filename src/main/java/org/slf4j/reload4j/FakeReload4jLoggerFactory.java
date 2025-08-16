package org.slf4j.reload4j;

import org.apache.log4j.LogManager;
import org.apache.log4j.spi.LoggerFactory;
import org.slf4j.Logger;

public class FakeReload4jLoggerFactory extends Reload4jLoggerFactory implements LoggerFactory {

    @Override
    public Logger getLogger(String name) {
        Logger slf4jLogger = loggerMap.get(name);
        if (slf4jLogger != null) {
            return slf4jLogger;
        } else {
            org.apache.log4j.Logger log4jLogger;
            if (name.equalsIgnoreCase(Logger.ROOT_LOGGER_NAME)) {
                log4jLogger = LogManager.getRootLogger();
            } else {
                log4jLogger = LogManager.getLogger(name, this);

                if (!(log4jLogger instanceof FakeLogger)) {
                    log4jLogger = new FakeLogger(name, log4jLogger);
                }
            }

            Logger newInstance = new Reload4jLoggerAdapter(log4jLogger);
            Logger oldInstance = loggerMap.putIfAbsent(name, newInstance);
            return oldInstance == null ? newInstance : oldInstance;
        }
    }

    @Override
    public org.apache.log4j.Logger makeNewLoggerInstance(String name) {
        return new FakeLogger(name, null);
    }

}
