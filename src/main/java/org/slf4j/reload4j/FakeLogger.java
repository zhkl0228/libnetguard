package org.slf4j.reload4j;

import com.github.netguard.handler.replay.Replay;
import org.apache.log4j.Appender;
import org.apache.log4j.Logger;
import org.apache.log4j.Priority;
import org.apache.log4j.spi.LoggingEvent;

import java.util.Date;
import java.util.Enumeration;

class FakeLogger extends Logger {

    FakeLogger(String name, Logger logger) {
        super(name);
        if (logger != null) {
            this.repository = logger.getLoggerRepository();
            this.level = logger.getLevel();
            this.additive = logger.getAdditivity();
            this.parent = logger.getParent();
            this.resourceBundle = logger.getResourceBundle();
            Enumeration<?> enumeration = logger.getAllAppenders();
            while (enumeration.hasMoreElements()) {
                Appender appender = (Appender) enumeration.nextElement();
                addAppender(appender);
            }
        }
    }

    @Override
    protected void forcedLog(String fqcn, Priority level, Object message, Throwable t) {
        Date date = Replay.getReplayLogDate();
        LoggingEvent event = date == null ?
                new LoggingEvent(fqcn, this, level, message, t) :
                new LoggingEvent(fqcn, this, date.getTime(), level, message, t);
        callAppenders(event);
    }
}
