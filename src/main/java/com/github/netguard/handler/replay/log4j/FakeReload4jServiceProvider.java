package com.github.netguard.handler.replay.log4j;

import org.slf4j.ILoggerFactory;
import org.slf4j.reload4j.FakeReload4jLoggerFactory;
import org.slf4j.reload4j.Reload4jServiceProvider;

public class FakeReload4jServiceProvider extends Reload4jServiceProvider {

    private FakeReload4jLoggerFactory loggerFactory;

    @Override
    public void initialize() {
        loggerFactory = new FakeReload4jLoggerFactory();
    }

    @Override
    public ILoggerFactory getLoggerFactory() {
        return loggerFactory;
    }

}
