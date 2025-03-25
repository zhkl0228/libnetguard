package com.twitter.http2;

import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.DefaultHttpHeadersFactory;
import io.netty.handler.codec.http.HttpHeaders;

import java.util.*;

public class NetGuardHttp2Headers extends DefaultHttpHeaders {

    public NetGuardHttp2Headers() {
        super(DefaultHttpHeadersFactory.headersFactory().withNameValidation(false).getNameValidator(),
                DefaultHttpHeadersFactory.headersFactory().withValidation(false).getValueValidator());
    }

    private Set<String> getNamesOrder(CharSequence name) {
        if (!contains(name)) {
            return null;
        }
        List<Map.Entry<String, String>> entries = entries();
        Set<String> names = new LinkedHashSet<>(entries.size());
        for (Map.Entry<String, String> entry : entries) {
            names.add(entry.getKey());
        }
        return names;
    }

    private void restoreNamesOrder(Set<String> names) {
        if (names == null) {
            return;
        }
        Map<String, List<String>> map = new LinkedHashMap<>(names.size());
        for (String name : names) {
            List<String> values = getAll(name);
            map.put(name, values);
        }
        clear();
        for(Map.Entry<String, List<String>> entry : map.entrySet()) {
            String name = entry.getKey();
            List<String> values = entry.getValue();
            add(name, values);
        }
    }

    @Override
    public HttpHeaders set(String name, Object value) {
        Set<String> names = getNamesOrder(name);
        HttpHeaders self = super.set(name, value);
        restoreNamesOrder(names);
        return self;
    }

    @Override
    public HttpHeaders set(CharSequence name, Object value) {
        Set<String> names = getNamesOrder(name);
        HttpHeaders self = super.set(name, value);
        restoreNamesOrder(names);
        return self;
    }

    @Override
    public HttpHeaders set(String name, Iterable<?> values) {
        Set<String> names = getNamesOrder(name);
        HttpHeaders self = super.set(name, values);
        restoreNamesOrder(names);
        return self;
    }

    @Override
    public HttpHeaders set(CharSequence name, Iterable<?> values) {
        Set<String> names = getNamesOrder(name);
        HttpHeaders self = super.set(name, values);
        restoreNamesOrder(names);
        return self;
    }

    @Override
    public HttpHeaders setInt(CharSequence name, int value) {
        Set<String> names = getNamesOrder(name);
        HttpHeaders self = super.setInt(name, value);
        restoreNamesOrder(names);
        return self;
    }

    @Override
    public HttpHeaders setShort(CharSequence name, short value) {
        Set<String> names = getNamesOrder(name);
        HttpHeaders self = super.setShort(name, value);
        restoreNamesOrder(names);
        return self;
    }

}
