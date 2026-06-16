package com.example.employee.util;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.ImmutableList;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public class GuavaUtil {
    private static final LoadingCache<String, ImmutableList<String>> cache = CacheBuilder.newBuilder()
            .expireAfterWrite(10, TimeUnit.MINUTES)
            .maximumSize(100)
            .build(new CacheLoader<>() {
                @Override
                public ImmutableList<String> load(String key) {
                    return ImmutableList.of(key);
                }
            });

    public static ImmutableList<String> getImmutableList(String key) {
        try {
            return cache.get(key);
        } catch (ExecutionException e) {
            return ImmutableList.of();
        }
    }
}
