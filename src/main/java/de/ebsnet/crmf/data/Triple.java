package de.ebsnet.crmf.data;

public record Triple<T>(T encryption, T signature, T transport) {}
