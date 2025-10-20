package de.ebsnet.crmf.data;

import java.util.stream.Stream;

public record Triple<T>(T encryption, T signature, T transport) {
  public Stream<T> stream() {
    return Stream.of(encryption, signature, transport);
  }
}
