package de.ebsnet.crmf.util;

import java.nio.file.Path;
import java.util.Objects;

public class InteractivePasswordProvider {
  private final Path path;

  public InteractivePasswordProvider(final Path path) {
    this.path = Objects.requireNonNull(path);
  }

  public char[] getPassword() {
    return System.console().readPassword("Enter password for %s: ", this.path);
  }
}
