package de.ebsnet.crmf.util;

import java.nio.file.Path;

public record InteractivePasswordProvider(Path path) {
  public char[] askPassword() {
    return System.console().readPassword("Enter password for %s: ", this.path);
  }
}
