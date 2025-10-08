package de.ebsnet.crmf.util;

import java.nio.file.Path;

public interface InteractivePasswordProvider {
  default char[] askPassword(final Path path) {
    return System.console().readPassword("Enter password for %s: ", path);
  }
}
