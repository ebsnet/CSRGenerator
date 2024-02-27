package de.ebsnet.crmf;

import java.io.IOException;
import java.util.Properties;
import picocli.CommandLine;

public final class VersionProvider implements CommandLine.IVersionProvider {
  @Override
  public String[] getVersion() {
    return new String[] {ValueHolder.VERSION};
  }

  private static final class ValueHolder {
    private static final String VERSION;

    static {
      String version;
      try (var in = CSRGenerator.class.getClassLoader().getResourceAsStream("version.properties")) {
        final var prop = new Properties();
        prop.load(in);
        version = prop.getProperty("version", "0.0.0");
      } catch (final IOException ex) {
        version = "-0.0.0";
      }
      VERSION = version;
    }
  }
}
