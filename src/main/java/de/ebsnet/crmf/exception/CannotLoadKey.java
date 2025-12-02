package de.ebsnet.crmf.exception;

import java.io.IOException;
import java.io.Serial;

public class CannotLoadKey extends IOException {
  @Serial private static final long serialVersionUID = 600519096708602623L;

  public CannotLoadKey(final String message) {
    super(message);
  }

  public CannotLoadKey(final String message, final Throwable cause) {
    super(message, cause);
  }
}
