package de.ebsnet.crmf.exception;

import java.io.Serial;

public final class InvalidCertificateChain extends Exception {
  @Serial private static final long serialVersionUID = -1135272886431567727L;

  public InvalidCertificateChain(final String message) {
    super(message);
  }

  public InvalidCertificateChain(final Throwable cause) {
    super(cause);
  }

  public InvalidCertificateChain(final String message, final Throwable cause) {
    super(message, cause);
  }
}
