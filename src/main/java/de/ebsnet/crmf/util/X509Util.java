package de.ebsnet.crmf.util;

import de.ebsnet.crmf.exception.InvalidCertificateChain;
import java.security.cert.X509Certificate;

public final class X509Util {
  private static final int MIN_CHAIN_LENGTH = 2;

  // TODO: this is a good candidate for unit testing
  public static void validateCertificateChain(final X509Certificate... chain)
      throws InvalidCertificateChain {
    if (chain.length < MIN_CHAIN_LENGTH) {
      throw new InvalidCertificateChain(
          "supplied certificate chain must contain at least "
              + MIN_CHAIN_LENGTH
              + " certificates to be complete. Got "
              + chain.length);
    }
    for (int idx = 0; idx < chain.length - 1; idx++) {
      if (!chain[idx].getIssuerX500Principal().equals(chain[idx + 1].getSubjectX500Principal())) {
        throw new InvalidCertificateChain(
            chain[idx].getSubjectX500Principal()
                + " is not signed by "
                + chain[idx + 1].getSubjectX500Principal());
      }
    }

    final var root = chain[chain.length - 1];
    final var endsWithRoot = root.getSubjectX500Principal().equals(root.getIssuerX500Principal());
    if (!endsWithRoot) {
      throw new InvalidCertificateChain(
          "Certificate chain does not end with root certificate. Ends with "
              + root.getSubjectX500Principal());
    }
  }

  private X509Util() {}
}
