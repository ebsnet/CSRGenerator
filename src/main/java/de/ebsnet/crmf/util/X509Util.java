package de.ebsnet.crmf.util;

import de.ebsnet.crmf.exception.InvalidCertificateChain;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
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

  /** Load a certificate chain from a file. */
  public static X509Certificate[] loadCertificateChain(final Path path)
      throws CertificateException, IOException {
    try (var inStream = Files.newInputStream(path)) {
      return loadCertificateChain(inStream);
    }
  }

  /** Load a certificate chain from memory. */
  public static X509Certificate[] loadCertificateChain(final byte[] cert)
      throws CertificateException, IOException {
    try (var inStream = new ByteArrayInputStream(cert)) {
      return loadCertificateChain(inStream);
    }
  }

  private static X509Certificate[] loadCertificateChain(final InputStream inStream)
      throws CertificateException {
    final var fact = CertificateFactory.getInstance("X.509");
    return fact.generateCertificates(inStream).stream()
        .map(c -> (X509Certificate) c)
        .toArray(X509Certificate[]::new);
  }

  private X509Util() {}
}
