package de.ebsnet.crmf;

import java.net.URISyntaxException;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.util.Objects;
import java.util.Optional;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/* default */ final class PEM2PKCS12Test {
  private static final String KEY_A = "/keyAndCert/a.key";
  private static final String KEY_B = "/keyAndCert/b.key";
  private static final String CERT_A = "/keyAndCert/a.cer";

  static {
    CSRGenerator.init();
  }

  private final Path keyA;
  private final Path keyB;
  private final Path certA;

  /* default */ PEM2PKCS12Test() throws URISyntaxException {
    this.keyA = Path.of(Objects.requireNonNull(getClass().getResource(KEY_A)).toURI());
    this.keyB = Path.of(Objects.requireNonNull(getClass().getResource(KEY_B)).toURI());
    this.certA = Path.of(Objects.requireNonNull(getClass().getResource(CERT_A)).toURI());
  }

  @Test
  /* default */ void matchingKeyAndCert() {
    Assertions.assertDoesNotThrow(
        () ->
            PEM2PKCS12.pemToPKCS12(
                this.keyA, Optional.empty(), this.certA, "alias", "pass".toCharArray()),
        "KeyStore for matching private key and certificate works");
  }

  @Test
  /* default */ void certAndKeyMissmatch() {
    Assertions.assertThrows(
        CertificateException.class,
        () ->
            PEM2PKCS12.pemToPKCS12(
                this.keyB, Optional.empty(), this.certA, "alias", "pass".toCharArray()),
        "KeyStore must not be created when private key and certificate do not match");
  }
}
