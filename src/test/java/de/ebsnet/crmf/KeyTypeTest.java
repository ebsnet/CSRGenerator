package de.ebsnet.crmf;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/* default */ final class KeyTypeTest {
  private static final String ENC = "/certType/enc.cer";
  private static final String SIG = "/certType/sig.cer";
  private static final String TLS = "/certType/tls.cer";

  static {
    CSRGenerator.init();
  }

  private final Path enc;
  private final Path sig;
  private final Path tls;

  /* default */ KeyTypeTest() throws URISyntaxException {
    this.enc = Path.of(Objects.requireNonNull(getClass().getResource(ENC)).toURI());
    this.sig = Path.of(Objects.requireNonNull(getClass().getResource(SIG)).toURI());
    this.tls = Path.of(Objects.requireNonNull(getClass().getResource(TLS)).toURI());
  }

  @Test
  /* default */ void detectEnc() throws IOException {
    final var keyType = KeyType.fromCertificate(Files.readAllBytes(enc));
    Assertions.assertEquals(
        Optional.of(KeyType.ENC), keyType, "expected to detect encryption certificate");
  }

  @Test
  /* default */ void detectSig() throws IOException {
    final var keyType = KeyType.fromCertificate(Files.readAllBytes(sig));
    Assertions.assertEquals(
        Optional.of(KeyType.SIG), keyType, "expected to detect signature certificate");
  }

  @Test
  /* default */ void detectTls() throws IOException {
    final var keyType = KeyType.fromCertificate(Files.readAllBytes(tls));
    Assertions.assertEquals(
        Optional.of(KeyType.TLS), keyType, "expected to detect transport certificate");
  }
}
