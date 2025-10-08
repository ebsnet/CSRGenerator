package de.ebsnet.crmf;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Optional;
import picocli.CommandLine.Option;

/** Base for all subcommands */
public class BaseCommand {
  @Option(
      names = {"--encryption"},
      required = true,
      description =
          "Path to the PEM encoded encryption private key (MUST be a new key. Old keys must not be reused)")
  protected Path encPath;

  @Option(
      names = {"--encryption-pass"},
      description = "Password for the encryption key")
  private Optional<char[]> encPass;

  @Option(
      names = {"--signature"},
      required = true,
      description =
          "Path to the PEM encoded signature private key (MUST be a new key. Old keys must not be reused)")
  protected Path sigPath;

  @Option(
      names = {"--signature-pass"},
      description = "Password for the signature key")
  private Optional<char[]> sigPass;

  @Option(
      names = {"--tls"},
      required = true,
      description =
          "Path to the PEM encoded TLS private key (MUST be a new key. Old keys must not be reused)")
  protected Path tlsPath;

  @Option(
      names = {"--tls-pass"},
      description = "Password for the TLS key")
  private Optional<char[]> tlsPass;

  @Option(
      names = {"--key-pass"},
      description =
          "Password if it's the same for all keys. If the specific `--signature-pass`, `--encryption-pass` or `--tls-pass` parameters are set, those are used.")
  private Optional<char[]> keyPass;

  @Option(
      names = {"--out"},
      required = true,
      description = "Path to write the CSR to")
  protected Path out;

  protected BaseCommand() {
    // this class can only be instantiated from an extending class
  }

  @SuppressWarnings("PMD.UselessParentheses") // false positive
  protected Optional<char[]> passForType(final KeyType keyType) {
    return (switch (keyType) {
          case SIG -> this.sigPass;
          case ENC -> this.encPass;
          case TLS -> this.tlsPass;
        })
        .or(() -> this.keyPass);
  }

  /**
   * Load a certificate chain from a file.
   *
   * @param path
   * @return
   * @throws CertificateException
   * @throws IOException
   */
  /* default */ static X509Certificate[] loadCertificateChain(final Path path)
      throws CertificateException, IOException {
    final var fact = CertificateFactory.getInstance("X.509");
    try (var inStream = Files.newInputStream(path)) {
      return fact.generateCertificates(inStream).stream()
          .map(c -> (X509Certificate) c)
          .toArray(X509Certificate[]::new);
    }
  }
}
