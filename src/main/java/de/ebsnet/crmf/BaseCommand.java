package de.ebsnet.crmf;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
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
      names = {"--signature"},
      required = true,
      description =
          "Path to the PEM encoded signature private key (MUST be a new key. Old keys must not be reused)")
  protected Path sigPath;

  @Option(
      names = {"--tls"},
      required = true,
      description =
          "Path to the PEM encoded TLS private key (MUST be a new key. Old keys must not be reused)")
  protected Path tlsPath;

  @Option(
      names = {"--out"},
      required = true,
      description = "Path to write the CSR to")
  protected Path out;

  protected BaseCommand() {
    // this class can only be instantiated from an extending class
  }

  /**
   * Load a PEM encoded EC keypair from disk.
   *
   * @param path
   * @return
   * @throws IOException
   */
  public static KeyPair loadKeyPair(final Path path) throws IOException {
    try (var parser = new PEMParser(Files.newBufferedReader(path))) {
      var parsed = parser.readObject();
      while (parsed != null && !(parsed instanceof PEMKeyPair)) {
        parsed = parser.readObject();
      }
      if (parsed != null) {
        return new JcaPEMKeyConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getKeyPair((PEMKeyPair) parsed);
      } else {
        throw new IllegalArgumentException("not a PEM encoded EC key.");
      }
    }
  }

  /**
   * Load a single certificate from a file. If the file contains a certificate chain, the first
   * certificate of the chain is returned.
   *
   * @param path
   * @return
   * @throws CertificateException
   * @throws IOException
   */
  public static X509Certificate loadCertificate(final Path path)
      throws CertificateException, IOException {
    return loadCertificateChain(path)[0];
  }

  /**
   * Load a certificate chain from a file.
   *
   * @param path
   * @return
   * @throws CertificateException
   * @throws IOException
   */
  public static X509Certificate[] loadCertificateChain(final Path path)
      throws CertificateException, IOException {
    final var fact = CertificateFactory.getInstance("X.509");
    try (var inStream = Files.newInputStream(path)) {
      return fact.generateCertificates(inStream).stream()
          .map(c -> (X509Certificate) c)
          .toArray(X509Certificate[]::new);
    }
  }
}
