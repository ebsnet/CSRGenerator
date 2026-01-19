package de.ebsnet.crmf;

import de.ebsnet.crmf.exception.InvalidCertificateChain;
import de.ebsnet.crmf.util.KeyPairUtil;
import de.ebsnet.crmf.util.X509Util;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/** Subcommand to convert a PEM encoded key pair and certificate into a single PKCS12 keystore. */
@Command(
    name = "pem2p12",
    mixinStandardHelpOptions = true,
    description = "Convert key pair and certificate in PEM format to a PKCS12 keystore")
public final class PEM2PKCS12 implements Callable<Void> {

  private static final Logger LOG = Logger.getLogger(PEM2PKCS12.class.getSimpleName());

  @Option(
      names = {"--out"},
      required = true,
      description = "Path to write the keystore to. If it already exists, the key is added")
  private Path out;

  @Option(
      names = {"--keypair"},
      required = true,
      description = "Path to the PEM key pair")
  private Path keyPairPath;

  @Option(
      names = {"--keypair-pass"},
      description = "Password for the PEM key pair")
  private Optional<char[]> keyPairPass;

  @Option(
      names = {"--certificate"},
      required = true,
      description = "Path to the PEM certificate")
  private Path certificatePath;

  @Option(
      names = {"--password"},
      required = true,
      description = "Key store password")
  private char[] keyStorePass;

  @Option(
      names = {"--trusted"},
      description =
          "Trust chain of the certificate. Chain is built in the order, the trusted certificates are passed.")
  private List<Path> trusted;

  @Option(
      names = {"--alias"},
      required = true,
      description = "Alias inside the keystore")
  private String alias;

  @Override
  public Void call()
      throws CertificateException,
          IOException,
          KeyStoreException,
          NoSuchProviderException,
          NoSuchAlgorithmException {
    try {
      final var keyStore = loadKeyStore(this.out, this.keyStorePass);
      if (keyStore.containsAlias(this.alias)) {
        throw new IllegalStateException("alias already exists in the keystore");
      }
      final var keyPair = KeyPairUtil.loadKeyPair(this.keyPairPath, this.keyPairPass);
      final var certificate = X509Util.loadCertificateChain(this.certificatePath);
      final var chain = new ArrayList<>(List.of(certificate));

      for (final var trustedCert : trusted) {
        chain.addAll(List.of(X509Util.loadCertificateChain(trustedCert)));
      }

      X509Util.validateCertificateChain(chain.toArray(new X509Certificate[0]));

      keyStore.setKeyEntry(
          this.alias,
          keyPair.getPrivate(),
          this.keyStorePass,
          chain.toArray(new X509Certificate[0]));

      try (var outStream = Files.newOutputStream(this.out, StandardOpenOption.CREATE_NEW)) {
        keyStore.store(outStream, this.keyStorePass);
      }
    } catch (InvalidCertificateChain ex) {
      LOG.severe(() -> "invalid certificate chain: " + ex.getMessage());
    }
    return null;
  }

  /**
   * Load a {@link KeyStore} from a file or initialize a new one in memory if {@code path} is {@code
   * null}.
   *
   * @param path
   * @param pass
   * @return
   * @throws CertificateException
   * @throws IOException
   * @throws NoSuchAlgorithmException
   * @throws KeyStoreException
   * @throws NoSuchProviderException
   */
  private static KeyStore loadKeyStore(final Path path, final char... pass)
      throws CertificateException,
          IOException,
          NoSuchAlgorithmException,
          KeyStoreException,
          NoSuchProviderException {
    final var keyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
    if (null != path && path.toFile().isFile()) {
      try (var stream = Files.newInputStream(path)) {
        keyStore.load(stream, pass);
      }
    } else {
      keyStore.load(null, pass);
    }
    return keyStore;
  }

  public static KeyStore pemToPKCS12(
      final Path key,
      final Optional<char[]> keyPass,
      final Path cert,
      final String alias,
      final char... pass)
      throws KeyStoreException,
          CertificateException,
          IOException,
          NoSuchAlgorithmException,
          NoSuchProviderException {
    final var keyPair = KeyPairUtil.loadKeyPair(key, keyPass);
    final var certificate = X509Util.loadCertificateChain(cert);
    final var kpPub = keyPair.getPublic();
    final var cerPub = certificate[0].getPublicKey();
    if (!Objects.equals(kpPub, cerPub)) {
      final var encoder = Base64.getEncoder();
      final var message =
          "KeyPair - Certificate Missmatch. Got KeyPair with PubKey: "
              + encoder.encodeToString(kpPub.getEncoded())
              + " certificate with PubKey: "
              + encoder.encodeToString(cerPub.getEncoded());
      throw new CertificateException(message);
    }
    final var keyStore = loadKeyStore(null, pass);
    keyStore.setKeyEntry(alias, keyPair.getPrivate(), pass, certificate);
    return keyStore;
  }
}
