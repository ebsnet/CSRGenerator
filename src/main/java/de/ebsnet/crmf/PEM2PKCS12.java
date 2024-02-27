package de.ebsnet.crmf;

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
import java.util.List;
import java.util.concurrent.Callable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(
    name = "pem2p12",
    mixinStandardHelpOptions = true,
    description = "Convert key pair and certificate in PEM format to a PKCS12 keystore")
public final class PEM2PKCS12 implements Callable<Void> {
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
      throws CertificateException, IOException, KeyStoreException, NoSuchProviderException,
          NoSuchAlgorithmException {
    final var keyStore = loadKeyStore(this.out, this.keyStorePass);
    if (keyStore.containsAlias(this.alias)) {
      throw new IllegalStateException("alias already exists in the keystore");
    }
    final var keyPair = BaseCommand.loadKeyPair(this.keyPairPath);
    final var certificate = BaseCommand.loadCertificateChain(this.certificatePath);
    final var chain = new ArrayList<>(List.of(certificate));

    for (final var trustedCert : trusted) {
      chain.addAll(List.of(BaseCommand.loadCertificateChain(trustedCert)));
    }

    keyStore.setKeyEntry(
        this.alias, keyPair.getPrivate(), this.keyStorePass, chain.toArray(new X509Certificate[0]));
    //    final var entry =
    //        new KeyStore.PrivateKeyEntry(
    //            keyPair.getPrivate(), chain.toArray(chain.toArray(new X509Certificate[0])));
    //    final var protectionParams = new KeyStore.PasswordProtection(this.keyStorePass);
    //    keyStore.setEntry(this.alias, entry, protectionParams);

    try (var outStream = Files.newOutputStream(this.out, StandardOpenOption.CREATE_NEW)) {
      keyStore.store(outStream, this.keyStorePass);
    }
    return null;
  }

  private static KeyStore loadKeyStore(final Path path, final char[] pass)
      throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException,
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
      final Path key, final Path cert, final String alias, final char[] pass)
      throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException,
          NoSuchProviderException {
    final var keyPair = BaseCommand.loadKeyPair(key);
    final var certificate = BaseCommand.loadCertificateChain(cert);
    final var ks = loadKeyStore(null, pass);
    ks.setKeyEntry(alias, keyPair.getPrivate(), "123456".toCharArray(), certificate);
    return ks;
  }
}
