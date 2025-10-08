package de.ebsnet.crmf.util;

import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;

public class OptionalInteractiveDecryptorProvider implements InputDecryptorProvider {
  private final Optional<char[]> pass;
  private final InteractivePasswordProvider passwordProvider;

  public OptionalInteractiveDecryptorProvider(final Optional<char[]> pass, final Path path) {
    this.pass = Objects.requireNonNull(pass);
    this.passwordProvider = new InteractivePasswordProvider(path);
  }

  @Override
  public InputDecryptor get(final AlgorithmIdentifier algorithm) throws OperatorCreationException {
    final var password = pass.orElseGet(passwordProvider::askPassword);
    return new JceOpenSSLPKCS8DecryptorProviderBuilder()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .build(password)
        .get(algorithm);
  }
}
