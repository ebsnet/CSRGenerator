package de.ebsnet.crmf.util;

import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptor;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;

/**
 * {@link InputDecryptorProvider} that uses an {@link Optional} password or asks the user to enter
 * the password.
 */
public class OptionalInteractiveDecryptorProvider
    implements InputDecryptorProvider, PEMDecryptorProvider, InteractivePasswordProvider {
  private final Optional<char[]> pass;
  private final Path path;

  public OptionalInteractiveDecryptorProvider(final Optional<char[]> pass, final Path path) {
    this.pass = Objects.requireNonNull(pass);
    this.path = Objects.requireNonNull(path);
  }

  private char[] password() {
    return pass.orElseGet(() -> this.askPassword(path));
  }

  @Override
  public InputDecryptor get(final AlgorithmIdentifier algorithm) throws OperatorCreationException {
    return new JceOpenSSLPKCS8DecryptorProviderBuilder()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .build(password())
        .get(algorithm);
  }

  @Override
  public PEMDecryptor get(final String dekAlgName) {
    return (data, iv) -> new BcPEMDecryptorProvider(password()).get(dekAlgName).decrypt(data, iv);
  }
}
