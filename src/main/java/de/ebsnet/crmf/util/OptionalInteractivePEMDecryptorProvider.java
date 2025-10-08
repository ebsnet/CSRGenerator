package de.ebsnet.crmf.util;

import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;
import org.bouncycastle.openssl.PEMDecryptor;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;

/** {@link PEMDecryptorProvider} that interactively asks the user for a password. */
public final class OptionalInteractivePEMDecryptorProvider implements PEMDecryptorProvider {
  private final Optional<char[]> pass;
  private final InteractivePasswordProvider passwordProvider;

  /**
   * @param path Path to the file to be decrypted. This is printed in the password prompt.
   */
  public OptionalInteractivePEMDecryptorProvider(final Optional<char[]> pass, final Path path) {
    this.pass = Objects.requireNonNull(pass);
    this.passwordProvider = new InteractivePasswordProvider(path);
  }

  @Override
  public PEMDecryptor get(final String dekAlgName) {
    return (data, iv) ->
        new BcPEMDecryptorProvider(this.pass.orElseGet(passwordProvider::getPassword))
            .get(dekAlgName)
            .decrypt(data, iv);
  }
}
