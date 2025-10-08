package de.ebsnet.crmf.util;

import java.nio.file.Path;
import java.util.Objects;
import org.bouncycastle.openssl.PEMDecryptor;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;

/** {@link PEMDecryptorProvider} that interactively asks the user for a password. */
public final class PEMAskPassDecryptorProvider implements PEMDecryptorProvider {
  /** Path to the file to be decrypted. This is printed in the password prompt. */
  private final Path keyPath;

  /**
   * @param path Path to the file to be decrypted. This is printed in the password prompt.
   */
  public PEMAskPassDecryptorProvider(final Path path) {
    this.keyPath = Objects.requireNonNull(path);
  }

  @Override
  public PEMDecryptor get(final String dekAlgName) {
    return (data, iv) -> {
      final var pass = System.console().readPassword("Enter password for %s: ", keyPath);
      return new BcPEMDecryptorProvider(pass).get(dekAlgName).decrypt(data, iv);
    };
  }
}
