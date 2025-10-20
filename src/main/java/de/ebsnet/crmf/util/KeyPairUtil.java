package de.ebsnet.crmf.util;

import de.ebsnet.crmf.exception.CannotLoadKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Optional;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

public final class KeyPairUtil {
  /**
   * Load an EC keypair from disk.
   *
   * @param path
   * @return
   * @throws IOException
   */
  @SuppressWarnings("PMD.OnlyOneReturn")
  public static KeyPair loadKeyPair(final Path path, final Optional<char[]> pass)
      throws IOException {
    try (var parser = new PEMParser(Files.newBufferedReader(path))) {
      for (var parsed = parser.readObject(); parsed != null; parsed = parser.readObject()) {
        if (parsed instanceof PEMKeyPair pkp) {
          return loadPEMKeyPair(pkp);
        } else if (parsed instanceof PEMEncryptedKeyPair pekp) {
          return loadPEMEncryptedKeyPair(pekp, path, pass);
        } else if (parsed instanceof PrivateKeyInfo privateKeyInfo) {
          return loadECKeyPair(privateKeyInfo);
        } else if (parsed instanceof PKCS8EncryptedPrivateKeyInfo p8epki) {
          return loadPKCS8EncryptedKeyPair(p8epki, path, pass);
        }
      }
      throw new CannotLoadKey("unsupported key format");
    }
  }

  private static KeyPair loadPKCS8EncryptedKeyPair(
      final PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo,
      final Path path,
      final Optional<char[]> pass)
      throws IOException {
    try {
      final var decrypted =
          encryptedPrivateKeyInfo.decryptPrivateKeyInfo(
              new OptionalInteractiveDecryptorProvider(pass, path));
      return loadECKeyPair(decrypted);
    } catch (PKCSException e) {
      throw new CannotLoadKey("cannot decrypt private key", e);
    }
  }

  private static KeyPair loadECKeyPair(final PrivateKeyInfo privateKeyInfo) throws CannotLoadKey {
    try {
      final var keyFactory =
          new NamedJcaJceHelper(BouncyCastleProvider.PROVIDER_NAME).createKeyFactory("EC");
      final var privateKey =
          keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded()));

      if (privateKey instanceof ECPrivateKey ecPrivateKey) {
        final var wrapped =
            org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(
                    privateKeyInfo.getPrivateKey().getOctets())
                .getPublicKey();
        final var publicKey =
            keyFactory.generatePublic(
                new X509EncodedKeySpec(
                    new SubjectPublicKeyInfo(privateKeyInfo.getPrivateKeyAlgorithm(), wrapped)
                        .getEncoded()));
        return new KeyPair(publicKey, ecPrivateKey);
      }
    } catch (IOException
        | InvalidKeySpecException
        | NoSuchAlgorithmException
        | NoSuchProviderException e) {
      throw new CannotLoadKey("unable to convert key pair: " + e.getMessage(), e);
    }
    throw new CannotLoadKey("does not look like a EC key");
  }

  private static KeyPair loadPEMEncryptedKeyPair(
      final PEMEncryptedKeyPair pemEncryptedKeyPair, final Path path, final Optional<char[]> pass)
      throws IOException {
    return loadPEMKeyPair(
        pemEncryptedKeyPair.decryptKeyPair(new OptionalInteractiveDecryptorProvider(pass, path)));
  }

  private static KeyPair loadPEMKeyPair(final PEMKeyPair pemKeyPair) throws PEMException {
    return new JcaPEMKeyConverter()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .getKeyPair(pemKeyPair);
  }

  private KeyPairUtil() {}
}
