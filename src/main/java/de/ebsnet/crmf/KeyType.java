package de.ebsnet.crmf;

import de.ebsnet.crmf.util.X509Util;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;

/** Key Types in an SM-PKI certificate triple. */
@SuppressWarnings("PMD.OnlyOneReturn")
public enum KeyType {

  /** Signature key. */
  SIG("_sig.pem"),
  /** Encryption key. */
  ENC("_enc.pem"),
  /** TLS key. */
  TLS("_tls.pem");

  /** position of digitalSignature value */
  private static final int KEY_USAGE_SIG = 0;

  /** position of keyEncipherment value */
  private static final int KEY_USAGE_KEY_ENCIPHERMENT = 2;

  /** position of keyAgreement value */
  private static final int KEY_USAGE_KEY_AGREEMENT = 4;

  /** indicates start of certificate */
  private static final String PEM_BEGIN = "-----BEGIN CERTIFICATE-----\n";

  /** indicates end of certificate */
  private static final String PEM_END = "\n-----END CERTIFICATE-----";

  private final String filename;

  KeyType(final String filename) {
    this.filename = filename;
  }

  public String filename() {
    return this.filename;
  }

  /**
   * Get the required {@link KeyUsage} flags for each {@link KeyType}.
   *
   * @return
   */
  public KeyUsage keyUsage() {
    return switch (this) {
      case ENC -> new KeyUsage(KeyUsage.keyAgreement | KeyUsage.keyEncipherment);
      case SIG, TLS -> new KeyUsage(KeyUsage.digitalSignature);
    };
  }

  /**
   * Some {@link KeyType}s also have {@link ExtendedKeyUsage} attributes.
   *
   * @return
   */
  public Optional<ExtendedKeyUsage> extendedKeyUsage() {
    return switch (this) {
      case TLS ->
          Optional.of(
              new ExtendedKeyUsage(
                  new KeyPurposeId[] {
                    KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth
                  }));
      case ENC, SIG -> Optional.empty();
    };
  }

  public static Optional<KeyType> fromCertificate(final byte[] cert) {
    try {
      final var chain = X509Util.loadCertificateChain(cert);
      return chain.length > 0 ? fromCertificate(chain[0]) : Optional.empty();
    } catch (CertificateException | IOException e) {
      return Optional.empty();
    }
  }

  public static Optional<KeyType> fromCertificate(final X509Certificate cert) {
    try {
      // TLS: extended keyUsage, digitalSignature
      if (cert.getExtendedKeyUsage() != null && cert.getKeyUsage()[KEY_USAGE_SIG]) {
        return Optional.of(TLS);
      }
      // SIG: no extended keyUsage, digitalSignature
      if (cert.getExtendedKeyUsage() == null && cert.getKeyUsage()[KEY_USAGE_SIG]) {
        return Optional.of(SIG);
      }
      // ENC: no extended keyUsage, keyEncipherment, keyAgreement
      if (cert.getExtendedKeyUsage() == null
          && cert.getKeyUsage()[KEY_USAGE_KEY_ENCIPHERMENT]
          && cert.getKeyUsage()[KEY_USAGE_KEY_AGREEMENT]) {
        return Optional.of(ENC);
      }
    } catch (CertificateParsingException ignored) {
    }
    return Optional.empty();
  }
}
