package de.ebsnet.crmf;

import java.util.Optional;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;

/** Key Types in an SM-PKI certificate triple. */
@SuppressWarnings("PMD.OnlyOneReturn")
public enum KeyType {
  /** Signature key. */
  SIG,
  /** Encryption key. */
  ENC,
  /** TLS key. */
  TLS;

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
}
