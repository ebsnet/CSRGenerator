package de.ebsnet.crmf;

import java.util.Optional;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;

@SuppressWarnings("PMD.OnlyOneReturn")
public enum KeyType {
  SIG,
  ENC,
  TLS;

  public KeyUsage keyUsage() {
    switch (this) {
      case ENC:
        return new KeyUsage(KeyUsage.keyAgreement | KeyUsage.keyEncipherment);
      case SIG:
      case TLS:
        return new KeyUsage(KeyUsage.digitalSignature);
      default:
        throw new UnsupportedOperationException("unreachable... switched on " + this);
    }
  }

  public Optional<ExtendedKeyUsage> extendedKeyUsage() {
    switch (this) {
      case TLS:
        return Optional.of(
            new ExtendedKeyUsage(
                new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}));
      case ENC:
      case SIG:
        return Optional.empty();
      default:
        throw new UnsupportedOperationException("unreachable... switched on " + this);
    }
  }
}
