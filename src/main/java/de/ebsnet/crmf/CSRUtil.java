package de.ebsnet.crmf;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicInteger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateReqMessages;
import org.bouncycastle.cert.crmf.CertificateReqMessagesBuilder;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

@SuppressFBWarnings("DMI_RANDOM_USED_ONLY_ONCE")
public final class CSRUtil {
  private static final String SIGNATURE_ALGORITHM = "SHA384withECDSA";

  public static final ASN1ObjectIdentifier OID_CERT_REQ_MSGS =
      new ASN1ObjectIdentifier("0.4.0.127.0.7.4.1.1.1");
  public static final ASN1ObjectIdentifier OID_CERT_REQ_MSGS_WITH_OUTER_SIG =
      new ASN1ObjectIdentifier("0.4.0.127.0.7.4.1.1.2");

  private static final SecureRandom RNG = new SecureRandom();

  // start with random positive ID and ensure we can increment without overflowing
  private static final AtomicInteger CERT_REQ_ID =
      new AtomicInteger(RNG.nextInt(Integer.MAX_VALUE - 3));

  /**
   * Merge multiple {@code CertReqMsg} into a single {@code CertReqMessages} object
   *
   * @param messages
   * @return
   */
  public static CertificateReqMessages buildCertificateRequestMessages(
      final CertificateRequestMessage... messages) {
    final var builder = new CertificateReqMessagesBuilder();
    for (final var message : messages) {
      builder.addRequest(message);
    }
    return builder.build();
  }

  /**
   * Wrap the {@code CertificateReqMessages} in a {@link ContentInfo} for an initial request.
   *
   * @param messages the request messages
   * @return
   */
  public static ContentInfo asContentInfo(final CertificateReqMessages messages) {
    return asContentInfo(messages.toASN1Structure(), false);
  }

  /**
   * Create a {@link ContentInfo} from the {@link ASN1Encodable} content.
   *
   * @param content the content
   * @param renewal if this is a renewal or initial request.
   * @return
   */
  public static ContentInfo asContentInfo(final ASN1Encodable content, final boolean renewal) {
    return new ContentInfo(renewal ? OID_CERT_REQ_MSGS_WITH_OUTER_SIG : OID_CERT_REQ_MSGS, content);
  }

  /**
   * Generate CSR for a single keypair.
   *
   * @param keyPair
   * @param type
   * @param subject
   * @param uri
   * @param email
   * @return
   * @throws CertIOException
   * @throws OperatorCreationException
   * @throws CRMFException
   */
  public static CertificateRequestMessage certReqMsg(
      final KeyPair keyPair,
      final KeyType type,
      final X500Name subject,
      final URI uri,
      final String email,
      final AttributeTypeAndValue... regInfo)
      throws IOException, OperatorCreationException, CRMFException {
    final var san = subjectAlternativeNames(type, uri, email);

    final var pubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
    final var extUtil =
        new X509ExtensionUtils(
            new BcDigestCalculatorProvider()
                .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)));

    final var builder =
        new JcaCertificateRequestMessageBuilder(BigInteger.valueOf(CERT_REQ_ID.getAndIncrement()))
            .setPublicKey(pubKeyInfo)
            .setSubject(subject)
            .addExtension(
                Extension.subjectKeyIdentifier,
                false,
                extUtil.createSubjectKeyIdentifier(pubKeyInfo))
            .addExtension(Extension.keyUsage, false, type.keyUsage())
            .addExtension(Extension.subjectAlternativeName, false, san)
            .setRegInfo(regInfo)
            .setProofOfPossessionSigningKeySigner(
                new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(keyPair.getPrivate()));

    final var eku = type.extendedKeyUsage();
    if (eku.isPresent()) {
      builder.addExtension(Extension.extendedKeyUsage, false, eku.get());
    }

    return builder.build();
  }

  /**
   * Generate SubjectAlternativeNames.
   *
   * @param type
   * @param uri
   * @param email
   * @return
   */
  private static GeneralNames subjectAlternativeNames(
      final KeyType type, final URI uri, final String email) {
    final var uriGN = new GeneralName(GeneralName.uniformResourceIdentifier, uri.toString());
    final var emailGN = new GeneralName(GeneralName.rfc822Name, email);
    final var generalNames =
        type == KeyType.TLS
            ? new GeneralName[] {
              emailGN, new GeneralName(GeneralName.dNSName, uri.getHost()), uriGN
            }
            : new GeneralName[] {emailGN, uriGN};
    return new GeneralNames(generalNames);
  }

  private CSRUtil() {}
}
