package de.ebsnet.crmf;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicInteger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
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
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

@SuppressWarnings("PMD.ExcessiveImports")
@SuppressFBWarnings("DMI_RANDOM_USED_ONLY_ONCE")
public final class CSRUtil {
  public static final String SIGNATURE_ALGORITHM = "SHA384withECDSA";
  public static final ASN1ObjectIdentifier SIG_ALG_OID =
      new ASN1ObjectIdentifier("1.2.840.10045.4.3.3");

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
  public static CertificateReqMessages merge(final CertificateRequestMessage... messages) {
    final var builder = new CertificateReqMessagesBuilder();
    for (final var message : messages) {
      builder.addRequest(message);
    }
    return builder.build();
    //    return new CertificateReqMessages(
    //        new CertReqMessages(
    //            Stream.of(messages)
    //                .map(CertificateRequestMessage::toASN1Structure)
    //                .toArray(CertReqMsg[]::new)));
  }

  /**
   * Wrap the {@code CertReqMessages} in a {@link PKIMessage}
   *
   * @param messages
   * @return
   */
  public static PKIMessage asPKIMessage(final CertificateReqMessages messages) {
    return asPKIMessage(messages, false);
  }

  /**
   * Create a {@link PKIMessage} with the {@link BSIPKIHeader} from the {@link
   * CertificateReqMessages}.
   *
   * @param messages
   * @param renewal should always be false since renewal is currently not supported
   * @return
   */
  public static PKIMessage asPKIMessage(
      final CertificateReqMessages messages, final boolean renewal) {
    return asPKIMessage(messages.toASN1Structure(), renewal);
  }

  public static PKIMessage asPKIMessage(final ASN1Encodable content, final boolean renewal) {
    return new PKIMessage(
        renewal ? new BSIRenewalHeader() : new BSIPKIHeader(),
        new PKIBody(renewal ? PKIBody.TYPE_CERT_REQ : PKIBody.TYPE_INIT_REQ, content));
  }

  //  public static ProtectedPKIMessage wrapForRenewal(
  //      final CertificateReqMessages body, final KeyPair oldSignatureKey)
  //      throws OperatorCreationException, CMPException {
  //    //    return new PKIMessage(
  //    //        new BSIRenewalHeader(), new PKIBody(PKIBody.TYPE_CERT_REQ,
  //    // messages.toASN1Structure()));
  //    final var signer =
  //        new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
  //            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
  //            .build(oldSignatureKey.getPrivate());
  //    return new ProtectedPKIMessageBuilder(PKIHeader.NULL_NAME, PKIHeader.NULL_NAME)
  //        .setBody(PKIBody.TYPE_CERT_REQ, body)
  //        .build(signer);
  //  }

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
            .addExtension(Extension.keyUsage, true, type.keyUsage())
            .addExtension(Extension.subjectAlternativeName, true, san)
            .setRegInfo(regInfo)
            .setProofOfPossessionSigningKeySigner(
                new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(keyPair.getPrivate()));

    final var eku = type.extendedKeyUsage();
    if (eku.isPresent()) {
      builder.addExtension(Extension.extendedKeyUsage, true, eku.get());
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

  public static CMSSignedData outerSignature(
      final KeyPair keyPair, final X509Certificate[] chain, final CertificateReqMessages csr)
      throws IOException, GeneralSecurityException, OperatorCreationException, CMSException {
    return outerSignature(keyPair, chain, csr.toASN1Structure().getEncoded(ASN1Encoding.DER));
  }

  public static CMSSignedData outerSignature(
      final KeyPair keyPair, final X509Certificate[] chain, final byte[] data)
      throws OperatorCreationException, GeneralSecurityException, CMSException {
    final var gen = new CMSSignedDataGenerator();

    final var signedAttributes = new ASN1EncodableVector();
    signedAttributes.add(
        new Attribute(CMSAttributes.contentType, new BERSet(BSIPKIHeader.OID_BSI_CERT_REQ_MSGS)));

    final var signedAttributesTable = new AttributeTable(signedAttributes);
    final var sigAlg = "SHA256withECDSA";
    final var signer =
        new JcaContentSignerBuilder(sigAlg)
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(keyPair.getPrivate());
    gen.addSignerInfoGenerator(
        new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build())
            .setSignedAttributeGenerator(
                new DefaultSignedAttributeTableGenerator(signedAttributesTable))
            .build(signer, chain[0]));

    //    final var certStore = new JcaCertStore(List.of(chain));
    //    gen.addCertificates(certStore);
    gen.addCertificate(new JcaX509CertificateHolder(chain[0]));

    return gen.generate(
        new CMSProcessableByteArray(BSIPKIHeader.OID_BSI_CERT_REQ_MSGS, data), true);
  }

  private CSRUtil() {}
}
