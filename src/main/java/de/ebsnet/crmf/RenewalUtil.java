package de.ebsnet.crmf;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.crmf.CertificateReqMessages;
import org.bouncycastle.cert.jcajce.JcaCertStore;
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

public final class RenewalUtil {
  public static CMSSignedData outerSignature(
      final PrivateKey privateKey, final X509Certificate[] chain, final CertificateReqMessages csr)
      throws IOException, GeneralSecurityException, OperatorCreationException, CMSException {
    return outerSignature(privateKey, chain, csr.toASN1Structure().getEncoded());
  }

  private static CMSSignedData outerSignature(
      final PrivateKey privateKey, final X509Certificate[] chain, final byte[] data)
      throws OperatorCreationException, GeneralSecurityException, CMSException {
    final var gen = new CMSSignedDataGenerator();

    final var signedAttributes = new ASN1EncodableVector();
    signedAttributes.add(
        new Attribute(CMSAttributes.contentType, new BERSet(CSRUtil.OID_CERT_REQ_MSGS)));

    final var certHolder = new JcaX509CertificateHolder(chain[0]);
    final var extUtil =
        new X509ExtensionUtils(
            new BcDigestCalculatorProvider()
                .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)));
    final var keyIdentifier =
        extUtil.createSubjectKeyIdentifier(certHolder.getSubjectPublicKeyInfo());

    final var signedAttributesTable = new AttributeTable(signedAttributes);
    final var sigAlg = "SHA256withECDSA";
    final var signer =
        new JcaContentSignerBuilder(sigAlg)
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(privateKey);
    gen.addSignerInfoGenerator(
        new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build())
            .setSignedAttributeGenerator(
                new DefaultSignedAttributeTableGenerator(signedAttributesTable))
            .build(signer, keyIdentifier.getKeyIdentifier()));

    final var certStore = new JcaCertStore(List.of(chain));
    gen.addCertificates(certStore);

    return gen.generate(new CMSProcessableByteArray(CSRUtil.OID_CERT_REQ_MSGS, data), true);
  }

  private RenewalUtil() {}
}
