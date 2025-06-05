package de.ebsnet.crmf;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.stream.Stream;
import javax.naming.InvalidNameException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

// TODO: This does not work, yet

/**
 * This should generate a renewal CSR according to the SM-PKI but our SubCA does not accept those
 * yet.
 *
 * <p>If you have any ideas on how to properly implement this, PRs are very welcome.
 */
@Command(
    name = "renew",
    mixinStandardHelpOptions = true,
    description = "Generate a Request for Renewal")
@SuppressWarnings("PMD.ExcessiveImports")
public final class Renew extends BaseCommand implements Callable<Void> {
  // we initialize here to, in case we are testing from a main method inside this
  // class
  static {
    CSRGenerator.init();
  }

  private static final int OFFSET_CONTENT_TYPE = 2;

  // private static final int OFFSET_E_CONTENT_TYPE = 37;

  @Option(
      names = {"--previous-keypair"},
      required = true,
      description = "Path to one of the old Key Pairs, used to sign the renewal")
  private Path prevKeyPair;

  @Option(
      names = {"--previous-certificate"},
      required = true,
      description =
          "Path to the old certificate. This is used to sign the renewal and for metadata of the new certificates")
  private Path prevCertificate;

  private Path trustChain;

  public static void main(final String[] args)
      throws InvalidNameException,
          CRMFException,
          GeneralSecurityException,
          IOException,
          OperatorCreationException,
          CMSException,
          NoSuchFieldException,
          IllegalAccessException {
    final var renew = new Renew();
    renew.prevCertificate =
        Path.of("/home/me/work/tmp/crmf-csr/keys/old/personalSignatureCertificate.pem");
    renew.trustChain = Path.of("/home/me/Dokumente/work/keys/old/DARZ-Test.CA-SN4-2022.pem");
    renew.prevKeyPair = Path.of("/home/me/work/tmp/crmf-csr/keys/old/sig.key");
    renew.encPath = Path.of("/home/me/work/tmp/crmf-csr/keys/new/enc.key");
    renew.sigPath = Path.of("/home/me/work/tmp/crmf-csr/keys/new/sig.key");
    renew.tlsPath = Path.of("/home/me/work/tmp/crmf-csr/keys/new/tls.key");
    renew.out = Path.of("/home/me/work/tmp/crmf-csr/csr4.pem");
  }

  @SuppressWarnings("PMD.UseVarargs")
  private static <T> T[] concatArrays(final T[] array1, final T[] array2) {
    final T[] result = Arrays.copyOf(array1, array1.length + array2.length);
    System.arraycopy(array2, 0, result, array1.length, array2.length);
    return result;
  }

  @Override
  @SuppressFBWarnings(
      value = {"LDAP_INJECTION"},
      justification = "Not used for LDAP query")
  public Void call()
      throws GeneralSecurityException,
          IOException,
          InvalidNameException,
          CRMFException,
          OperatorCreationException,
          CMSException,
          NoSuchFieldException,
          IllegalAccessException {
    final var prevKp = loadKeyPair(this.prevKeyPair);
    final var prevCerts = loadCertificateChain(this.prevCertificate);
    final var trustChain = loadCertificateChain(this.trustChain);
    final X509Certificate[] allCerts = concatArrays(prevCerts, trustChain);

    final var filteredSubject = new JcaX509CertificateHolder(prevCerts[0]).getSubject();

    final var email = extractSAN(prevCerts[0], GeneralName.rfc822Name);
    final var uri = URI.create(extractSAN(prevCerts[0], GeneralName.uniformResourceIdentifier));

    final var sigKp = loadKeyPair(this.sigPath);
    final var sigCrmf = certReqMsg(sigKp, KeyType.SIG, filteredSubject, uri, email);

    final var encKp = loadKeyPair(this.encPath);
    final var encCrmf = certReqMsg(encKp, KeyType.ENC, filteredSubject, uri, email);

    final var tlsKp = loadKeyPair(this.tlsPath);
    final var tlsCrmf = certReqMsg(tlsKp, KeyType.TLS, filteredSubject, uri, email);

    final var crmf = merge(tlsCrmf, encCrmf, sigCrmf);
    final var pkiMsg = wrap(crmf, true);

    final var renewalCsr = outerSignature(prevKp, allCerts, pkiMsg);
    final var csr = renewalCsr.getEncoded();
    var offsetContentType = OFFSET_CONTENT_TYPE;
    for (final var content : SignedCSRData.CONTENT_TYPE.getEncoded()) {
      csr[offsetContentType] = content;
      offsetContentType += 1;
    }
    Files.write(this.out, csr, StandardOpenOption.CREATE_NEW);

    return null;
  }

  private static String extractSAN(final X509Certificate certificate, final int gnTag)
      throws CertificateEncodingException {
    final var holder = new JcaX509CertificateHolder(certificate);
    final var san = holder.getExtension(Extension.subjectAlternativeName);
    final var generalNames = GeneralNames.getInstance(san.getParsedValue());
    return Stream.of(generalNames.getNames())
        .filter(gn -> gn.getTagNo() == gnTag)
        .findFirst()
        .get()
        .getName()
        .toString();
  }

  private static CMSSignedData outerSignature(
      final KeyPair keyPair, final X509Certificate[] chain, final PKIMessage csr)
      throws OperatorCreationException, GeneralSecurityException, CMSException, IOException {
    final var gen = new CMSSignedDataGenerator();
    final var signedAttributes = new ASN1EncodableVector();
    signedAttributes.add(
        new Attribute(CMSAttributes.contentType, new DERSet(BSIPKIHeader.OID_BSI_CERT_REQ_MSGS)));

    final var signedAttributesTable = new AttributeTable(signedAttributes);
    final var signer =
        new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
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

    final var certStore = new JcaCertStore(List.of(chain));
    gen.addCertificates(certStore);
    return gen.generate(new SignedCSRData(csr), true);
  }
}
