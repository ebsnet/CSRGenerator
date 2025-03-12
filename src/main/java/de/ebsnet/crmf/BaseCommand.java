package de.ebsnet.crmf;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
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
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import picocli.CommandLine.Option;

@SuppressFBWarnings("DMI_RANDOM_USED_ONLY_ONCE")
public abstract class BaseCommand {
  protected static final String SIGNATURE_ALGORITHM = "SHA384withECDSA";
  // start with random positive ID and ensure we can increment without overflowing
  protected static final AtomicInteger CERT_REQ_ID =
      new AtomicInteger(new SecureRandom().nextInt(Integer.MAX_VALUE - 3));

  protected static final String RDN_CN = "CN";
  protected static final String RDN_O = "O";
  protected static final String RDN_OU = "OU";
  protected static final String RDN_C = "C";
  protected static final String RDN_L = "L";
  protected static final String RDN_STREET = "STREET";
  protected static final String RDN_ST = "ST";
  protected static final String RDN_PC = "2.5.4.17"; // NOPMD: not an IP address
  protected static final Set<String> RDNS = Set.of(RDN_CN, RDN_O, RDN_OU, RDN_C, RDN_L, RDN_PC);

  @Option(
      names = {"--encryption"},
      required = true,
      description =
          "Path to the PEM encoded encryption private key (MUST be a new key. Old keys must not be reused)")
  protected Path encPath;

  @Option(
      names = {"--signature"},
      required = true,
      description =
          "Path to the PEM encoded signature private key (MUST be a new key. Old keys must not be reused)")
  protected Path sigPath;

  @Option(
      names = {"--tls"},
      required = true,
      description =
          "Path to the PEM encoded TLS private key (MUST be a new key. Old keys must not be reused)")
  protected Path tlsPath;

  @Option(
      names = {"--out"},
      required = true,
      description = "Path to write the CSR to")
  protected Path out;

  /**
   * Load a PEM encoded EC keypair from disk.
   *
   * @param path
   * @return
   * @throws IOException
   */
  public static KeyPair loadKeyPair(final Path path) throws IOException {
    try (var parser = new PEMParser(Files.newBufferedReader(path))) {
      var parsed = parser.readObject();
      while (parsed != null && !(parsed instanceof PEMKeyPair)) {
        parsed = parser.readObject();
      }
      if (parsed != null) {
        return new JcaPEMKeyConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getKeyPair((PEMKeyPair) parsed);
      } else {
        throw new IllegalArgumentException("not a PEM encoded EC key.");
      }
    }
  }

  public static X509Certificate loadCertificate(final Path path)
      throws CertificateException, IOException {
    return loadCertificateChain(path)[0];
  }

  public static X509Certificate[] loadCertificateChain(final Path path)
      throws CertificateException, IOException {
    final var fact = CertificateFactory.getInstance("X.509");
    try (var inStream = Files.newInputStream(path)) {
      return fact.generateCertificates(inStream).stream()
          .map(c -> (X509Certificate) c)
          .toArray(X509Certificate[]::new);
    }
  }

  /**
   * Generate CSR for a single keypair.
   *
   * @param kp
   * @param type
   * @param subject
   * @param uri
   * @param email
   * @return
   * @throws CertIOException
   * @throws OperatorCreationException
   * @throws CRMFException
   */
  protected static CertificateRequestMessage certReqMsg(
      final KeyPair kp,
      final KeyType type,
      final X500Name subject,
      //      final Optional<X500Name> issuer,
      final URI uri,
      final String email,
      final AttributeTypeAndValue... regInfo)
      throws IOException, OperatorCreationException, CRMFException {
    final var san = subjectAlternativeNames(type, uri, email);

    final var pubKeyInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
    final var extUtil =
        new X509ExtensionUtils(
            new BcDigestCalculatorProvider()
                .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)));
    final var builder =
        new CertificateRequestMessageBuilder(BigInteger.valueOf(CERT_REQ_ID.getAndIncrement()))
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
                    .build(kp.getPrivate()));

    final var eku = type.extendedKeyUsage();
    if (eku.isPresent()) {
      builder.addExtension(Extension.extendedKeyUsage, true, eku.get());
    }

    //    final var ext = new ArrayList<Extension>();
    //    ext.add(new Extension(Extension.keyUsage, true, type.keyUsage().getEncoded()));
    //    final var exts = new Extensions(ext.toArray(new Extension[0]));
    //    final var ctb = new CertTemplateBuilder().setPublicKey(pubKeyInfo).setSubject(subject)
    //      .addExtension(
    //        Extension.subjectKeyIdentifier,
    //        false,
    //        extUtil.createSubjectKeyIdentifier(pubKeyInfo))
    //      .addExtension(Extension.keyUsage, true, type.keyUsage())
    //      .addExtension(Extension.subjectAlternativeName, true, san)
    //      .setRegInfo(regInfo);

    //    final var x = ctb.build();

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

  /**
   * Merge multiple {@code CertReqMsg} into a single {@code CertReqMessages} object
   *
   * @param messages
   * @return
   */
  protected static CertificateReqMessages merge(final CertificateRequestMessage... messages) {
    return new CertificateReqMessages(
        new CertReqMessages(
            Stream.of(messages)
                .map(CertificateRequestMessage::toASN1Structure)
                .toArray(CertReqMsg[]::new)));
  }

  /**
   * Wrap the {@code CertReqMessages} in a {@link PKIMessage}
   *
   * @param messages
   * @return
   */
  protected static PKIMessage wrap(final CertificateReqMessages messages) {
    return wrap(messages, false);
  }

  protected static PKIMessage wrap(final CertificateReqMessages messages, final boolean renewal) {
    return new PKIMessage(
        new BSIPKIHeader(),
        new PKIBody(
            renewal ? PKIBody.TYPE_CERT_REQ : PKIBody.TYPE_INIT_REQ, messages.toASN1Structure()));
  }
}
