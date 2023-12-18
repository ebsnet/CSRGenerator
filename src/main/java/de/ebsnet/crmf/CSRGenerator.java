package de.ebsnet.crmf;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
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
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(
    name = "CSRGenerator",
    mixinStandardHelpOptions = true,
    version = "1.0",
    description = "Create SM PKI Compatible CSRs")
@SuppressFBWarnings("DMI_RANDOM_USED_ONLY_ONCE")
public final class CSRGenerator implements Callable<Void> {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Option(
      names = {"--encryption"},
      required = true,
      description = "Path to the PEM encoded encryption private key")
  private Path encPath;

  @Option(
      names = {"--signature"},
      required = true,
      description = "Path to the PEM encoded signature private key")
  private Path sigPath;

  @Option(
      names = {"--tls"},
      required = true,
      description = "Path to the PEM encoded TLS private key")
  private Path tlsPath;

  @Option(
      names = {"--out"},
      required = true,
      description = "Path to write the CSR to")
  private Path out;

  @Option(
      names = {"--gln"},
      required = true,
      description = "GLN of the MP. Will be written into the OU field")
  private String gln;

  @Option(
      names = {"--name"},
      required = true,
      description = "Will result in `<name>.EMT.MAK` in the CN field")
  private String name;

  @Option(
      names = {"--uri"},
      required = true,
      description =
          "AS4 endpoint URI. The DNS Name in SubjectAlternativeName will also extracted from this URI")
  private URI uri;

  @Option(
      names = {"--email"},
      required = true,
      description = "Contact email, will be written into SubjectAlternativeName")
  private String email;

  @Option(
      names = {"--city"},
      description = "Subject city")
  private Optional<String> city;

  @Option(
      names = {"--street"},
      description = "Subject street")
  private Optional<String> street;

  @Option(
      names = {"--state"},
      description = "Subject state")
  private Optional<String> state;

  @Option(
      names = {"--postal-code"},
      description = "Subject postal code")
  private Optional<String> postalCode;

  @Option(
      names = {"--country"},
      description = "Subject country",
      defaultValue = "DE")
  private String country;

  @Option(
      names = {"--pki"},
      description = "Which PKI to use (will be the `O` field)",
      defaultValue = "SM-PKI-DE")
  private String pki;

  // start with random positive ID and ensure we can increment without overflowing
  private static final AtomicInteger CERT_REQ_ID =
      new AtomicInteger(new SecureRandom().nextInt(Integer.MAX_VALUE - 3));

  public static void main(final String[] args) {
    new CommandLine(new CSRGenerator()).execute(args);
  }

  public Void call() throws CRMFException, IOException, OperatorCreationException {
    final var dirName =
        Stream.of(
                Optional.of(this.name).map(cn -> "CN=" + cn + ".EMT.MAK"),
                Optional.of(this.pki).map(o -> "O=" + o),
                Optional.of(this.gln).map(ou -> "OU=" + ou),
                Optional.of(this.country).map(c -> "C=" + c),
                this.city.map(c -> "L=" + c),
                this.street.map(s -> "STREET=" + s),
                this.state.map(st -> "ST=" + st),
                this.postalCode.map(pc -> "2.5.4.17=" + pc))
            .flatMap(Optional::stream)
            .collect(Collectors.joining(","));
    final var subject = new X500Name(dirName);

    final var sigKp = loadKeyPair(this.sigPath);
    final var sigCrmf = certReqMsg(sigKp, KeyType.SIG, subject, this.uri, this.email);

    final var encKp = loadKeyPair(this.encPath);
    final var encCrmf = certReqMsg(encKp, KeyType.ENC, subject, this.uri, this.email);

    final var tlsKp = loadKeyPair(this.tlsPath);
    final var tlsCrmf = certReqMsg(tlsKp, KeyType.TLS, subject, this.uri, this.email);

    final var crmf = merge(tlsCrmf, encCrmf, sigCrmf);
    final var pkiMsg = wrap(crmf);
    Files.write(this.out, pkiMsg.getEncoded(), StandardOpenOption.CREATE_NEW);
    return null;
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
  private static CertificateRequestMessage certReqMsg(
      final KeyPair kp,
      final KeyType type,
      final X500Name subject,
      final URI uri,
      final String email)
      throws CertIOException, OperatorCreationException, CRMFException {
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
            .setProofOfPossessionSigningKeySigner(
                new JcaContentSignerBuilder("SHA256withECDSA")
                    .setProvider("BC")
                    .build(kp.getPrivate()));

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

  /**
   * Merge multiple {@code CertReqMsg} into a single {@code CertReqMessages} object
   *
   * @param messages
   * @return
   */
  private static CertificateReqMessages merge(final CertificateRequestMessage... messages) {
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
  private static PKIMessage wrap(final CertificateReqMessages messages) {
    return new PKIMessage(
        new BSIPKIHeader(), new PKIBody(PKIBody.TYPE_INIT_REQ, messages.toASN1Structure()));
  }

  /**
   * Generate a brainpool keypair. This does not use FIPS certified CSPRNGs so these keys must not
   * be used for production
   *
   * @return
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws InvalidAlgorithmParameterException
   * @deprecated Not FIPS compatible
   */
  @Deprecated
  private static KeyPair generateKeyPair()
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    final var gen = KeyPairGenerator.getInstance("EC", "BC");
    gen.initialize(new ECGenParameterSpec("brainpoolP256r1"));
    return gen.generateKeyPair();
  }

  /**
   * Load a PEM encoded EC keypair from disk.
   *
   * @param path
   * @return
   * @throws IOException
   */
  private static KeyPair loadKeyPair(final Path path) throws IOException {
    try (var parser = new PEMParser(Files.newBufferedReader(path))) {
      var parsed = parser.readObject();
      while (parsed != null && !(parsed instanceof PEMKeyPair)) {
        parsed = parser.readObject();
      }
      if (parsed != null) {
        return new JcaPEMKeyConverter().setProvider("BC").getKeyPair((PEMKeyPair) parsed);
      } else {
        throw new IllegalArgumentException("not a PEM encoded EC key.");
      }
    }
  }
}
