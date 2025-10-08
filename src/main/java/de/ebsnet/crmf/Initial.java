package de.ebsnet.crmf;

import de.ebsnet.crmf.data.CSRMetadata;
import de.ebsnet.crmf.data.Triple;
import de.ebsnet.crmf.util.KeyPairUtil;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.ECGenParameterSpec;
import java.util.Optional;
import java.util.concurrent.Callable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateReqMessages;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/** Subcommand to generate an initial CSR. */
@Command(name = "initial", mixinStandardHelpOptions = true, description = "Generate an initial CSR")
public final class Initial extends BaseCommand implements Callable<Void> {
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

  @Override
  public Void call() throws CRMFException, IOException, OperatorCreationException {
    final var keyPairs =
        new Triple<>(
            KeyPairUtil.loadKeyPair(this.encPath, this.passForType(KeyType.ENC)),
            KeyPairUtil.loadKeyPair(this.sigPath, this.passForType(KeyType.SIG)),
            KeyPairUtil.loadKeyPair(this.tlsPath, this.passForType(KeyType.TLS)));
    final var metadata =
        new CSRMetadata(
            this.name,
            this.gln,
            this.uri,
            this.email,
            this.pki,
            this.country,
            this.state,
            this.city,
            this.postalCode,
            this.street);

    final var pkiMsg = generateCSR(keyPairs, metadata);

    Files.write(this.out, pkiMsg.getEncoded(), StandardOpenOption.CREATE_NEW);
    return null;
  }

  public static ContentInfo generateCSR(final Triple<KeyPair> keyPairs, final CSRMetadata metadata)
      throws CRMFException, IOException, OperatorCreationException {
    return CSRUtil.asContentInfo(generateCertReqMessages(keyPairs, metadata));
  }

  public static CertificateReqMessages generateCertReqMessages(
      final Triple<KeyPair> keyPairs, final CSRMetadata metadata)
      throws CRMFException, IOException, OperatorCreationException {
    final var subject = metadata.toSubject();

    final var sigCrmf =
        CSRUtil.certReqMsg(
            keyPairs.signature(), KeyType.SIG, subject, metadata.uri(), metadata.email());

    final var encCrmf =
        CSRUtil.certReqMsg(
            keyPairs.signature(), KeyType.ENC, subject, metadata.uri(), metadata.email());

    final var tlsCrmf =
        CSRUtil.certReqMsg(
            keyPairs.signature(), KeyType.TLS, subject, metadata.uri(), metadata.email());

    return CSRUtil.buildCertificateRequestMessages(sigCrmf, encCrmf, tlsCrmf);
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
    final var gen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
    gen.initialize(new ECGenParameterSpec("brainpoolP256r1"));
    return gen.generateKeyPair();
  }
}
