package de.ebsnet.crmf;

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
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

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

  public Void call() throws CRMFException, IOException, OperatorCreationException {
    final var normalizedName = this.name.contains(".EMT.MAK") ? this.name : this.name + ".EMT.MAK";
    final var dirName =
        Stream.of(
                Optional.of(normalizedName).map(cn -> RDN_CN + "=" + cn),
                Optional.of(this.pki).map(o -> RDN_O + "=" + o),
                Optional.of(this.gln).map(ou -> RDN_OU + "=" + ou),
                Optional.of(this.country).map(c -> RDN_C + "=" + c),
                this.city.map(c -> RDN_L + "=" + c),
                this.street.map(s -> RDN_STREET + "=" + s),
                this.state.map(st -> RDN_ST + "=" + st),
                this.postalCode.map(pc -> RDN_PC + "=" + pc))
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
