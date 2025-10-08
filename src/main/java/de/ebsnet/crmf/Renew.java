package de.ebsnet.crmf;

import de.ebsnet.crmf.data.CSRMetadata;
import de.ebsnet.crmf.data.Triple;
import de.ebsnet.crmf.util.KeyPairUtil;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.logging.Logger;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

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
public final class Renew extends BaseCommand implements Callable<Void> {
  // we initialize here to, in case we are testing from a main method inside this
  // class
  static {
    CSRGenerator.init();
  }

  private static final Logger LOG = Logger.getLogger(Renew.class.getSimpleName());
  private static final int MIN_CHAIN_LENGTH = 2;

  @Option(
      names = {"--previous-keypair"},
      required = true,
      description = "Path to one of the old Key Pairs, used to sign the renewal")
  private Path prevKeyPair;

  @Option(
      names = {"--previous-keypair-pass"},
      description = "Password for the old key")
  private Optional<char[]> prevKeyPass;

  @Option(
      names = {"--previous-certificate"},
      required = true,
      description =
          "Path to the old certificate. This is used to sign the renewal and for metadata of the new certificates")
  private Path prevCertificate;

  @Option(
      names = {"--trust-chain"},
      description = "Path to the trust chain of the sub CA")
  private Path[] trustChain;

  @SuppressFBWarnings("DMI_HARDCODED_ABSOLUTE_FILENAME")
  public static void main(final String[] args)
      throws CRMFException,
          GeneralSecurityException,
          IOException,
          OperatorCreationException,
          CMSException {
    final var basePath = Path.of("/home/me/work/tmp/renewal");
    final var renew = new Renew();
    renew.prevCertificate = basePath.resolve("EBSnet.EMT.MAK_Signature_539.pem");
    renew.trustChain =
        new Path[] {
          basePath.resolve("DARZ-Test.CA-SN4-2022.pem"),
          //          basePath.resolve("sm-test-root.ca_sn3.der"),
        };
    renew.prevKeyPair = basePath.resolve("9984533000003_sig.key.enc");
    renew.prevKeyPass = Optional.of("123456".toCharArray());
    renew.encPath = basePath.resolve("enc.key");
    renew.sigPath = basePath.resolve("sig.key");
    renew.tlsPath = basePath.resolve("tls.key");
    renew.out = basePath.resolve("renew.pem");
    renew.call();
  }

  private static X509Certificate[] buildTrustChain(final X509Certificate[]... chains) {
    final var insertionOrderSet = new LinkedHashSet<X509Certificate>();
    for (final var chain : chains) {
      insertionOrderSet.addAll(List.of(chain));
    }
    return insertionOrderSet.toArray(new X509Certificate[0]);
  }

  @SuppressWarnings("PMD.OnlyOneReturn")
  public static boolean isCompleteTrustChain(final X509Certificate... chain) {
    if (chain.length < MIN_CHAIN_LENGTH) {
      return false;
    }
    for (int i = 0; i < chain.length - 1; i++) {
      if (!chain[i].getIssuerX500Principal().equals(chain[i + 1].getSubjectX500Principal())) {
        final var idx = i;
        LOG.warning(
            () ->
                chain[idx].getSubjectX500Principal()
                    + " is not signed by "
                    + chain[idx + 1].getSubjectX500Principal());
        return false;
      }
    }

    final var root = chain[chain.length - 1];
    final var endsWithRoot = root.getSubjectX500Principal().equals(root.getIssuerX500Principal());
    if (!endsWithRoot) {
      LOG.warning(
          () ->
              "Certificate chain does not end with root certificate. Ends with "
                  + root.getSubjectX500Principal());
    }
    return endsWithRoot;
  }

  @Override
  public Void call()
      throws GeneralSecurityException,
          IOException,
          CRMFException,
          OperatorCreationException,
          CMSException {
    final var prevKp = KeyPairUtil.loadKeyPair(this.prevKeyPair, this.prevKeyPass);
    final var prevCerts = loadCertificateChain(this.prevCertificate);
    var buildChain = new X509Certificate[0];
    for (final var chain : this.trustChain) {
      buildChain = buildTrustChain(buildChain, loadCertificateChain(chain));
    }
    final var allCerts = buildTrustChain(prevCerts, buildChain);

    if (!isCompleteTrustChain(allCerts)) {
      LOG.warning("incomplete trust chain for signature certificate");
    }

    final var keyPairs =
        new Triple<>(
            KeyPairUtil.loadKeyPair(this.encPath, this.passForType(KeyType.ENC)),
            KeyPairUtil.loadKeyPair(this.sigPath, this.passForType(KeyType.SIG)),
            KeyPairUtil.loadKeyPair(this.tlsPath, this.passForType(KeyType.TLS)));
    final var metadata = CSRMetadata.fromCertificate(prevCerts[0]);

    final var innerCSR = Initial.generateCertReqMessages(keyPairs, metadata);
    final var signed = RenewalUtil.outerSignature(prevKp.getPrivate(), allCerts, innerCSR);

    final var signedASN1 = signed.toASN1Structure();

    final var result = CSRUtil.asContentInfo(signedASN1.getContent(), true);

    Files.write(this.out, result.getEncoded(), StandardOpenOption.CREATE_NEW);

    return null;
  }
}
