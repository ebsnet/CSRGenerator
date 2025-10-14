package de.ebsnet.crmf.data;

import java.net.URI;
import java.security.InvalidParameterException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

public record CSRMetadata(
    String name,
    String gln,
    URI uri,
    String email,
    String pki,
    String country,
    Optional<String> state,
    Optional<String> city,
    Optional<String> postalCode,
    Optional<String> street) {
  private static final String RDN_CN = "CN";
  private static final String RDN_O = "O";
  private static final String RDN_OU = "OU";
  private static final String RDN_C = "C";
  private static final String RDN_L = "L";
  private static final String RDN_STREET = "STREET";
  private static final String RDN_ST = "ST";
  private static final String RDN_PC = "2.5.4.17"; // NOPMD: not an IP address
  public static final ASN1ObjectIdentifier OID_PC = new ASN1ObjectIdentifier(RDN_PC);

  //  private static final Set<String> RDNS = Set.of(RDN_CN, RDN_O, RDN_OU, RDN_C, RDN_L, RDN_PC);

  public static CSRMetadata fromCertificate(final X509Certificate certificate)
      throws CertificateEncodingException {
    final var holder = new JcaX509CertificateHolder(certificate);
    final var subject = holder.getSubject();

    final var name =
        extractFromCertificate(subject, BCStyle.CN).orElseThrow(InvalidParameterException::new);
    final var gln =
        extractFromCertificate(subject, BCStyle.OU).orElseThrow(InvalidParameterException::new);
    final var uri = URI.create(extractSAN(holder, GeneralName.uniformResourceIdentifier));
    final var email = extractSAN(holder, GeneralName.rfc822Name);
    final var pki =
        extractFromCertificate(subject, BCStyle.O).orElseThrow(InvalidParameterException::new);
    final var country =
        extractFromCertificate(subject, BCStyle.C).orElseThrow(InvalidParameterException::new);
    final var city = extractFromCertificate(subject, BCStyle.L);
    final var street = extractFromCertificate(subject, BCStyle.STREET);
    final var state = extractFromCertificate(subject, BCStyle.ST);
    final var postalCode = extractFromCertificate(subject, OID_PC);

    return new CSRMetadata(name, gln, uri, email, pki, country, state, city, postalCode, street);
  }

  private static Optional<String> extractFromCertificate(
      final X500Name subject, final ASN1ObjectIdentifier oid) {
    return Optional.of(subject.getRDNs(oid))
        .filter(r -> r.length != 0)
        .map(r -> r[0].getFirst().getValue().toString());
  }

  private static String extractSAN(final X509CertificateHolder holder, final int gnTag) {
    final var san = holder.getExtension(Extension.subjectAlternativeName);
    final var generalNames = GeneralNames.getInstance(san.getParsedValue());
    return Stream.of(generalNames.getNames())
        .filter(gn -> gn.getTagNo() == gnTag)
        .findFirst()
        .get()
        .getName()
        .toString();
  }

  public X500Name toSubject() {
    final var normalizedName = name().contains(".EMT.MAK") ? name() : name() + ".EMT.MAK";
    final var dirName =
        Stream.of(
                Optional.of(normalizedName).map(cn -> RDN_CN + "=" + cn),
                Optional.of(pki()).map(o -> RDN_O + "=" + o),
                Optional.of(gln()).map(ou -> RDN_OU + "=" + ou),
                Optional.of(country()).map(c -> RDN_C + "=" + c),
                city().map(c -> RDN_L + "=" + c),
                street().map(s -> RDN_STREET + "=" + s),
                state().map(st -> RDN_ST + "=" + st),
                postalCode().map(pc -> RDN_PC + "=" + pc))
            .flatMap(Optional::stream)
            .collect(Collectors.joining(","));
    return new X500Name(dirName);
  }
}
