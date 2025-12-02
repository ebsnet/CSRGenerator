# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changes

- Implement generation and sending of certificate renewal requests ([#43](https://github.com/ebsnet/CSRGenerator/pull/43))

### Dependencies
- Bump `jakarta.xml.bind:jakarta.xml.bind-api` from 2.3.3 to 4.0.4 ([#1](https://github.com/ebsnet/CSRGenerator/pull/1), [#34](https://github.com/ebsnet/CSRGenerator/pull/34), [#40](https://github.com/ebsnet/CSRGenerator/pull/40))
- Bump `jakarta.xml.ws:jakarta.xml.ws-api` from 2.3.3 to 4.0.2 ([#2](https://github.com/ebsnet/CSRGenerator/pull/2), [#34](https://github.com/ebsnet/CSRGenerator/pull/34))
- Bump `com.github.bjornvester.wsdl2java` from 1.2 to 2.0.2 ([#3](https://github.com/ebsnet/CSRGenerator/pull/3), [#34](https://github.com/ebsnet/CSRGenerator/pull/34))
- Bump `com.sun.xml.ws:jaxws-rt` from 2.3.7 to 4.0.3 ([#4](https://github.com/ebsnet/CSRGenerator/pull/4), [#34](https://github.com/ebsnet/CSRGenerator/pull/34))
- Bump `com.sun.xml.ws:jaxws-ri` from 2.3.7 to 4.0.3 ([#5](https://github.com/ebsnet/CSRGenerator/pull/5), [#34](https://github.com/ebsnet/CSRGenerator/pull/34))
- Bump `jakarta.xml.soap:jakarta.xml.soap-api` from 1.4.2 to 3.0.2 ([#6](https://github.com/ebsnet/CSRGenerator/pull/6), [#34](https://github.com/ebsnet/CSRGenerator/pull/34))
- Bump `com.github.spotbugs` from 6.2.5 to 6.4.7 ([#36](https://github.com/ebsnet/CSRGenerator/pull/36), [#37](https://github.com/ebsnet/CSRGenerator/pull/37), [#38](https://github.com/ebsnet/CSRGenerator/pull/38), [#40](https://github.com/ebsnet/CSRGenerator/pull/40), [#43](https://github.com/ebsnet/CSRGenerator/pull/43), [#49](https://github.com/ebsnet/CSRGenerator/pull/49))
- Bump `jakarta.xml.soap:jakarta.xml.soap-api` from 1.4.2 to 3.0.2 ([#6](https://github.com/ebsnet/CSRGenerator/pull/6), [#34](https://github.com/ebsnet/CSRGenerator/pull/34))
- Bump `org.ajoberstar.grgit` from 5.3.2 to 5.3.3 ([#37](https://github.com/ebsnet/CSRGenerator/pull/37))
- Bump `org.bouncycastle:bcpkix-jdk18on` from 1.81 to 1.83 ([#40](https://github.com/ebsnet/CSRGenerator/pull/40), [#49](https://github.com/ebsnet/CSRGenerator/pull/49))
- Bump `org.bouncycastle:bcprov-jdk18on` from 1.81 to 1.83 ([#40](https://github.com/ebsnet/CSRGenerator/pull/40), [#49](https://github.com/ebsnet/CSRGenerator/pull/49))
- Bump `org.bouncycastle:bctls-jdk18on` from 1.81 to 1.83 ([#40](https://github.com/ebsnet/CSRGenerator/pull/40), [#49](https://github.com/ebsnet/CSRGenerator/pull/49))
- Bump `org.bouncycastle:bcutil-jdk18on` from 1.81 to 1.83 ([#40](https://github.com/ebsnet/CSRGenerator/pull/40), [#49](https://github.com/ebsnet/CSRGenerator/pull/49))
- Bump `com.diffplug.spotless` from 7.2.1 to 8.0.0 ([#43](https://github.com/ebsnet/CSRGenerator/pull/43), [#41](https://github.com/ebsnet/CSRGenerator/pull/41))
- Bump `nebula.lint` from 21.1.1 to 21.1.3 ([#43](https://github.com/ebsnet/CSRGenerator/pull/43))
- Bump `stefanzweifel/git-auto-commit-action` from 6 to 7 ([#44](https://github.com/ebsnet/CSRGenerator/pull/44))
- Bump `actions/checkout` from 5 to 6 ([#47](https://github.com/ebsnet/CSRGenerator/pull/47))
- Bump `org.apache.cxf:cxf-core` from 4.1.3 to 4.1.4 ([#49](https://github.com/ebsnet/CSRGenerator/pull/49))

## [1.2.0] 2025-08-27

### Changes

- Use Java 17 ([#33](https://github.com/ebsnet/CSRGenerator/pull/33))

### Dependencies

- Bump `com.github.spotbugs` from 6.1.13 to 6.2.5 ([#21](https://github.com/ebsnet/CSRGenerator/pull/21), [#22](https://github.com/ebsnet/CSRGenerator/pull/22), [#25](https://github.com/ebsnet/CSRGenerator/pull/25), [#27](https://github.com/ebsnet/CSRGenerator/pull/27), [#28](https://github.com/ebsnet/CSRGenerator/pull/28), [#31](https://github.com/ebsnet/CSRGenerator/pull/31))
- Bump `nebula.lint` from 20.6.1 to 21.1.1 ([#21](https://github.com/ebsnet/CSRGenerator/pull/21), [#33](https://github.com/ebsnet/CSRGenerator/pull/33))
- Bump `org.ajoberstar.grgit` from 5.3.0 to 5.3.2 ([#21](https://github.com/ebsnet/CSRGenerator/pull/21))
- Bump `stefanzweifel/git-auto-commit-action` from 5 to 6 ([#20](https://github.com/ebsnet/CSRGenerator/pull/20))
- Bump `org.ajoberstar.grgit` from 5.3.0 to 5.3.2 ([#21](https://github.com/ebsnet/CSRGenerator/pull/21))
- Bump `com.diffplug.spotless` from 7.0.4 to 7.2.1 ([#24](https://github.com/ebsnet/CSRGenerator/pull/24), [#26](https://github.com/ebsnet/CSRGenerator/pull/26))
- Bump `actions/checkout` from 4 to 5 ([#29](https://github.com/ebsnet/CSRGenerator/pull/29))
- Bump `actions/setup-java` from 4 to 5 ([#32](https://github.com/ebsnet/CSRGenerator/pull/32))
- Bump Gradle Wrapper from 8.13 to 9.0.0 ([#33](https://github.com/ebsnet/CSRGenerator/pull/33))

## [1.1.0] 2025-06-05

### Dependencies

- Bump `com.diffplug.spotless` from 7.0.2 to 7.0.4 ([#7](https://github.com/ebsnet/CSRGenerator/pull/7), [#16](https://github.com/ebsnet/CSRGenerator/pull/16))
- Bump `info.picocli:picocli` from 4.7.6 to 4.7.7 ([#8](https://github.com/ebsnet/CSRGenerator/pull/8))
- Bump `com.h3xstream.findsecbugs:findsecbugs-plugin` from 1.13.0 to 1.14.0 ([#8](https://github.com/ebsnet/CSRGenerator/pull/8))
- Bump `com.github.spotbugs` from 6.1.7 to 6.1.13 ([#9](https://github.com/ebsnet/CSRGenerator/pull/9), [#11](https://github.com/ebsnet/CSRGenerator/pull/11), [#12](https://github.com/ebsnet/CSRGenerator/pull/12), [#13](https://github.com/ebsnet/CSRGenerator/pull/13), [#16](https://github.com/ebsnet/CSRGenerator/pull/16))
- Bump `com.h3xstream.findsecbugs:findsecbugs-plugin` from 1.13.0 to 1.14.0 ([#8](https://github.com/ebsnet/CSRGenerator/pull/8))
- Bump `nebula.lint` from 20.5.6 to 20.6.1 ([#10](https://github.com/ebsnet/CSRGenerator/pull/10), [#11](https://github.com/ebsnet/CSRGenerator/pull/11), [#16](https://github.com/ebsnet/CSRGenerator/pull/16))
- Bump `org.bouncycastle:bcpkix-jdk18on` from 1.80 to 1.81 ([#16](https://github.com/ebsnet/CSRGenerator/pull/16))
- Bump `org.bouncycastle:bcprov-jdk18on` from 1.80 to 1.81 ([#16](https://github.com/ebsnet/CSRGenerator/pull/16))
- Bump `org.bouncycastle:bctls-jdk18on` from 1.80 to 1.81 ([#16](https://github.com/ebsnet/CSRGenerator/pull/16))
- Bump `org.bouncycastle:bcutil-jdk18on` from 1.80 to 1.81 ([#16](https://github.com/ebsnet/CSRGenerator/pull/16))

## [1.0.0] 2025-03-12

- Initial release with base functionality
