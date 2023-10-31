package net.pincette.jwt;

import static com.auth0.jwt.JWT.create;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.time.Duration.ofSeconds;
import static java.time.Instant.now;
import static net.pincette.io.StreamConnector.copy;
import static net.pincette.jwt.BitSize.BIT256;
import static net.pincette.jwt.BitSize.BIT384;
import static net.pincette.jwt.BitSize.BIT512;
import static net.pincette.util.Util.tryToDoRethrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.util.Objects;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class TestJwt {
  private static String readResource(final String name) {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    tryToDoRethrow(
        () -> copy(Objects.requireNonNull(TestJwt.class.getResourceAsStream("/" + name)), out));

    return out.toString(US_ASCII);
  }

  private static void test(final String privateKey, final String publicKey, final BitSize bits) {
    assertTrue(
        new Verifier(readResource(publicKey))
            .verify(
                new Signer(readResource(privateKey), bits)
                    .sign(
                        create()
                            .withSubject("test")
                            .withAudience("test")
                            .withIssuer("test")
                            .withExpiresAt(now().plus(ofSeconds(5)))))
            .isPresent());
  }

  @Test
  @DisplayName("ecdsa256")
  void ecdsa256() {
    test("ecdsa.priv", "ecdsa.pub", BIT256);
  }

  @Test
  @DisplayName("ecdsa384")
  void ecdsa384() {
    test("ecdsa.priv", "ecdsa.pub", BIT384);
  }

  @Test
  @DisplayName("ecdsa512")
  void ecdsa512() {
    test("ecdsa.priv", "ecdsa.pub", BIT512);
  }

  @Test
  @DisplayName("rsa256")
  void rsa256() {
    test("rsa.priv", "rsa.pub", BIT256);
  }

  @Test
  @DisplayName("rsa384")
  void rsa384() {
    test("rsa.priv", "rsa.pub", BIT384);
  }

  @Test
  @DisplayName("rsa512")
  void rsa512() {
    test("rsa.priv", "rsa.pub", BIT512);
  }
}
