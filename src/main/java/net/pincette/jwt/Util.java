package net.pincette.jwt;

import static java.security.KeyFactory.getInstance;
import static java.util.Arrays.stream;
import static java.util.Base64.getDecoder;
import static java.util.stream.Collectors.joining;
import static net.pincette.util.Util.tryToGetRethrow;
import static net.pincette.util.Util.tryToGetSilent;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import net.pincette.function.BiFunctionWithException;

/**
 * Some utilities.
 *
 * @author Werner Donné
 */
class Util {
  private Util() {}

  private static byte[] decode(final String key) {
    return getDecoder().decode(extractKey(key));
  }

  private static String extractKey(final String s) {
    return stream(s.split("\\n")).filter(line -> !line.startsWith("-----")).collect(joining());
  }

  private static <T> T generate(
      final EncodedKeySpec spec, final BiFunctionWithException<KeyFactory, EncodedKeySpec, T> gen) {
    return tryToGetSilent(() -> gen.apply(getInstance("RSA"), spec))
        .orElseGet(() -> tryToGetRethrow(() -> gen.apply(getInstance("EC"), spec)).orElse(null));
  }

  static PrivateKey privateKey(final String key) {
    return generate(new PKCS8EncodedKeySpec(decode(key)), KeyFactory::generatePrivate);
  }

  static PublicKey publicKey(final String key) {
    return generate(new X509EncodedKeySpec(decode(key)), KeyFactory::generatePublic);
  }
}
