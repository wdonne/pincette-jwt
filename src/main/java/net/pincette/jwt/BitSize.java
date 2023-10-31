package net.pincette.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.function.Function;

public enum BitSize {
  BIT256(Algorithm::ECDSA256, Algorithm::RSA256),
  BIT384(Algorithm::ECDSA384, Algorithm::RSA384),
  BIT512(Algorithm::ECDSA512, Algorithm::RSA512);

  final Function<ECKey, Algorithm> ecAlgorithm;
  final Function<RSAKey, Algorithm> rsaAlgorithm;

  BitSize(
      final Function<ECKey, Algorithm> ecAlgorithm,
      final Function<RSAKey, Algorithm> rsaAlgorithm) {
    this.ecAlgorithm = ecAlgorithm;
    this.rsaAlgorithm = rsaAlgorithm;
  }
}
