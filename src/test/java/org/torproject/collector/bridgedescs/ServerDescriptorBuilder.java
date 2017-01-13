/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.bridgedescs;

import java.util.Arrays;

/** Builds a non-sanitized bridge server descriptor that comes with an original
 * bridge descriptor (of a bundled and therefore publicly known bridge) by
 * default. */
class ServerDescriptorBuilder extends DescriptorBuilder {

  /** Initializes the descriptor builder. */
  ServerDescriptorBuilder() {
    this.addAll(Arrays.asList(
        "@purpose bridge",
        "router MeekGoogle 198.50.200.131 8008 0 0",
        "identity-ed25519",
        "-----BEGIN ED25519 CERT-----",
        "AQQABjliAVz1pof1ijauJttRPRlhPc4GKgp7SWOtFsnvSA3ddIsIAQAgBAA6BoYk",
        "ZEXE7RkiEJ1l5Ij9hc9TJOpM7/9XSPZnF/PbMfE0u3n3JbOO3s82GN6BPuA0v2Cs",
        "5eSvciL7+38Ok2eCaMa6vDrXYUSKrN+z9Kz3feL/XDWQy9L9Tkm7bticng0=",
        "-----END ED25519 CERT-----",
        "master-key-ed25519 "
            + "OgaGJGRFxO0ZIhCdZeSI/YXPUyTqTO//V0j2Zxfz2zE",
        "platform Tor 0.2.7.6 on Linux",
        "protocols Link 1 2 Circuit 1",
        "published 2016-06-30 21:43:52",
        "fingerprint 46D4 A711 97B8 FA51 5A82 6C6B 017C 522F E264 655B",
        "uptime 543754",
        "bandwidth 3040870 5242880 56583",
        "extra-info-digest 6D03E80568DEFA102968D144CB35FFA6E3355B8A "
            + "cy/LwP7nxukmmcT1+UnDg4qh0yKbjVUYKhGL8VksoJA",
        "onion-key",
        "-----BEGIN RSA PUBLIC KEY-----",
        "MIGJAoGBANcIfT+XV4HHSWEQPGkID0C4OgWQ3Gc/RmfQYLMPe5enDNSLBTstw4ep",
        "aiScHB1xhN8xRhpVB/qaCcYGpmUltIH0NaWQ3tuRV7rw+fp7amfYZfThUk5OPpF0",
        "soGd3jRrzX7SEm4YCGdLZALL51Wb2pdOmR93WucOZYav/tGs/d9rAgMBAAE=",
        "-----END RSA PUBLIC KEY-----",
        "signing-key",
        "-----BEGIN RSA PUBLIC KEY-----",
        "MIGJAoGBAMHXuK8J+5028rDovbEejPrsOJKWtsj7fr4EhMmOmIUM4N2gLdEVyFq7",
        "sVkHZFf3v04PmOhSJymLmVVcXe+Qsb4U300DwADvnpeFjhU4trrFqZljZM5+gPW6",
        "ZmK0ViD54td0biJZd9Ow65Od9XzbJTa2acO/sVXD0Q8tIfnEywvZAgMBAAE=",
        "-----END RSA PUBLIC KEY-----",
        "onion-key-crosscert",
        "-----BEGIN CROSSCERT-----",
        "zQvq4eQYXn9Y2St2Qch4AvwqPAJ+Y+MgTFTf4qYaQ04FXo1csf2eSPB5zbWaUgBb",
        "GbtKaw1ZJJjEtVzk/HnIWQ/V/ONJUSL4BiF2M4RuhozJoK2BGpYfmcsGWQKeLcPi",
        "YIVtO5OI2XcvxgGGVz4ZPPiiGDFJ2MxHA1747KnGSo8=",
        "-----END CROSSCERT-----",
        "ntor-onion-key-crosscert 1",
        "-----BEGIN ED25519 CERT-----",
        "AQoABjjOAToGhiRkRcTtGSIQnWXkiP2Fz1Mk6kzv/1dI9mcX89sxAA0280fSYhvB",
        "Y39F6J5FuCFcE/B1KDZZP8zY3NYAP4y+jVTG82RRsN87hwZlyShoBxm2q3x4LNPl",
        "67ZGbPdAUAA=",
        "-----END ED25519 CERT-----",
        "hidden-service-dir",
        "contact jvictors at jessevictors com, PGP 0xC20BEC80, BTC "
            + "1M6tuPXNmhbgSfaJqnxBUAf5tKi4TVhup8",
        "ntor-onion-key YjZG5eaQ1gmXvlSMGEBwM7OLswv8AtXZr6ccOnDUKQw=",
        "reject *:*",
        "router-sig-ed25519 ObNigP8q0HkRDaDPP84txWH+3TbuL8DUNLAF25OZV9uRovF9j02"
            + "StDVEdLGR6vOx9lRos0/264n42jEHzmUbBg",
        "router-signature",
        "-----BEGIN SIGNATURE-----",
        "u/J/T0w7JlH4yUbXcg5hDIVBzGZtXxoH+800zOJXIxbIEGqgTxOhA13C6s/j/C0G",
        "+L6bcrNdqKriJERsJicT2UqVRiIl54c76J9ySsknNKvXuEbZ3RJ71FhzLbi5CQXJ",
        "N5wdZX+AqHSnSe+ayaB3zVlp97gUbFhg3vE2eWPtRxY=",
        "-----END SIGNATURE-----"));
  }
}

