/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.bridgedescs;

import java.util.Arrays;

/** Builds a non-sanitized bridge extra-info descriptor that comes with an
 * original bridge descriptor (of a bundled and therefore publicly known bridge)
 * by default. */
class ExtraInfoDescriptorBuilder extends DescriptorBuilder {

  /** Initializes the descriptor builder. */
  ExtraInfoDescriptorBuilder() {
    this.addAll(Arrays.asList(
        "extra-info MeekGoogle "
            + "46D4A71197B8FA515A826C6B017C522FE264655B",
        "identity-ed25519",
        "-----BEGIN ED25519 CERT-----",
        "AQQABjliAVz1pof1ijauJttRPRlhPc4GKgp7SWOtFsnvSA3ddIsIAQAgBAA6BoYk",
        "ZEXE7RkiEJ1l5Ij9hc9TJOpM7/9XSPZnF/PbMfE0u3n3JbOO3s82GN6BPuA0v2Cs",
        "5eSvciL7+38Ok2eCaMa6vDrXYUSKrN+z9Kz3feL/XDWQy9L9Tkm7bticng0=",
        "-----END ED25519 CERT-----",
        "published 2016-06-30 21:43:52",
        "write-history 2016-06-30 18:40:48 (14400 s) "
            + "415744,497664,359424,410624,420864,933888",
        "read-history 2016-06-30 18:40:48 (14400 s) "
            + "4789248,6237184,4473856,5039104,5567488,5440512",
        "geoip-db-digest 6346E26E2BC96F8511588CE2695E9B0339A75D32",
        "geoip6-db-digest 43CCB43DBC653D8CC16396A882C5F116A6004F0C",
        "dirreq-stats-end 2016-06-30 14:40:48 (86400 s)",
        "dirreq-v3-ips ",
        "dirreq-v3-reqs ",
        "dirreq-v3-resp ok=0,not-enough-sigs=0,unavailable=0,not-found=0,"
            + "not-modified=0,busy=0",
        "dirreq-v3-direct-dl complete=0,timeout=0,running=0",
        "dirreq-v3-tunneled-dl complete=0,timeout=0,running=0",
        "transport meek 198.50.200.131:8000",
        "transport meek 198.50.200.131:7443",
        "bridge-stats-end 2016-06-30 14:41:18 (86400 s)",
        "bridge-ips ",
        "bridge-ip-versions v4=0,v6=0",
        "bridge-ip-transports ",
        "router-sig-ed25519 xNkIgy3gYoENUDMvMvPj1/qPv4suyODE8PcVNLZpY8/WxKvoniT"
            + "+2UsWvKsZVAZwFnq7kSByBJUGdxC3YdhSCA",
        "router-signature",
        "-----BEGIN SIGNATURE-----",
        "jwfwSxul/olhO4VzJfBTg+KQf4G+nRwFa9XLMSgBTy6P+hqDkw7TE079BZiYb8+v",
        "ElS08R1Diq50N8fosR5lqP/Ihhm+V0KcEyWG10+Vl7ADMA3m4GdbGa6dSrdiFMPs",
        "OYE9aueVDIMgKyiOyNmgK3S8lwjX4v6yhaiJWxDGuKs=",
        "-----END SIGNATURE-----"));
  }
}

