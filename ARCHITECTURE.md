# Architecture: jwt-library

## Purpose
An extract of the web-token/jwt-framework components, packaged as a standalone library without the Symfony bundle. Provides JWS signing/verification, JWE encryption/decryption, JWK management, claim checking, and nested token support.

## Directory Structure
```
Checker/                        # Claim and header validation (exp, nbf, iss, aud, etc.)
  Claim_Checker_Manager.php     # Runs registered claim checkers
  Header_Checker_Manager.php    # Runs registered header checkers
Encryption/
  Algorithm/
    ContentEncryption/          # AES-CBC-HMAC, AES-GCM content encryption algorithms
    KeyEncryption/              # RSA, AES-KW, ECDH-ES, PBES2 key wrapping algorithms
  JWE_Builder_Factory.php
  JWE_Decrypter_Factory.php
  JWE_Loader.php
  JWE_Loader_Factory.php
  Serializer/JWE_Serializer.php
KeyManagement/
  Analyzer/                     # Key strength and configuration analyzers
NestedToken/                    # Nested JWT (JWE wrapping JWS)
Signature/
  Algorithm/                    # RS/PS/ES/HS/EdDSA signature algorithms
  JWS_Builder_Factory.php
  JWS_Loader.php
  JWS_Loader_Factory.php
  JWS_Verifier_Factory.php
  Serializer/                   # Compact and JSON serialization
```

## Key Design Decisions
- **Factory pattern** — `JWS_Builder_Factory`, `JWE_Builder_Factory`, etc. produce pre-configured builder/loader instances from an `Algorithm_Manager`, decoupling algorithm selection from token operations.
- **Serializer abstraction** — compact serialization (standard JWT string) and JSON serialization (for multi-recipient JWE) are handled by the same `Serializer` interface.
- **Key analyzer reports** — `Key_Analyzer_Manager` collects `Message` objects (warnings/errors) about key material quality, independent of the signing/encryption workflow.

## Extension Points
- Implement `Signature_Algorithm` to add a new signing algorithm.
- Implement `Content_Encryption_Algorithm` or `Key_Encryption_Algorithm` to add a new JWE algorithm.
- Implement `Claim_Checker` for custom claim validation.

## Dependency Flow
```
JWS_Builder_Factory::create(Algorithm_Manager)
  └─ JWS_Builder
       └─ sign($payload, $headers, $jwk) → compact JWT string

JWS_Loader_Factory::create(Algorithm_Manager, Serializer_Manager, Checker_Manager)
  └─ JWS_Loader
       └─ load($token, $jwks, $mandatoryClaims) → verified payload
```
