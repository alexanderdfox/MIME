# MIME Security Upgrade Proposal

**Version:** 1.0  
**Author:** Alexander Fox / proposal drafted with AI assistance  
**Date:** 2025-08-29

---

## Executive summary

This proposal outlines a practical, backward-compatible roadmap to upgrade MIME and the associated email protection ecosystem (S/MIME/CMS, MTAs, and clients) for improved **confidentiality**, **integrity**, **authentication**, and **parser/renderer hardening**.

It focuses on three tiers of improvements:

1. **Short-term deployable changes** (immediately actionable by clients and servers).  
2. **Medium-term protocol extensions** for standardization (RFC proposals).  
3. **Long-term cryptographic roadmap** for forward secrecy and post-quantum readiness.

The proposal includes a concrete, compatible example (a signed MIME manifest), migration guidance, and developer-focused parser hardening recommendations.

---

## Goals

- Preserve backwards compatibility where feasible.
- Ensure every MIME part (attachments, inline resources, nested multiparts) can be validated for integrity and authenticity.
- Add support for strong authenticated encryption (AEAD) and forward secrecy where practical.
- Harden parsing and rendering to reduce exploitation surface (e.g., XSS, archive bombs, header injection).
- Provide explicit policy mechanisms for domains and clients to enforce safe defaults.

---

## Short-term, practical upgrades (deployable now)

These actions require no changes to the core MIME container format and can be adopted by mail clients, libraries, and MTAs now.

1. **Require AEAD algorithms for CMS/S/MIME profiles**
   - Default to AES-GCM or ChaCha20-Poly1305 for encryption and AEAD-friendly construction where supported.

2. **Sign a canonical manifest covering the full MIME tree**
   - Compute cryptographic hashes for every part (including nested parts and attachments) and sign a canonical manifest. See the example manifest section below.

3. **Prefer authenticated-encryption profiles for combined sign+encrypt workflows**
   - Avoid naive sign-then-encrypt pipes that risk losing signature metadata. Use CMS profiles that preserve integrity metadata.

4. **Tighten transport security (MTA ops)**
   - Enforce MTA-STS and Strict TLS for MTAs where available. Encourage DANE for additional cryptographic binding.

5. **Default client hardening**
   - Block remote content by default; require explicit user consent to fetch remote images/resources.
   - Sanitize HTML using a maintained sanitizer; render in a sandboxed process with no filesystem/network privileges.
   - Limit nesting depth, attachment sizes, and decompressed sizes to protect against archive/zlib bombs.

6. **Canonical filename and charset handling**
   - Sanitize Content-Disposition filenames; strip control characters and map or warn on potentially dangerous extensions.
   - Canonicalize RFC-2231 encoded filenames prior to validation/signature operations.

7. **Signed Content-Type enforcement**
   - When a message or manifest is signed, treat the signed Content-Type and declared part metadata as authoritative for security decisions.

---

## Medium-term protocol extensions (RFC-style proposals)

These items are intended to be standardized so that interoperable implementations can adopt them and servers/clients can enforce policy.

1. **Signed MIME Part Manifest (new optional part/type)**
   - Introduce an optional part type `application/vnd.mime-manifest+json` (or `multipart/signed-manifest`) carrying a manifest listing every MIME part with canonical metadata (index, content-type, filename, declared size) and a SHA-256/SHA-384 hash for each part.
   - The manifest is signed with S/MIME/CMS. Recipients verify the signature then compare hashes before rendering or executing parts.
   - Backwards-compatible: legacy clients ignore unknown part types.

2. **Per-message ephemeral encryption profile (forward secrecy)**
   - Define a CMS/S/MIME profile that uses ephemeral ECDH per message to derive symmetric keys for each recipient (hybrid encryption). The ephemeral public values are included in the encrypted headers wrapped for each recipient.
   - Profile should define algorithm identifiers and OIDs for ephemeral ECDH and AEAD symmetric encryption.

3. **DKIM/CMS Binding**
   - Define a mechanism to cryptographically bind DKIM signatures (which cover headers and body canonicalization) to the MIME manifest so intermediate rewriting and envelope modifications can be detected by relying parties.

4. **Integrity metadata for embedded remote resources**
   - Allow authors to include `integrity` (hash) attributes for inline resources (images/CSS) similar to Subresource Integrity so rendering clients can validate fetched resources without solely trusting the network source.

5. **MIME-Security-Policy header**
   - Define `MIME-Security-Policy` for domains to advertise expectations (e.g., `require-signed-manifest`, `require-aead`, `remote-content=block,allow-on-click`, `max-part-depth=6`).
   - Clients and MTAs can query and cache domain policies (analogous to MTA-STS) and enforce or warn when messages violate policy.

6. **Standardize a safe HTML subset and email-CSP**
   - Produce an RFC that defines a restricted HTML/CSS subset for email and a CSP-like policy for clients to apply when rendering email HTML bodies.

7. **Optional JSON crypto profile (JWE/JWS for MIME parts)**
   - Provide an optional profile `application/jose+mime` that describes how to wrap individual MIME parts with JWE and sign with JWS, leveraging the rich, extensible JOSE ecosystem.

---

## Long-term cryptographic roadmap

1. **Post-Quantum readiness**
   - Define hybrid (classical + PQ) key exchange and signature profiles in CMS/S/MIME. Update certificate profiles and OIDs to advertise PQ-capable keys.

2. **Message-level forward secrecy & ratcheting**
   - Explore a ratchet-based approach (like Double Ratchet or MLS-inspired group key management) for multi-recipient message confidentiality and forward secrecy across threads and replies. This is ambitious and requires extensive key-management tooling.

3. **Stronger key lifecycle & recovery models**
   - Recommend organizational key recovery and escrow patterns for enterprise deployments, with strict audit and access controls.

---

## Parser & renderer hardening checklist (developer guidance)

- Enforce strict header limits (maximum header length, maximum number of headers).  
- Reject or sanitize control characters in headers and filenames.  
- Disallow excessive `multipart/*` recursion beyond a safe depth.  
- Enforce declared part sizes and refuse to allocate memory for unrealistic decompressed sizes.  
- Use streaming parsers with limits and graceful failure modes to prevent OOM/CPU exhaustion.  
- Validate charset conversions and reject malformed Unicode sequences.  
- Avoid content-sniffing overrides of signed Content-Type.  
- Render HTML in a sandboxed renderer without network or filesystem privileges.  
- Maintain an allowlist for content types that are rendered inline; others must be download-only or scanned.

---

## Example: Signed MIME Manifest (concrete, deployable today)

**Overview:** Composer computes SHA-256 for every MIME part, builds a JSON manifest with canonical metadata, includes this manifest as an `application/vnd.mime-manifest+json` part, and signs it with S/MIME/CMS. Recipients verify the signature and compare hashes before rendering.

**Example manifest (JSON):**

```json
{
  "version": 1,
  "parts": [
    {"idx": 1, "name": "plain.txt", "ctype": "text/plain; charset=utf-8", "size": 128, "sha256": "<hex>"},
    {"idx": 2, "name": "message.html", "ctype": "text/html; charset=utf-8", "size": 2048, "sha256": "<hex>"},
    {"idx": 3, "name": "image.png", "ctype": "image/png", "size": 51234, "sha256": "<hex>"}
  ]
}
```

**Placement:** Insert the manifest as a top-level MIME part (e.g., `multipart/mixed` containing the manifest and the rest of the parts). Sign the manifest using S/MIME (`multipart/signed` or CMS signature wrapping).

**Validation:** Recipient steps:

1. Verify signature on manifest.  
2. For each entry, compute the part hash and compare.  
3. If hashes match, mark parts as integrity-verified; otherwise, treat content as tampered and refuse to render sensitive content.

**Backwards compatibility:** Unknown part types are ignored by legacy clients; the message still delivers raw parts. Clients that support the manifest gain integrity assurance.

---

## Example OpenSSL commands (sign manifest & encrypt)

> These are illustrative; implementations should follow CMS/S/MIME profiles and use secure parameter choices.

1. Generate a manifest file and sign using S/MIME/CMS:

```bash
# sign manifest.json -> manifest.p7s (detached)
openssl cms -sign -in manifest.json -signer me.crt -inkey me.key -outform PEM -out manifest.p7s -nodetach
```

2. Encrypt a message (single part) to a recipient using AEAD (AES-GCM):

```bash
openssl smime -encrypt -aes256 -in message.txt -out encrypted.p7m -outform SMIME bob.crt
```

3. Sign then encrypt using an authenticated flow (recommended: use CMS profiles that preserve signature metadata):

```bash
# sign -> encrypt (example pipeline)
openssl cms -sign -in message.txt -signer me.crt -inkey me.key -outform PEM |
  openssl smime -encrypt -aes256 -out signed_encrypted.p7m -outform SMIME bob.crt
```

---

## Migration & compatibility strategy

1. **Phase 0 (0–12 months): optional adoption**
   - Clients add support for validating signed manifests and AEAD encryption by default.  
   - Servers begin publishing `MIME-Security-Policy` optionally and support strict TLS.

2. **Phase 1 (12–36 months): recommended**
   - Major clients and email libraries adopt the signed manifest as recommended.  
   - MTAs validate domain policies and begin warning or rejecting non-compliant messages where policy dictates.

3. **Phase 2 (36+ months): required / enforced**
   - Domains may opt to require signed manifests and AEAD encryption for intra-organization mail; public enforcement will depend on ecosystem readiness.

---

## Risks & tradeoffs

- **Backward compatibility:** Older clients will ignore new parts; a staged rollout is required.
- **Usability impact:** Blocking remote content and requiring signatures may break workflows; provide clear UX and fallbacks.
- **Operational complexity:** Forward secrecy, ratchets, and PQ key management increase key lifecycle complexity.
- **Performance:** Additional hashing/signing steps add CPU cost, but this is acceptable for most modern systems.

---

## Implementation checklist & next steps

- [ ] Draft RFC text for `application/vnd.mime-manifest+json` and `MIME-Security-Policy` header.
- [ ] Create reference implementation (library) for manifest creation and verification (OpenSSL-based example + higher-level bindings for Python, Swift, JavaScript).
- [ ] Update major mail clients (Apple Mail, Thunderbird, Outlook) with manifest validation and hardened rendering.
- [ ] Publish best-practice guidelines for MTAs (MTA-STS, DANE, strict TLS) and encourage domain adoption.
- [ ] Research and prototype ephemeral-cipher CMS profile for forward secrecy.

---

## Appendix A — Suggested `MIME-Security-Policy` header syntax (example)

```
MIME-Security-Policy: v=1; require-signed-manifest=prefer; require-aead=yes; remote-content=block; max-part-depth=6; pq-ready=no
```

Fields:
- `require-signed-manifest`: `no|prefer|require`  
- `require-aead`: `yes|no|prefer`  
- `remote-content`: `block|warn|allow`  
- `max-part-depth`: integer  
- `pq-ready`: `yes|no|partial`

---

## Appendix B — Glossary

- **AEAD:** Authenticated Encryption with Associated Data (e.g., AES-GCM, ChaCha20-Poly1305).  
- **CMS:** Cryptographic Message Syntax, basis for S/MIME.  
- **S/MIME:** Secure/Multipurpose Internet Mail Extensions.  
- **DKIM:** DomainKeys Identified Mail.  
- **MTA-STS:** SMTP MTA Strict Transport Security.  
- **DANE:** DNS-based Authentication of Named Entities.

---

*End of proposal.*

