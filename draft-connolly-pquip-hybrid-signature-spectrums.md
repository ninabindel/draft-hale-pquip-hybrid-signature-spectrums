---
title: Hybrid signatures schemes
abbrev: ietf-pquip-hybrid-signature-spectrums
docname: draft-ietf-pquip-hybrid-signature-spectrums-latest
date: 2023-10-23
category: info

ipr: none
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

submissionType: IETF

author:
  -
    ins: N. Bindel
    name: Nina Bindel
    organization: SandboxAQ
    email: nina.bindel@sandboxaq.com
  -
    ins: B. Hale
    name: Britta Hale
    organization: Naval Postgraduate School
    email: britta.hale@nps.edu
  -
    ins: D. Connolly
    name: Deirdre Connolly
    organization: SandboxAQ
    email: deirdre.connolly@sandboxaq.com
  -
    ins: F. Driscoll
    name: Florence Driscoll
    organization: UK National Cyber Security Centre
    email: flo.d@ncsc.gov.uk

informative:
  HYBRIDKEM:
    target: https://doi.org/10.1007/978-3-030-25510-7_12
    title: Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange
    author:
      -
        ins: N. Bindel
        name: Nina Bindel
      -
        ins: J. Brendel
        name: Jacqueline Brendel
      -
        ins: M. Fischlin
        name: Marc Fischlin
      -
        ins: B. Goncalves
        name: Brian Goncalves
      -
        ins: D. Stebila
        name: Douglas Stebila
    refcontent: Post-Quantum Cryptography pp.206-226
    seriesinfo:
      DOI: 10.1007/978-3-030-25510-7_12
    date: 2019-07

  HYBRIDSIG:
    target: https://eprint.iacr.org/2017/460
    title: Transitioning to a Quantum-Resistant Public Key Infrastructure
    author:
      -
        ins: N. Bindel
        name: Nina Bindel
      -
        ins: U. Herath
        name: Udyani Herath
      -
        ins: M. McKague
        name: Matthew McKague
      -
        ins: D. Stebila
        name: Douglas Stebila
    date: 2017-05

  HYBRIDSIGDESIGN:
    target: https://eprint.iacr.org/2023/423
    title: A Note on Hybrid Signature Schemes
    author:
    -
      ins: N. Bindel
      name: Nina Bindel
    -
      ins: B. Hale
      name: Britta Hale
    date: 2023-03

  I-D.ietf-tls-hybrid-design:

  I-D.ietf-pquip-pqt-hybrid-terminology:

  I-D.ounsworth-pq-composite-sigs:

  I-D.becker-guthrie-noncomposite-hybrid-auth:

  MOSCA:
    title: An Introduction to Quantum Computing, Oxford University Press
    author:
      -
        ins: P. Kaye
        name: Phillip Kaye
      -
        ins: R. Laflamme
        name: Raymond Laflamme
      -
        ins: M. Mosca
        name: Michele Mosca
    date: 2007-11

    NIST_PQC_FAQ:
    target: https://csrc.nist.gov/Projects/post-quantum-cryptography/faqs
    title: Post-Quantum Cryptography FAQs
    author:
      - org: National Institute of Standards and Technology (NIST)
    date: 2022-07-05

  RFC4949:


--- abstract

This document describes classification of design goals and security considerations
for hybrid digital signature schemes, including proof composability (that the
security of the hybrid signature scheme can easily be reduced to the ingredient
algorithms), non-separability of the ingredient signatures given a hybrid signature,
backwards/forwards compatiblity, hybrid generality, and simultaneous verification.

Discussion of this work is encouraged to happen on the IETF PQUIP mailing list
pqc@ietf.org or on the GitHub repository which contains the draft:
https://github.com/dconnolly/draft-connolly-pquip-hybrid-signature-spectrums

--- middle

<!--

# Todos

- shorten the text and revise as appropriate to an IETF draft instead of research paper
- include figures in ascii
- add discussion
- extend with discussion points from private emails between Britta, Nina and IETF
- extend with discussion points fromn IETF mailing lists - for both be very careful to provide
acknowledgements!!
- double-check and extend/refer to Florence' draft

> I left statements from Douglas' hybrid KEM draft in, because we might want to pull from them

> FD: Possible useful mailing list references:
> https://mailarchive.ietf.org/arch/msg/secdispatch/2Q6aYKi2u0ope-YHcRs684GBng8/
> https://mailarchive.ietf.org/arch/msg/secdispatch/IyYOal5zrGe7yXvGAD_PUh1jGtI/
> https://mailarchive.ietf.org/arch/msg/spasm/fFwsL1hJ3TLksmz_IbSYvaY8P7A/
> https://mailarchive.ietf.org/arch/msg/spasm/dVf00_AW0VxDSxmoKPnxbfbFQqU/
> https://mailarchive.ietf.org/arch/msg/spasm/C6ZD6WTgQXfsJTa46ruLGUvEdQc/
> I propose we just write what we want to write and then come back to the mailing lists to check
> we're capturing major points.
-->

# Introduction {#introduction}

> NB: Adapt a bit more to signatures (mention scalability issue), discuss and adapt notion:
> post-quantum vs next-generation, dowgrading vs stripping attack etc

Initial focus on the transition to use of post-quantum algorithms in protocols has
largely been on confidentiality, given the potential risk of store and decrypt
attacks, where data encrypted today using traditional algorithms could be
decrypted in the future by an attacker with a Cryptographically Relevant Quantum
Computer (CRQC). While traditional authentication is only at risk once a CRQC
exists, it is important to consider the transition to post-quantum authentication
before this point.  This is particularly relevant for systems where algorithm
turn-over is complex or takes a long time (e.g., long-lived systems with hardware
roots of trust), or where future checks on past authenticity play a role (e.g.,
digital signatures on legal documents).

Initial focus on the transition to use of post-quantum algorithms in protocols has
largely been on confidentiality, given the potential risk of store and decrypt
attacks, where data encrypted today using traditional algorithms could be decrypted
in the future by an attacker with a Cryptographically-Relevant Quantum Computer (CRQC).
While traditional authentication is only at risk once a CRQC exists, it is
important to consider the transition to post-quantum authentication before this
point.  This is particularly relevant for systems where algorithm turn-over is complex
or takes a long time (e.g., long-lived systems with hardware roots of trust), or
where future checks on past authenticity play a role (e.g., digital signatures
on legal documents).

One approach to designing quantum-resistant protocols, particularly during the
transition period from traditional to post-quantum algorithms, is incorporating
PQ/T Hybrid schemes, which combine both traditional and post-quantum algorithms
in one cryptographic scheme. Hybridization has been looked at for key
encapsulation [HYBRIDKEM], and in an initial sense for digital signatures
[HYBRIDSIG]. Compared to key encapsulation, hybridization of digital signatures,
where the verification tag may be expected to attest to both standard and
post-quantum components, is subtler to design and implement due to the
potential separability of the composite signatures and the risk of downgrade
attacks.  There are also a range of requirements and properties that may be
required from PQ/T signatures, not all of which can be achieved at once.

This document focuses on explaining advantages and disadvantages of different
hybrid signature scheme designs and different security goals for them. It is
intended as a resource for designers and implementers of hybrid signature schemes
to help them decide what properties they do and do not require from their scheme.
It intentionally does not propose concrete hybrid signature combiners or
instantiations thereof.

## Revision history

> **RFC Editor's Note:** Please remove this section prior to publication of a final version of this
> document.

- TBD-00: Initial version.

## Terminology {#terminology}

We follow existing Internet drafts on hybrid terminology [I-D.ietf-pquip-pqt-hybrid-terminology]
and hybrid key encapsulation mechanisms (KEM) [I-D.ietf-tls-hybrid-design] to enable settling on a
consistent language. We will make clear when this is not possible. In particular, we follow the
definition of 'post-quantum algorithm', 'traditional algorithms', and 'combiner'. Moreover, we use the
definition of 'certificate' to mean 'public-key certificate' as defined in [RFC4949].

- 'Signature scheme': A signature scheme is defined via the following three algorithms:
  - `KeyGen() -> (pk, sk)`: A probabilistic key generation algorithm, which generates a public
    verifying key `pk` and a secret signing key `sk`.
  - `Sign(sk, m) -> (sig)`: A probabilistic signature generation, which takes as input a secret
    signing key `sk` and a message `m`, and outputs a signature `sig`.
  - `Verify(pk, sig, m) -> b`: A verification algorithm, which takes as input a public verifying key
    `pk`, a signature `sig` and a message `m`, and outputs a bit `b` indicating `accept` ($b=1$) or
    `reject` ($b=0$) of the signature for message `m`.

- 'Hybrid signature scheme':  Following [I-D.ietf-pquip-pqt-hybrid-terminology], we define a hybrid
  signature scheme to be "a multi-algorithm digital signature scheme made up of two or more component
  digital signature algorithms [...]". We require that the security of the component schemes is based
  on the hardness of different cryptographic assumptions. In contrast to [I-D.ietf-pquip-pqt-hybrid-terminology],
  we will use the more general term 'hybrid signature scheme' instead of requiring one
  post-quantum and one traditional algorithm (i.e., PQ/T hybrid signature schemes) to allow also the
  combination of several post-quantum algorithms. The term 'composite' scheme is often used as a synonym
  for 'hybrid scheme'. This is different from [I-D.ietf-pquip-pqt-hybrid-terminology] where the term is used
  at the protocol level.

- 'Hybrid signature': A hybrid signature is the output of the hybrid signature scheme's signature
  generation. As synonyms we might use 'composite signature' or 'dual signature'.  For example, NIST define a dual signature as "two or more signatures on a common message" [NIST_PQC_FAQ].

- 'Component (signature) scheme': Component signature schemes are the cryptographic algorithms
  contributing to the hybrid signature scheme. This has a similar purpose as in [I-D.ietf-pquip-pqt-hybrid-terminology].
  In this draft, we will use 'ingredient signature scheme' as a synonym.

- 'Next-generation algorithms': Similarly to the case of hybrid KEMs [I-D.ietf-tls-hybrid-design],
  hybrid signatures are mostly motiviated as preparation for the post-quantum migration. Following
  [I-D.ietf-tls-hybrid-design], we opt to use the more generic term "next-generation" and "traditional"
  algorithm instead of "post-quantum" and "classical" algorithms.

- 'Artifact':  An artifact is evidence of sender intent to hybridize a signature that remains even if a component algorithm tag is removed. Artifacts can be e.g., at the algorithmic level (within the digital signature), or at the protocol level (within the message or certificate). Artifacts should be easily identifiable by the receiver in the case of signature stripping.


## Motivation for use of hybrid signature schemes {#motivation}

Before diving into the design goals for hybrid digital signatures,
it is worth taking a look at why hybrid digital signatures are desirable
for some applications. As many of the arguments hold in general for hybrid
algorithms, we again refer to [I-D.ietf-tls-hybrid-design] that summarizes these well.
In addition, we explicate the motivation for hybrid signatures here.

**Complexity.** Next-generation algorithms and their underlying hardness assumptions
are often more complex than traditional algorithms and as such carry a higher risk of implementation
mistakes and revision of parameters compared to traditional algorithms, such as RSA. RSA is a relatively simple algorithm to understand and
explain, yet during its existence and use there have been multiple attacks and refinements, such as
adding requirements to how padding and keys are chosen, and implementation issues such as cross-protocol
attacks. Thus, even in a relatively simple algorithm subtleties and caveats on implementation and
use can arise over time. Given the complexity of next generation algorithms, such discoveries and
caveats are likely.

Of note, next generation algorithms have been heavily vetted. Thus, if and when further information
on caveats and implementation issues come to light, it is less likely that a "break" will be
catastrophic. Instead, such vulnerabilities and issues may represent a weakening of security - which
may in turn be offset if a hybrid approach has been used.

The complexity of next-generation algorithms needs to be balanced against the fact that hybridization
itself adds more complexity to a protocol and introduces the risk of implementation mistakes
in the hybridization process.

One example of a next generation algorithm is the signature scheme ML-DSA
(a.k.a. Kyber-Dilithium) that has been selected for standardization by NIST. While
the scheme follows the know Fiat-Shamir transform to construct the signature scheme,
it also relies on rejection sampling that is known to give cache side channel
information (not necessarily leading to a known attack though). Furthermore,
recent attacks again some next-generation signature schemes such as MULTI-VARIATE
schemes might call into question the asymptotic and concrete security for conservative
adopters and therefore might hinder adoption.


**Time.**
The need to transition to quantum-resistant algorithms
now while simultaneously being aware of potential, hidden subtleties in their
resistance to standard attacks drives transition designs towards hybridization.
Mosca’s equation [MOSCA] very simply illustrates the risk of post-quantum
transition delay: $l + d > q$, where l is the information life-span, d is the time for
system transition to post-quantum algorithms, and q is the time before a quantum
computer is ready to execute cryptanalysis. As opposed to key exchange and KEMs,
it may not be obvious why there is urgency for an adoption of next-generation signatures;
namely, while encryption is subject to store-now-decrypt-later attacks, there may not
seem to be a parallel notion for authenticity, i.e., 'store-now-modify-later attacks'.
However, in larger systems, including national systems, space systems, large healthcare
support systems, and critical infrastructure, where acquisition and procurement time can be
measured in years and algorithm replacement may be difficult or even practically
impossible, this equation can have drastic implications.
In such systems, algorithm turn-over can be complex and difficult and can take considerable
time (such as in long-lived systems with hardware deployment),
meaning that an algorithm may be
committed to long-term, with no option for replacement. Long-term
committment creates further urgency for immediate next-generation algorithm selection.
Additionally, for some sectors furture checks on past authenticity plays a role (e.g., many
legal, financial, auditing, and governmental systems).
The 'store-now-modify-later' analogy would present challenges in such sectors, where future
analysis of past authentication may be more critical
than in e.g., internet connection use cases. As such there is an eagerness to use
next-generation signatures algorithms for some applications.

## Goals {#goals}
There are various security goals that can be achieved through hybridization. The following provides a
summary of these goals, while also noting where security goals are in conflict, i.e., that achievement
of one goal precludes another, such as backwards compatibility.

**Unforgability.** One goal is security of hybrid signature schemes, in particular that
EUF-CMA security is maintained as long as at least one of the ingredient schemes is EUF-CMA secure.
There might be, however, other goals in competition with this one, such as backward-compatibility,
where the EUF-CMA seucurity of the hybrid signature relies solely on the security of one of the ingredient
schemes instead of relying on both.

**Proof Composability.** Under proof composability, the ingredient algorithms are combined
in such a way that it is possible to prove a security reduction from the security
properties of hybrid signature scheme to the properties of the respective ingredient
signature schemes and, potentially, other building blocks such as hash functions, KDF, etc.
Otherwise an entirely new proof of security is required, and there is a lack of
assurance that the combination builds on the standardization processes and analysis performed to
date on ingredient algorithms. The resulting hybrid signature would be, in effect, an entirely
new algorithm of its own. The more two signature schemes are entangled, the more likely it is
that an entirely new proof is required, thus not meeting proof composability.

**Weak Non-Separability.** Non-Separability was one of the earliest
properties of hybrid digital signatures to be discussed [HYBRIDSIG]. It was
defined as the guarantee that an adversary cannot simply “remove” one of the
ingredient signatures without evidence left behind. For example there are artifacts
that a carefully designed verifier may be able to identify, or that are
identifiable in later audits. This was later termed Weak Non-Separability (WNS)
[HYBRIDSIGDESIGN]. Note that WNS does not restrict an adversary from potentially
creating a valid ingredient digital signatures from a hybrid one (a signature
stripping attack), but rather implies that such a digital signature will contain
artifacts of the separation. Thus authentication is not simply provided by the
sender to the receiver through correct verification of the digital signature(s),
but potentially through further investigation on the receiver side that may
extend well beyond traditional signature verification behavior. For instance, this
can intuitively be seen in cases of a message containing a context note
on hybrid authentication, that is then signed by all ingredient
algorithms/the hybrid signature scheme. If an adversary removes one
ingredient signature but not the other, then artifacts in the message
itself point to the possible existence of hybrid signature such as a
label stating “this message must be hybrid signed”. This might be a counter
measure against stripping attacks if the verifier expects a hybrid signature
scheme to ensure this property. However, it places the responsibility of signature
validity not only on the correct format of the message, as in a traditional
signature security guarantee, but the precise content thereof.

**Strong Non-Separability.** Strong Non-Separability (SNS) is a stronger notion
of WNS, introduced in [HYBRIDSIGDESIGN]. SNS guarantees that an adversary cannot take
as input a hybrid signature (and message) and output a valid ingredient signature
(and potentially different message) that will verify correctly. In other words,
separation of the hybrid signature into component signatures implies that the component
signature will fail verification (of the component signature scheme) entirely. Therefore,
authentication is provided by the sender to the receiver through correct verification of
the digital signature(s), as in traditional signature security experiments. It is not
dependent on other components, such as message content checking, or protocol level aspects,
such as public key provenance. As an illustrative example distinguishing WNS from SNS,
consider the case of ingredient algorithms $\Sigma_1.Sign$ and $\Sigma_2.Sign$ where
the hybrid signature is computed as a concatenation $(sig_1, sig_2)$, where
$sig_1 = \Sigma_1.Sign(hybridAlgID,m)$ and $sig_2 = \Sigma_2.Sign(hybridAlgID,m)$.
In this case, separation and delivery of a new message $m^* = (hybridAlgID,m)$ along
with signature $sig_1$ and $\Sigma_1.pk$ could allow for correct verification and the
hybrid artifact is embedded in the message instead of the signature (identifiable through
further investigation but the signature verification itself would not fail). Thus, this
case shows WNS (assuming the verification algorithm is defined accordingly) but not SNS.

Some work [I-D.ounsworth-pq-composite-sigs] has looked at reliance on the public
key certificate chains to explicitly define hybrid use of the public key. Namely,
that $\Sigma_1.pk$ cannot be used without $\Sigma_2.pk$. This implies pushing
the hybrid artifacts into the protocol and system level and a dependency on the
security of other verification algorithms (namely those in the certificate
chain). This further requires that security analysis of a hybrid digital signature requires
analysis of the key provenance, i.e., not simply that a valid public key is used but how it
hybridization and hybrid artifacts have been managed throughout the entire chain. External
dependencies such as this may imply hybrid artifacts lie outside the scope of the signature
algorithm itself. SNS may potentially be achieveable based on dependencies at the
system level.

<!--
However, since those
artifacts are outside the security definition scope for a digital
signature, namely definitions such EUF-CMA, we do not include them
in the SNS category.
-->

**Backwards/Forwards Compatibility.** Backwards compatibility refers
to the property where a hybrid algorithm may also be used for legacy
receivers that may take a hybrid signature and verify it as being
valid using only the verification algorithm of one component scheme
(e.g., the verification algorithm of the traditional signature scheme used in the
hybrid scheme), potentially ignoring the next-generation signature entirely. This
provides an option to transition various sender system attributes to next-generation
algorithms while still supporting select legacy receivers. Notably, this is a
verification property; the sender has provided a hybrid digital signature, but
the verifier is allowed, due to internal restrictions and/or implementation, to
only verify one component signature. Backwards compatibility may be further decomposed
to subcategories where ingredient key provenance is either separate or hybrid so as to
support implementations that cannot recognize (and/or process) hybrid signatures.

Forwards compatibility has also been a consideration in hybrid proposals
[I-D.becker-guthrie-noncomposite-hybrid-auth]. Forward compatibility assumes
that hybrid signature schemes will be used for some time, but that eventually
all systems will transition to use only one (particularly, only one
next-generation) algorithm. As this is very similar to backwards compatibility,
it also may imply separability of a hybrid algorithm; however, it could also
simply imply capability to support separate ingredient signatures. Thus the key
distinction between backwards and forwards compatibility is that backwards
compatibility may be needed for legacy systems that cannot use and/or process
hybrid or next-generation signatures, whereas in forwards compatibility the
system has those capabilities and can choose what to support (e.g., for
efficiency reasons).

As noted in [I-D.ietf-tls-hybrid-design], ideally, forward/backward
compatibility is achieved using redundant information as little as possible.

**Simultaneous Verification.** Simultaneous Verification (SV) builds on SNS and was
first introduced in [HYBRIDSIGDESIGN]. SV requires that not only are all ingredient
signatures needed to achieve a successful verification present in the hybrid signature,
but also that verification of both component algorithms occurs simultaneously. Namely,
"missing" information needs to be computed by the verifier so they cannot “quit” the
verification process before both component signatures are verified. SV mimics traditional
digital signatures guarantees, essentially ensuring that the hybrid digital signature
behaves as a single algorithm vs. two separate component stages. Alternatively phrased,
under an SV guarantee it is not possible for an unerring verifier to initiate termination
of the hybrid verification upon successful verification of one component algorithm without
also knowing if the other component succeeded or failed.

<!--
What the sender is assured
of is that one of two cases occurred: either 1) the receiver ignored
the digital signatures or 2) the receiver initiated verification of
the digital signatures (resulting in either successful or failed
verification). WNS complicates this situation, resulting in six cases
instead of two: 1) the receiver ignored the digital signatures, 2)
the receiver verified the full hybrid combination (with success or
failure); 3) the receiver initiated verification of the hybrid digital
signatures, but terminated once the standard component succeeded or failed; 4)
the receiver initiated verification of the hybrid digital signatures,
but terminated once the post-quantum component succeeded or failed; 5)
the receiver initiated verification of the standard signature only (with success
or failure), and 6) the receiver initiated verification of the post-quantum
signature only (with success or failure). It may initially appear
that (3) and (5) (resp. (4) and (6)) are similar, however (3) and (4)
are precisely the cases eliminated by SNS, i.e. that the verifier does
not take as input the hybrid digital signatures, instead only attempting
verification on one component. SNS thus improves the situation to only
four options. Still, the verifier can still terminate upon correctly
checking only one component signature without actually verifying both
parts. One could argue that a receiver who has checked the accuracy of
their implementation should be assured that both components are verifying.
This misconstrues the original intent though, which is to correctly mirror
traditional digital signatures properties in hybrid digital signatures;
ideally, the sender should be assured that there are only two
options: 1) ignore the digital signatures or 2) verify the digital signatures
(resulting in either failure or full verification). Simultaneous Verification
addresses this property.
-->

**Hybrid Generality.** Hybrid generality means that a general signature combiner
is defined, based on inherent and common structures of component digital signatures
"categories." For instance, since multiple signature schemes use a Fiat-Shamir
Transform, a hybrid scheme based on the transform can be made that is generalizable
to all such signatures. Such generality can also result in simplified constructions
where as more tailored hybrid variants might be more efficient in terms of sizes and
performance.

**High performance.** Similarly to performance goals noted for hybridization
of other cryptographic components [I-D.ietf-tls-hybrid-design] hybrid signature
constructions are expected to be as performant as possible. For most hybrid
signatures this means that the computation time should only minimally exceed
the sum of the component signature computation time. It is noted that performance
of any variety may come at the cost of other properties, such as hybrid generality.

**High space efficiency.**
Similarly to space considerations in [I-D.ietf-tls-hybrid-design], hybrid signature
constructions are expected to be as space performant as possible. This includes messages
(as they might increase if artifacts are used), public keys, and the hybrid signature.
For the hybrid signature, size should no more than minimally exceed the signature
size of the two component signatures. In some cases, it may be possible for a hybrid
signature to even be smaller than two component signatures.

**Minimal duplicate information.** Similarly to [I-D.ietf-tls-hybrid-design],
duplicated information should be avoided when possible. This might concern
repeated information in hybrid certificates or in the communication of component
certificates in additional to hybrid certificates (for example to acheive
backwards/forwards-comptability), or sending multiple public keys or
signatures of the same component algorithm.

# Non-separability spectrum

Non-separability is not a singular definition but rather is a scale,
representing `degrees` of separability hardness, visualized in Fig. 1.

|-----------------------------------------------------------------------------|  
|**No Non-Separability**                                                        
| no artifacts exist                                                             
|-----------------------------------------------------------------------------|    
|**Weak Non-Separability**                                                      
| artifacts exist in the message, signature, system, application, or protocol    
| ----------------------------------------------------------------------------|    
|**Strong Non-Separability**                                                    
| artifacts exist in hybrid signature                                            
| ----------------------------------------------------------------------------|    
|**Strong Non-Separability w/ Simultaneous Verification**                         
| artifacts exist in hybrid signature and verification or failure of both         
| components occurs simultaneously                                              
| ----------------------------------------------------------------------------|    
▼  

Fig. 1: Spectrum of non-separability from weakest to strongest.


At one end of the spectrum are schemes in which one of the ingredient
signatures can be stripped away with the verifier not being able to detect
the change during verification.An example of this includes simple concatenation
of signatures without any artifacts used. Nested signatures (where a message
is signed by one component algorithm and then the message-signature
combination is signed by the second component algorithm) may also fall
into this category, dependent on whether the inner or outer signature
is stripped off without any artifacts remaining.

Next on the spectrum are weakly non-separable signatures. Under Weak
Non-Separability, if one of the composite signatures of a hybrid is
removed artifacts of the hybrid will remain (in the message, signature,
or at the protocol level, etc.). This may enable the verifier to detect
if a component signature is stripped away from a hybrid signature, but
that detectability depends highly on the type of artifact and permissions.
For instance, if a message contains a label artifact "This message must be
signed with a hybrid signature" then the system must be allowed to analyze
the message components for possible artifacts. Whether a hybrid signature
offers (Weak/Strong) Non-Separability might also depend on the
implementation and policy of the protocol or application the hybrid signature
is used in on the verifier side. Such policies may be further ambiguous to
the sender, meaning that the type of authenticity offered to the receiver
is unclear.
In another example, under nested signatures the
verifier could be tricked into interpreting a new message as the
message/inner signature combination and verify only the outer signature.
In this case, the inner signature-tag is an artifact.

Third on the scale is the Strong Non-Separability notion, in which
separability detection is dependent on artifacts in the signature
itself. Unlike in Weak Non-Separability, where artifacts may be in
the actual message, the certificate, or in other non-signature
components, this notion more closely ties to traditional algorithm
security notions (such as EUF-CMA) where security is dependent on
the internal construct of the signature algorithm and its
verification. In this type, the verifier is enabled to detect artifacts
on an algorithmic level during verification. For example, the signature
itself  encodes the information that a hybrid signature scheme is
used. Examples of this type may be found in Algorithms 16/17 and 18/19
of [HYBRIDSIGDESIGN], assuming a "loose" verification implementation where the
verifier may skill a final bit comparison check.

For schemes achieving the most demanding security notions, i.e., Strong
Non-Separability with Simultaneous Verification, verification succeeds
not only when both of the component signatures are present but
also only when the verifier has verified both signatures. Moreover, no
information is leaked to the receiver during the verification process on
the possibile validity/invalidity of the component signatures until both
verify. This construct most closely mirrors traditional digital signatures
where, assuming that the verifier does verify a signature at all, the result
is either a positive verification of a the full signature or a failure
if the signature is not valid. For hybrid signatures, a `full signature`
implies the hybridization of both component algorithms, and therefore the
strongest non-separability notion enforces an all-or-nothing approach to
verification. Algorithms 10/11, 12/13, 14/15, 16/17, 18/19, and 20/21 of
[HYBRIDSIGDESIGN] are examples providing this type of security.



# Artifact spectrum

Hybridization necessarily implies the presence of artifacts as evidence.
Where such evidence resides differs, however. Some artifact locations have been
mentioned above, but these are explicitly laid out here across three general
categories of types of hybridization: concatenation, nesting, and true hybrid.

Concatenation refers to variants of hybridization where, for component algorithms
$\Sigma_1.Sign$ and $\Sigma_2.Sign$, the hybrid signature is calculated as a
concatenation $(sig_1, sig_2)$ such that $sig_1 = \Sigma_1.Sign(hybridAlgID,m)$
and $sig_2 = \Sigma_2.Sign(hybridAlgID,m)$. WNS may be a goal of a concatenation
approach.

Nesting refers to variants of hybridization where for component algorithms
$\Sigma_1.Sign$ and $\Sigma_2.Sign$, the hybrid signature is calculated in
a layered approach as $(sig_1, sig_2)$ such that
$sig_1 = \Sigma_1.Sign(hybridAlgID,m)$ and $sig_2 = \Sigma_2.Sign(hybridAlgID,(m, sig_1))$.
WNS and potentially SNS (depending on prediction that $sig_1$ would be targeted
in a stripping attack) may be goals of a nesting approach.

Fusion refers to variants of hybridization where for component algorithms
$\Sigma_1.Sign$ and $\Sigma_2.Sign$, the hybrid signature is calculated with
entaglement to produce a single hybrid signature $sig_h$ without clear component
constructs. SNS and potentially SV are goals of a fused hybrid approach.

In addition to the natural artifact placement shown above for each category,
the message $m$ in any of these categories may contain a label artifact, and/or
the certificates for the public keys may contain such artifacts such as in
[I-D.ounsworth-pq-composite-sigs].
visualized in Fig. 2.


| ---------------------------------------------- | ------------------------------------------------------ |  
| Ref|   **Location of artifacts of hybrid intent**    |    **Category**                           
| ---------------------------------------------- | ------------------------------------------------------ |  
|                                                                                      **Concatenated**                                       
| ---------------------------------------------- | ------------------------------------------------------ |  
| 1 |None                                                                   | No label in message, public keys are in separate certs  
| 2 |In message                                                        | Label in message, public keys are in separate certs     
| 3 |In cert                                                                 | No label in message, public keys are in combined cert   
| 4 |In message and cert                                         | Label in message, public keys are in combined cert      
| ---------------------------------------------- | ------------------------------------------------------ |  
|                                                                                      **Nested**                                            
| ---------------------------------------------- | ------------------------------------------------------ |  
| 5 |In message                                                        | Label in message, public keys are in separate certs     
| 6 |In cert                                                                | No label in message, public keys are in combined cert   
| 7 |In message and cert                                         | Label in message, public keys are in combined cert      
| ---------------------------------------------- | ------------------------------------------------------ |  
|                                                                                     **Fused**                                        
| ---------------------------------------------- | ------------------------------------------------------ |  
| 8 |In signature                                                        | Public keys are in separate certs                       
| 9 |In signature and message                                | Label in message, public keys are in separate certs     
|10 |In signature and cert                                        | Public keys are in combined cert                        
|11 |In signature and message and cert                 | Label in message, public keys are in combined cert      
| ---------------------------------------------- | ------------------------------------------------------ |  

Fig. 2: Spectrum of artifacts

Under a concatenation combiner, the artifacts and therefore validity of the message depends on
the message itself unless keys are provisioned in a combined certificate (as in option
cases 3 and 4). Option case 1 provides the weakest guarantees of hybrid identification,
as there are no prescribed artifacts.

The artifact guarantees provided by a nesting combiner are similar to those provided by
concatenation option cases 2, 3, and 4. Namely, if
$sig_2 = \Sigma_2.Sign(hybridAlgID,(m, sig_1))$, then the "message"
$(m, sig_1)$ input into $\Sigma_2.Sign$ actually contains the artifact and acts as a label.
Unless an additional label is provided within $m$ itself, $sig_1$ does not therefore contain
an artifact. This presents an implementation challenge as it is necessary to guess which
algorithm is more at risk for a stripping attack and choose the order of nesting accordingly.

Under a fused combiner, SNS also implies that artifacts of hybridization are present
within the signature. This can be coupled with artifacts in the message, such as
through use of a label, and/or artifacts in the certificate if keys are also provisioned
in a combined certificate.

# EUF-CMA Challenges
Under traditional signature scheme security assumptions such as EUF-CMA, the adversary
`wins` the security experiment if it can produce a new message $m'$ that a message-signature
pair $(m', sig)$ correctly verifies. This traditional security notion is challenged under
a hybrid construct.

The most straightforward comparison would be for the adversary to attempt to produce a new
message $m'$ that a message-hybrid signature pair $(m', sig_h)$ correctly verifies.
However, such a guarantee depends on the signature being strongly non-separable. Otherwise,
in practical terms a security experiment must capture the case that an existing or new
message $m$ could be verified with a component signature, e.g., to produce $(m', sig_1)$
that correctly verifies under $\Sigma_1.Sign$. Such considerations are beyond the scope
of traditional security analysis and represent considerations that would need to be
accounted for depending on the signature combiner method chosen.

# Blackbox spectrum
> NB: instead Hybrid generality spectrum, as this is what we define as one of the goals
On a practical notes, it is interesting to consider how entanglement
of two component schemes for the goal of creating a hybrid digital
signature affects approved use. This includes NIST guidance and
FIPS approval considerations. NIST provides the following guidance
(emphasis added),

> how to do quotes in ascii??
> https://kramdown.gettalong.org/syntax.html#blockquotes
> begin quote
    Assume that in a [hybrid] signature, \textit{one signature is
    generated with a NIST-approved signature scheme as specified
    in FIPS 186, while another signature(s) can be generated using
    different schemes}, e.g., ones that are not currently specified
    in NIST standards...`hybrid signatures` can be accommodated by
    current standards in ``FIPS mode,`` as defined in FIPS 140,
    provided at least one of the component methods is a properly
    implemented}, NIST-approved signature algorithm. For the purposes
    of FIPS 140 validation, any signature that is generated by a
    non-approved component scheme would not be considered a security
    function, since the NIST-approved component is regarded as
    assuring the validity of the `hybrid` signature. [NISTPQC_faqs]
> end quote}

>NB: Should we mention and discuss NIST and FIPS explictely?

The emphasized text point to two things: 1) the signature scheme
for one of the component hybrids must be approved and 2) that said
algorithm must be properly implemented. This leaves some ambiguity
as to whether only the algorithm must be approved and well implemented,
or if that implementation must go through an approvals process as well.
As such, there is a ``black box scale`` that developers may consider
as to whether they are using at least one approved component algorithm
(``black box algorithm``), or whether the implementation of that
component algorithm has gone through an approvals review (thus making
a ``black box implementation``). The former `black box algorithm`
would suggest a straightforward path for FIPS-140 approvals based
on the NIST guidelines; however, it is not inconceivable that using
a `black box implementation` could automate much of the certification
review and therefore be attractive to developers.

We provide a scale for the different nuances of black box properties,
together with  respective example constructions. In addition the
`black box algorithm` options (represented as the 1 or 2 approved
FIPS Algorithm box in blue) and the `black box implementation` options
(represented as the 1-approved and 2-approved fIPS implementation
alternatives in blue), we also include a 0-approved hybrid approach
for completeness of scale. This aligns to brand new signature algorithms
that are reducible to hybrid hardness assumptions but require
e.g., fresh NIST approval.

> build figure in Ascii and include it here with references to it

We align Alg. 10/11, 18/19, and 20/21 from this paper to the
`black box algorithm` interpretation. However, it is worth noting
that the algorithmic modifications to either the standard or
post-quantum component algorithms in these cases are minor (such as
the inclusion if extra information in a hash). Since an addition,
however minor, to an implementation implies that the implementation
is not black box, we show these alignments conservatively. The
remaining algorithms we provide in this paper align to either a
full component black box implementation or event a both-component
algorithm black box implementation approach.


| --------------------------------------------------------------------|  
| **Specification-Algorithmic Blackbox**  
| Signature combiner supports one component algorithm                 
| as an approved specification                                         
| --------------------------------------------------------------------|     
| **Algorithmic Blackbox**  
| Signature combiner supports both component algorithms as   
| approved specifications and hybrid scheme is not a "new" algorithm           
| --------------------------------------------------------------------|   
| **Software Blackbox**       
| Signature combiner supports one component algorithm                 
| as an approved software module                                      
| --------------------------------------------------------------------|   
| **Full Software Blackbox**     
| Signature combiner supports both component algorithms as            
| individual, approved software modules                              
| --------------------------------------------------------------------|  
▼  
Fig. 3: Blackbox spectrum.



# Discussion of Advantages/Disadvantages

- There is an inherent mutual exclusion between backwards compatibility and SNS.
While WNS allows for a valid separation under leftover artifacts, SNS will ensure
verification failure if a receiver attempts separation.


# Acknowledgements

This draft is based on the template of [I-D.ietf-tls-hybrid-design].

We would like to acknowledge the following people in alphabetical order who have contributed to pushing this draft forward, 
offered insights and perspectives, and/or stimulated work in the area:  
Scott Fluhrer   
Felix Günther  
John Gray   
Serge Mister  
Max Pala  
Mike Ounsworth   
Douglas Stebila  

# Related work {#related-work}
