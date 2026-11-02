# Domain extraction and split integrity audit

## Executive finding

**NO-GO for describing the saved overall metrics as a defensible evaluation of generalization to previously unseen domains.** The saved manifest mechanically isolates its extracted domain keys, but a source-level audit found that bare dotted tokens in ordinary text are treated as destinations, public-suffix-only authorities can become exact-host fallback groups, and syntactically valid but non-registrable strings are grouped as fallback hosts. In addition, the overall test metrics include records without a registrable destination domain. The registrable-domain-containing test slice is useful as an exploratory within-corpus slice, but the entire metric set should not be presented as domain-held-out performance until extraction is corrected and the split and metrics are regenerated in a separate experiment.

No URLs were opened; no DNS, network, or remote-service calls were made. The saved model was loaded only for read-only prediction reproduction; no fitting or tuning occurred.

## Extraction paths traced

- URL token discovery reuses `(?:https?://|www\.)[^\s<>\"']+|\b[a-z0-9.-]+\.[a-z]{2,63}(?:/[^\s<>\"']*)?` from `prepare_ml_datasets.py`. The scheme/www branch consumes non-whitespace text up to `<`, `>`, or quotes; the bare-domain branch accepts a dotted token with an alphabetic suffix and optional path. It is a syntactic regex, not a URL semantic validator.
- Scheme-bearing and `www.` values are treated as strong URL-shaped candidates. Protocol-relative values are supported by the hostname parser when passed through, but the shared URL regex does not independently start on `//`; they are reliably discovered in HTML attributes, not guaranteed in arbitrary prose.
- Bare candidates receive an `https://` prefix for parsing. In plain text, email, and URL-typed records, every regex match is considered, including a bare `example.com` mention in prose. HTML uses canonical URL, then `og:url`, then form actions, then all anchor hrefs. Image/script/style resource URLs are ignored. Email addresses themselves are skipped when the candidate is immediately preceded by `@`; other message-body URLs are extracted.
- Multiple candidate URLs in a record are retained. Each destination key unions the record's pre-existing near-duplicate component with other components containing that key. A multi-link HTML/email record can therefore bridge many domain nodes.
- Host normalization lowercases, strips a trailing dot, applies Python's built-in `idna` codec, validates label syntax/length, canonicalizes IP literals, and accesses `.port` to reject malformed ports. Query and fragment components do not affect the hostname. Single-label hosts such as `localhost` are rejected as unqualified.
- If the local PSL returns a registrable domain, grouping uses `registrable:<domain>`. Otherwise, any host sourced from a strong-shaped candidate (`http(s)`, `www.`, or a URL-only record) is assigned `exact_host_fallback:<host>`. This fallback does not distinguish a genuinely unlisted hostname from a public-suffix-only hostname or a malformed URL token that happens to pass hostname syntax.
- Candidate extraction is not the same as confirmed destination extraction. Bare dotted strings from ordinary text are grouped when the PSL recognizes them, even if they are citations, prose, examples, or unrelated references.

## Full dataset domain-key inventory

- Source records: 77,676; records with any candidate reported by the destination extractor: 62,691; records with a match from the shared `URL_RE`: 62,483. The extractor's extra count includes bare-IP-only URL records.
- Distinct selected hostnames: 46,806; hosts with a PSL registrable domain: 46,314; distinct registrable-domain keys: 39,802.
- Distinct IP keys: 374; exact-host fallback keys: 118; all exact-host fallback-key associated source rows (non-deduplicated across keys): 157.
- Public-suffix-only selected hostnames: 7; invalid/unusable candidate tokens: 34,122 across 139,940 candidates (20,229 distinct rejected candidate strings). Key category totals: `{'CDN or infrastructure domain': 20, 'IP address': 374, 'common URL shortener': 13, 'platform or social-media domain': 883, 'public-suffix-only value': 7, 'unresolved exact-host fallback (no PSL registrable domain)': 111, 'valid registrable domain': 38886}`. See full counts and examples in `domain_key_classification.csv`.
- Records with multiple grouping keys: 3,420; records without any selected hostname: 22,436; records with no high-confidence registrable domain or IP: 22,478.
- Domain key classifications are diagnostic heuristics for common shortening, platform, and infrastructure services. They do not cause any key to be excluded. The full CSV preserves unresolved and fallback keys.
- In `domain_key_classification.csv`, the `classification` value for a `registrable:<domain>` row describes its representative hostname, which may be a subdomain; the `domain_key` itself is the registrable-domain grouping key.

### Most frequent fallback keys

| Key | Source records | Example source records | Candidate token | Extraction methods | Context excerpt |
|---|---:|---|---|---|---|
| `exact_host_fallback:www.internationalfreecall.comif` | 6 | combined_reduced.json:source_record_8182, combined_reduced.json:source_record_15607 | `http://www.internationalfreecall.comIf` | explicit_or_bare_url_tokens | ry dialing the access number you found on your reseller's web page at:http://www.internationalfreecall.comIf you ordered a flat-rate domestic calling product using a 1-800 toll-fre |
| `exact_host_fallback:www.internationalfreecall.comin` | 6 | combined_reduced.json:source_record_8182, combined_reduced.json:source_record_15607 | `http://www.internationalfreecall.comIn` | explicit_or_bare_url_tokens | rds, international calling products, or marketing tools, please visit:http://www.internationalfreecall.comIn the meantime, the other network on this free calling promotion is OPEX, |
| `exact_host_fallback:www.internationalfreecall.comto` | 5 | combined_reduced.json:source_record_35070, combined_reduced.json:source_record_36942 | `http://www.internationalfreecall.comTo` | explicit_or_bare_url_tokens | ed Calling and 0 cents per minute!!To purchase this product, click on:http://www.internationalfreecall.comTo take a 60 minute trial of this product, send your phone number to:82285 |
| `exact_host_fallback:messenger.msn.comhttp` | 4 | combined_reduced.json:source_record_14699, combined_reduced.json:source_record_38930 | `http://messenger.msn.comhttp://xent.com/mailman/listinfo/fork` | explicit_or_bare_url_tokens | ________________________ Chat with friends online, try MSN Messenger: http://messenger.msn.comhttp://xent.com/mailman/listinfo/fork  |
| `exact_host_fallback:uk.my.yahoo.comm` | 4 | combined_reduced.json:source_record_1862, combined_reduced.json:source_record_44999 | `http://uk.my.yahoo.comm` | explicit_or_bare_url_tokens | er need on one web page from News and Sport to Email and Music Charts http://uk.my.yahoo.comm -- Irish Linux Users' Group: ilug@linux.ie http://www.linux.ie/mailman/listinf |
| `exact_host_fallback:www.multiplayerpoker.netcurrent` | 4 | combined_reduced.json:source_record_1956, combined_reduced.json:source_record_20048 | `http://www.MultiPlayerPoker.netCurrent` | explicit_or_bare_url_tokens | rt playing with new & old friends...download our free software now at http://www.MultiPlayerPoker.netCurrent Promotion: Â· $50 Deposit Bonus! - 100% bonus! Â· Daily High Hand - $25 |
| `exact_host_fallback:www.multiplayerpoker.netplay` | 4 | combined_reduced.json:source_record_1956, combined_reduced.json:source_record_20048 | `http://www.multiplayerpoker.netPlay` | explicit_or_bare_url_tokens | Get your favorite Poker action at http://www.multiplayerpoker.netPlay against real people from around the world for real money or just for fun. Acce |
| `exact_host_fallback:endeavors.comhttp` | 3 | combined_reduced.json:source_record_15077, combined_reduced.json:source_record_37560 | `http://endeavors.comhttp://xent.com/mailman/listinfo/fork` | explicit_or_bare_url_tokens | at endeavors.com Endeavors Technology, Inc. \| cell: +1.714.928.5476 \| http://endeavors.comhttp://xent.com/mailman/listinfo/fork  |
| `exact_host_fallback:mobile.msn.comhttp` | 3 | combined_reduced.json:source_record_37498, combined_reduced.json:source_record_46460 | `http://mobile.msn.comhttp://xent.com/mailman/listinfo/fork` | explicit_or_bare_url_tokens | _____________________ Send and receive Hotmail on your mobile device: http://mobile.msn.comhttp://xent.com/mailman/listinfo/fork  |
| `exact_host_fallback:www.ldew.com1win150ppmx3age16` | 3 | combined_reduced.json:source_record_7341, combined_reduced.json:source_record_22566 | `www.Ldew.com1win150ppmx3age16` | explicit_or_bare_url_tokens | 5gift guaranteed & Free entry 2 100 wkly draw txt MUSIC to 87066 TnCs www.Ldew.com1win150ppmx3age16 |
| `exact_host_fallback:www.chinatop.netsincerely` | 2 | combined_reduced.json:source_record_2226, combined_reduced.json:source_record_39251 | `http://www.chinatop.netSincerely` | explicit_or_bare_url_tokens | ry to disturb you! More information, please check our World Wide Web: http://www.chinatop.netSincerely yours-- Irish Linux Users' Group: ilug@linux.ie http://www.linux.ie/mailman/l |
| `exact_host_fallback:www.freepicklotto.xn--com-kla` | 2 | combined_reduced.json:source_record_41193, combined_reduced.json:source_record_41193 | `http://www.freepicklotto.comÂ` | explicit_or_bare_url_tokens | ORE MONEY! Less than 2cents a visitor.Â Space is limited. Order Now! http://www.freepicklotto.comÂ Trade Links - businessopps@aol.com ------------------------------------------- |
| `exact_host_fallback:www.glitschka.comflash` | 2 | combined_reduced.json:source_record_12266, combined_reduced.json:source_record_53490 | `http://www.glitschka.comFlash` | explicit_or_bare_url_tokens | tes, you'll want to review the solution. Â GnomeFEATURE Glitschka.com http://www.glitschka.comFlash animations, downloadable icons, artistic doodles, and details about the artis |
| `exact_host_fallback:www.mobiusvc.com.about` | 2 | combined_reduced.json:source_record_34097, combined_reduced.json:source_record_68423 | `www.mobiusvc.com.About` | explicit_or_bare_url_tokens | s. Mobius Venture Capital can be contacted by visiting their web site www.mobiusvc.com.About Seed Capital Partners Seed Capital Partners is an early-stage venture fund affi |
| `exact_host_fallback:www.newslist.netor` | 2 | combined_reduced.json:source_record_3370, combined_reduced.json:source_record_37064 | `http://www.newslist.netor` | explicit_or_bare_url_tokens | plus get a free email follow-up system to process your replies, visit:http://www.newslist.netor just reply to this message.Note: You will automatically be removed from this li |
| `exact_host_fallback:www.seedcp.com.about` | 2 | combined_reduced.json:source_record_34097, combined_reduced.json:source_record_68423 | `www.seedcp.com.About` | explicit_or_bare_url_tokens | mpanyDNA. For more information on Seed Capital Partners, please visit www.seedcp.com.About DataPower Technology DataPower Technology provides enterprises with intelligent |
| `exact_host_fallback:www.venrock.comabout` | 2 | combined_reduced.json:source_record_34097, combined_reduced.json:source_record_68423 | `www.venrock.comAbout` | explicit_or_bare_url_tokens |  any locale. For more information on Venrock Associates, please visit www.venrock.comAbout Mobius Venture Capital Mobius Venture Capital, formerly SOFTBANK Venture Capita |
| `exact_host_fallback:053d33558d578d2cafe77639209ab4d9.html` | 1 | combined_reduced.json:source_record_60689 | `053d33558d578d2cafe77639209ab4d9.html` | url_only_or_url_type_tokens | 053d33558d578d2cafe77639209ab4d9.html |
| `exact_host_fallback:65.218.171.48click` | 1 | combined_reduced.json:source_record_71989 | `http://65.218.171.48Click` | explicit_or_bare_url_tokens | ! Face Plates As Low As 2.98! Lithium Ion Batteries As Low As 6.94! http://65.218.171.48Click Below For Accessories On All NOKIA, MOTOROLA LG, NEXTEL, SAMSUNG, QUALCOMM, ER |
| `exact_host_fallback:65.218.171.48hands` | 1 | combined_reduced.json:source_record_71989 | `http://65.218.171.48Hands` | explicit_or_bare_url_tokens | Unbelievable Prices On Cell Phones And Accessories:http://65.218.171.48Hands Free Ear Buds 1.99! Phone Holsters 1.98! Phone Cases 1.98! Car Chargers 1.98 |

The fallback keys are not validated destinations simply because the regex and URL parser accepted their hostname syntax. `domain_key_classification.csv` records counts, representative source IDs, extraction method, and a short source excerpt for each key. Review the high-frequency and malformed-looking entries there; the table above keeps only the most frequent keys.

## 12,341-text connected component

- Component ID: `33ad9b084ea1fb4f024863df94d45639593b39eec7ff61a8dd62502e4b046093`.
- Source records: 12,372; unique normalized text groups: 12,341; distinct domain-key nodes: 7,221; bipartite edges (unique existing near-duplicate-component/domain-key pairs): 23,616; near-duplicate component nodes: 12,051.
- Source-record label distribution: label 0=10,783, label 1=1,589; unique normalized-text label distribution: label 0=10,772, label 1=1,569.
- Promotional-review source records: 106; one conflicting-label near-duplicate component contains 5 source records. The number of distinct text groups in that specific conflict component was not separately verified in this report.
- The complete node list and degree/frequency columns are in `largest_component_domains.csv`.

| Top domain nodes by directly associated records | Direct source records | Direct unique texts | Adjacent domain keys via shared near-duplicate components |
|---|---:|---:|---:|
| `registrable:wikipedia.org` | 878 | 877 | 238 |
| `registrable:facebook.com` | 867 | 861 | 921 |
| `registrable:linux.ie` | 659 | 659 | 344 |
| `registrable:sourceforge.net` | 627 | 626 | 504 |
| `registrable:youtube.com` | 602 | 602 | 630 |
| `registrable:sf.net` | 562 | 561 | 339 |
| `registrable:xent.com` | 500 | 498 | 360 |
| `registrable:twitter.com` | 482 | 475 | 1159 |
| `registrable:yahoo.com` | 471 | 471 | 588 |
| `registrable:linkedin.com` | 416 | 415 | 419 |
| `registrable:000webhostapp.com` | 389 | 389 | 4 |
| `registrable:google.com` | 382 | 382 | 857 |
| `registrable:freshrpms.net` | 382 | 382 | 133 |
| `registrable:amazon.com` | 312 | 312 | 129 |
| `registrable:thinkgeek.com` | 302 | 301 | 185 |

| Top-N domain nodes | Source records covered (union) | Unique texts covered (union) |
|---:|---:|---:|
| 1 | 878 (7.1%) | 877 (7.1%) |
| 5 | 3,505 (28.3%) | 3,497 (28.3%) |
| 10 | 4,970 (40.2%) | 4,958 (40.2%) |
| 25 | 7,738 (62.5%) | 7,723 (62.6%) |

The hub analysis distinguishes direct key frequency from graph reach. If top-N coverage is small while the component contains thousands of keys and edges, the component is a chain/bridge effect rather than one dominant destination. High direct frequency can also be legitimate for a newsletter/archive containing many old links; that does not establish that every linked host was a destination in the original message.

## Deterministic parser test suite

- Actual results: 13/16 parser-plus-destination-policy cases passed. Full expected-versus-actual rows are in `parser_test_results.csv`; intentional failures expose behaviors requiring correction.
- Important observed behavior: `https://co.uk` is syntactically accepted and the JDK PSL returns no registrable domain; the experiment's strong-URL fallback then groups `co.uk` as an exact host, although it is a public-suffix-only value. Likewise, `https://aol.comsite/path` passes hostname syntax but has no registrable result and enters exact-host fallback.
- `I read example.com yesterday` yields a bare-domain regex match and is treated as a destination because the local PSL recognizes `example.com`. This is not a parser failure in `urlsplit`; it is a source-candidate classification limitation.
- The built-in Python `idna` codec converts the Unicode test host to its ASCII punycode form; it does not by itself document which IDNA policy/version semantics are intended by the project.

## Public Suffix List dependency assessment

- Current implementation uses Oracle JDK `java version "27.0.1.0.3" 2026-10-25` `sun.security.util.RegisteredDomain` and the bundled PSL snapshot `backend\notebooks\oracleJdk-27\lib\security\public_suffix_list.dat` (SHA-256 `37e71e43c8605f29b9072f152d0ea4708735cdf335a5b68b2bc2f875760806c3`). The API is in an internal `sun.*` package; this couples the split to a JDK implementation/version and is not a stable Python dependency interface.
- Locally installed candidate Python PSL packages: `none of tldextract, publicsuffix2, publicsuffixlist, python-domain-utils`. A pinned Python library could be reproducible if its release accepts a local immutable PSL snapshot and runtime remote fetching is disabled; the candidate API behavior was not verified from local/official package docs here, so this remains unresolved. No package was installed and no documentation or list was downloaded.
- The current JDK snapshot itself is local and can be pinned by JDK build plus file hash, so this run did not require runtime network access. Its portability and API stability remain weaker than a project-owned pinned parser/snapshot with tested behavior.

## Split, quarantine, and metric audit

- Primary inclusion is `partition in {train, validation, test}` and `quarantine_status != true`; all source rows remain in the manifest. Existing promotional-review and conflicting-label quarantine propagates across the full domain-connected component.
- Records without registrable-domain keys remain in the primary split by text/near-duplicate/domain-connected component. No-registrable-domain test groups: 3,284 of 9,682; these do not demonstrate unseen-registrable-domain generalization. The saved metrics' `test_url_containing` slice uses `URL_RE` and contains 7,444 groups; the manifest URL flag is true for 7,470 groups because the destination extractor additionally counts bare-IP-only candidates.
- Inferred input-type counts among test groups: `{'email': 51, 'html': 1975, 'plain_text': 2381, 'url': 5249}`. URL-containing and inferred `url` type are different slices: the former also includes other types that contain a URL token.
- The source record text and manifest were re-parsed with the exact saved extraction helpers; extracted host sets and URL-containing flags matched the manifest for all 77,676 records.
- The saved model was loaded using scikit-learn 1.8.0 and predicted once per test normalized-text group (n=9,656, all group IDs unique). Recomputed confusion matrix and all saved scalar metrics match `metrics.json` exactly: True.
- The URL/non-URL and inferred-input-type slices also match the saved metrics exactly: True. Recomputed formatted `classification_report.txt` matches byte-for-text after trimming final whitespace: True.
- No per-example test-prediction file exists among the experiment artifacts. Therefore a saved prediction-to-label row audit is unavailable; this audit reproduced predictions from the saved pipeline and checked that the one-per-group evaluation construction matches the aggregate report. The text classification report's aggregate support and class metrics agree with the recomputed predictions.
- Domain-component grouping is conservative: any selected URL/host key shared by records links their near-duplicate components. Questionable fallback hosts can create false joins and over-quarantine; if they misspell/absorb a true hostname, they can also fail to join records that should share a domain. Thus zero overlap counts prove separation only for extracted keys, not correctness of the extracted destination identity.
- Multiple-domain HTML/email records can create large components by chaining destinations. The giant component has both conflict/promotion quarantine; the available node/edge and hub statistics show whether it is driven by a few hubs or many bridges.
- Overall metrics combine URL-containing records (7,444), non-URL-containing records (2,212), and no-domain records. Only records with reliable registrable destination identities can support the intended unseen-domain claim. The current report's domain-containing subset is still a within-source, label-unadjudicated experiment.

## Recommendation and next steps

**NO-GO** for presenting the current overall metrics as a defensible unseen-domain generalization estimate. Preserve these artifacts as an exploratory result. Before a replacement experiment, review candidate extraction with a strict URL parser and context-specific acceptance rules; distinguish confirmed URL authorities, HTML page destinations, email body links, bare prose mentions, IPs, public-suffix-only values, and unresolved hosts. Do not group public suffixes or unverified fallback hosts as if they were confirmed registrable destinations. Recompute components and quarantine without relaxing text/domain leakage constraints, then report (a) registrable-domain-bearing test records, (b) no-domain/non-URL test records, and (c) unresolved-host records separately. Pin a stable PSL library and immutable local suffix snapshot only after offline behavior is documented and parser tests pass. No changes to the old split or model are made by this audit.

## Artifacts created

- `domain_integrity_audit.md`
- `domain_key_classification.csv`
- `largest_component_domains.csv`
- `parser_test_results.csv`
