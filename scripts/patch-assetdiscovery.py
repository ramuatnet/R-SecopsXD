"""One-shot patcher: rewrite assetDiscovery.run() for parallel capped sources (A3)."""
import io

p = 'src/engines/builtin/assetDiscovery.ts'
s = io.open(p, encoding='utf8').read()

start = s.index('    // ---- 1. DNS records ----')
end = s.index('    const summary =')

new_body = """    const originUrl = new URL(ctx.target.origin);
    const targetPort = Number(originUrl.port) || (originUrl.protocol === 'https:' ? 443 : 80);

    // A3: all independent sources run in parallel, each hard-capped, so a
    // single unreachable source can no longer dominate the scan wall-clock.
    const bucketCandidates = [...new Set([
      domain, domain.replace(/\\./g, '-'), domain.replace(/\\./g, ''),
      `www-${domain.replace(/\\./g, '-')}`, `${domain.replace(/\\./g, '-')}-assets`, `${domain.replace(/\\./g, '-')}-backups`,
    ])].slice(0, 6);

    const [dnsAssets, ctNames, sanRecon, attribution, buckets] = await Promise.all([
      dnsTimeout(discoverDnsAssets(domain), DNS_SOURCE_CAP_MS, [] as Awaited<ReturnType<typeof discoverDnsAssets>>),
      fetchCtNames(domain),
      (originUrl.protocol === 'https:' || targetPort === 443)
        ? httpRecon(hostname, targetPort, hostname, true)
        : Promise.resolve(undefined),
      (async () => {
        const ips = await resolveWithFallback(hostname);
        const publicIps = [...new Set(ips.map((a) => a.address))].filter((ip) => !isPrivateIp(ip)).slice(0, 4);
        const results = await Promise.allSettled(publicIps.map((ip) => whoisIpAttribution(ip)));
        return { publicIps, results };
      })(),
      ctx.mode === 'active'
        ? dnsTimeout(probeCloudStorage(bucketCandidates), 8_000, [] as Awaited<ReturnType<typeof probeCloudStorage>>)
        : Promise.resolve([] as Awaited<ReturnType<typeof probeCloudStorage>>),
    ]);

    // ---- 1. DNS records ----
    if (dnsAssets.length > 0) {
      findings.push({
        rawId: 'asset-dns-records',
        title: `DNS records for ${domain}: ${dnsAssets.length} record(s)`,
        category: 'A01',
        severity: 'info',
        confidence: 'high',
        status: 'informational',
        asset: domain,
        locator: domain,
        evidence: [{
          kind: 'process',
          command: `DNS enumeration ${domain} (CNAME/MX/NS/TXT)`,
          observation: dnsAssets.slice(0, 12).map((a) => `${a.source}: ${a.value}`).join('; ').slice(0, 400),
        }],
        explanation: 'Publicly observable DNS records for the domain space. Mail (MX) and nameserver (NS) hosts are part of the external attack surface.',
        remediation: 'Keep DNS records current; remove stale records pointing at decommissioned hosts.',
        references: [],
      });
    } else {
      notes.push('no DNS records enumerable (resolver denied; fallback resolvers also failed or timed out)');
    }

    // ---- 2. Certificate Transparency + subdomain liveness ----
    if (ctNames !== undefined && ctNames.length > 0) {
      const dns = await import('node:dns/promises');
      const live: string[] = [];
      await Promise.allSettled(ctNames.slice(0, RESOLVE_MAX).map(async (name) => {
        const addrs = await dnsTimeout(dns.lookup(name).catch(() => undefined), 2_500, undefined);
        if (addrs !== undefined) live.push(`${name} \\u2192 ${addrs.address}`);
      }));
      findings.push({
        rawId: 'asset-ct-logs',
        title: `Certificate Transparency: ${ctNames.length} certificate name(s) in the ${domain} space (${live.length} resolve)`,
        category: 'A01',
        severity: 'info',
        confidence: 'high',
        status: 'informational',
        asset: domain,
        locator: domain,
        evidence: [{
          kind: 'process',
          command: `CT log search crt.sh q=%.${domain}`,
          observation: `names: ${ctNames.slice(0, 15).join(', ')}${ctNames.length > 15 ? ` \\u2026(+${ctNames.length - 15})` : ''}; resolving: ${live.slice(0, 10).join(', ') || 'none'}`,
        }],
        explanation: 'Hostnames issued public TLS certificates for this domain space. Unfamiliar entries may be forgotten (shadow) infrastructure. Discovered assets are listed only \\u2014 they are not scanned; register them as targets to assess them.',
        remediation: 'Review certificate issuance: revoke/expire certificates for decommissioned hosts and ensure new issuance follows the change process.',
        references: ['https://certificate.transparency.dev/'],
      });
    } else {
      notes.push('CT log search unavailable or empty (crt.sh unreachable or no certs)');
    }

    // ---- 3. certificate SANs of the target itself ----
    if (sanRecon !== undefined && sanRecon.open && sanRecon.sans.length > 0) {
      findings.push({
        rawId: 'asset-cert-sans',
        title: `Target TLS certificate covers ${sanRecon.sans.length} SAN name(s)`,
        category: 'A01',
        severity: 'info',
        confidence: 'high',
        status: 'informational',
        asset: domain,
        locator: hostname,
        evidence: [{
          kind: 'process',
          command: `TLS handshake ${hostname}:${targetPort}`,
          observation: `CN=${sanRecon.cn ?? 'n/a'} issuer=${sanRecon.issuer ?? 'n/a'} SANs=${sanRecon.sans.slice(0, 12).join(', ')}`,
        }],
        explanation: 'Additional hostnames covered by the same certificate \\u2014 part of the same deployment surface.',
        remediation: 'No action; inventory context.',
        references: [],
      });
    }

    // ---- 4. IP attribution (passive; public IPs only) ----
    {
      const lines: string[] = [];
      for (let i = 0; i < attribution.publicIps.length; i++) {
        const a = attribution.results[i];
        if (a?.status === 'fulfilled' && a.value !== undefined) {
          lines.push(`${attribution.publicIps[i]} \\u2192 ${a.value.asn} | ${a.value.country} | ${a.value.owner}`);
        }
      }
      if (lines.length > 0) {
        findings.push({
          rawId: 'ip-attribution',
          title: `IP attribution: ${lines[0]!.slice(0, 80)}`,
          category: 'A01',
          severity: 'info',
          confidence: 'high',
          status: 'informational',
          asset: domain,
          locator: attribution.publicIps[0]!,
          evidence: [{
            kind: 'process',
            command: `Team Cymru IP\\u2192ASN whois for ${attribution.publicIps.join(', ')}`,
            observation: lines.join('; ').slice(0, 400),
          }],
          explanation: 'ASN/owner/country for the target IPs (cloud provider vs on-prem). Useful for asset ownership attribution and cloud-config correlation.',
          remediation: 'No action; inventory context.',
          references: ['https://www.team-cymru.com/ip-asn-mapping'],
        });
      } else if (attribution.publicIps.length > 0) {
        notes.push('IP attribution unavailable (whois service unreachable from this network)');
      }
    }

    // ---- 5. AXFR zone transfer (active only; needs NS from the DNS source) ----
    if (ctx.mode === 'active') {
      const nsRecords = dnsAssets.filter((a) => a.type === 'nameserver').slice(0, NS_AXFR_MAX);
      if (nsRecords.length === 0) {
        notes.push('AXFR skipped: no NS records discovered');
      } else {
        const axfrResults = await Promise.allSettled(nsRecords.map((ns) => tryAxfr(ns.value.replace(/\\.$/, ''), domain)));
        for (let i = 0; i < nsRecords.length; i++) {
          const r = axfrResults[i];
          if (r?.status === 'fulfilled' && r.value.transferred) {
            const nsHost = nsRecords[i]!.value.replace(/\\.$/, '');
            findings.push({
              rawId: 'zone-transfer-possible',
              title: `DNS zone transfer (AXFR) succeeded against ${nsHost} \\u2014 full zone disclosed`,
              category: 'A02',
              severity: 'high',
              confidence: 'high',
              status: 'confirmed',
              asset: domain,
              locator: `${nsHost}:53`,
              evidence: [{
                kind: 'process',
                command: `AXFR ${domain} @${nsHost}`,
                observation: `rcode=0, ${r.value.records} record(s) transferred`,
              }],
              explanation: 'The nameserver answers AXFR requests without authentication, disclosing the entire zone (all hostnames) to anyone.',
              remediation: 'Disable AXFR for unauthenticated clients; restrict zone transfers to designated secondaries via TSIG.',
              references: ['https://cwe.mitre.org/data/definitions/200.html'],
            });
          }
          // refused/failed AXFR is the healthy case \\u2014 recorded in detail only, never a finding
        }
      }

      // ---- 6. cloud bucket probes (active only; GETs target cloud providers) ----
      for (const b of buckets) {
        findings.push({
          rawId: 'cloud-bucket-public',
          title: `Publicly listable cloud storage: ${b.value.slice(0, 120)}`,
          category: 'A01',
          severity: 'medium',
          confidence: 'medium',
          status: 'probable',
          asset: domain,
          locator: b.value.slice(0, 120),
          evidence: [{
            kind: 'process',
            command: 'Cloud storage public-access probe',
            observation: `${b.value} (source: ${b.source})`,
          }],
          explanation: 'A cloud storage bucket named after the domain responds as publicly listable. Verify it contains no sensitive objects.',
          remediation: 'Disable public listing on buckets; require authenticated access.',
          references: [],
        });
      }
    }

"""

s = s[:start] + new_body + s[end:]
io.open(p, 'w', encoding='utf8', newline='\n').write(s)
print('rewritten OK')
