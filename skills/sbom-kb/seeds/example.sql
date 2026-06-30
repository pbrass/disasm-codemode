-- Example seed file. Seeds are loaded in sorted order by build_sbom.py.
-- Add your own seed*.sql files with CVEs, reachability verdicts, and github-review records.
-- The .db is disposable (rebuilt from schema + seeds by rebuild.sh); seeds are the source of truth.

-- Example: register a host you acquired artifacts from
-- INSERT OR REPLACE INTO host(alias,ip,build,os_version,role,notes)
--   VALUES('myhost','10.0.0.1','1.0.0','Linux 5.15','fleet-current','lab appliance');

-- Example: add a CVE + its reachability verdict
-- INSERT INTO cve(cve_id,component,component_type,severity,present_on_fleet,fixed_in_patch,present_on_successor,summary,url,triage_status)
--   VALUES('CVE-2024-XXXX','libexpat.so.1','library','High',1,1,0,'expat OOB write in XML parsing','https://nvd.nist.gov/...','todo');
-- INSERT INTO analysis(cve_id,component,reachable,exploitability,reachability_condition,confirm_step,verdict,status)
--   VALUES('CVE-2024-XXXX','libexpat.so.1','preauth-remote','plausible','attacker XML hits expat parser pre-auth','send malformed XML to :443','live n-day if reachable','open');

-- Example: log a github commit you reviewed (even dead-ends -- so coverage is auditable)
-- INSERT INTO github_review(component,url,ref_type,reviewed_date,security_relevant,reachable,analysis,links_to)
--   VALUES('openldap','https://github.com/openldap/openldap/commit/abc123','commit','2026-06-15','no','n/a','cosmetic refactor, no security impact','');

-- Example: record a CVE-less silent upstream fix
-- INSERT INTO upstream_fix(component,repo_url,ref,date,landed_version,present_on_fleet,security_relevance,summary,url)
--   VALUES('openldap','https://git.openldap.org/openldap/openldap','abc123','2025-01-15','2.6.8',1,'fixes a double-free in modrdn','modrdn double-free on error path','https://...');
