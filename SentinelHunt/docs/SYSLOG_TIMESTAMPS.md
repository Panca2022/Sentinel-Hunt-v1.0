# Assumption: year and timezone of the demo's syslog timestamps

The demo source (bastion-02, `sample_logs/`) uses classic syslog timestamps such as `Oct 24 09:15:45`. They carry
**no year and no timezone**.

What Agent 1 does: its timestamp step detected the layout `MMM d HH:mm:ss` (log: "timestamp: syslog 'MMM d HH:mm:ss'
-> dates 2026-2026") and registered an Elasticsearch `date` processor with that format and **no `timezone` setting and
no year**. Elasticsearch then:
- takes the **year in which the record is processed** (here 2026), and
- reads the clock time as **UTC** (the date processor's default timezone).

Observed: `Oct 24 09:15:45 bastion-02 sshd[7200]: …` → `@timestamp 2026-10-24T09:15:45.000Z`. The demo hypothesis
window "24 Oct 2026 between 09:15 and 09:25" is therefore in UTC, and the counts in the evidence files assume this.

Limits (worth stating in the report):
- logs written in another timezone would be shifted by their UTC offset; a real deployment should set the source's
  timezone on the date processor (per source/feed)
- logs from one year processed in the next (e.g. December lines ingested in January) would get the wrong year
- syslog has whole seconds only (no sub-second precision)

Not affected: the v3 dataset. Its timestamps are ISO 8601 with year and offset (`2026-10-22T17:07:40.247180+00:00`).
