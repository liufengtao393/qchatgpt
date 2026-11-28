"""Scan regression service logs for anomalies and enforce hard-gate exit codes."""

import argparse
from collections import Counter, defaultdict
import fnmatch
import glob
import json
from pathlib import Path
import re
from statistics import median
import sys

import yaml

from tools.regression.service_logs import TRACE, records


BLOCKING_KINDS = frozenset({'error', 'traceback', 'http_5xx', 'empty_exception_message'})


SECRET = re.compile(
    r"""(?ix)(\b(?:authorization|(?:[\w-]+[_-])?token|(?:[\w-]+[_-])?key|password|secret)["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|(?:bearer\s+|basic\s+)?[^\s,;&}\]]+)|\b(bearer\s+)[^\s,;"']+"""
)
VARIABLE = re.compile(
    r""""[^"]*"|'[^']*'|\b[\da-fA-F]{8}(?:-[\da-fA-F]{4}){3}-[\da-fA-F]{12}\b|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b|\b(?:0x[\da-fA-F]+|[\da-fA-F]{8,})\b|\d+"""
)
EMPTY = re.compile(r'(?:\bfailed\b.*|[\w.]+(?:Error|Exception)):\s*$', re.I)


def redact(text):
    return SECRET.sub(lambda match: (match[1] or match[2]) + '<redacted>', text)


def classify(record):
    stack = record.msg == TRACE or any(line.strip() == TRACE for line in record.continuation)
    if not stack and record.level not in ('WARN', 'ERROR', 'FATAL'):
        return None
    message = record.msg
    if record.access:
        method, path, status = record.access
        status_template = '5xx' if status >= 500 else str(status)
        route = '/'.join('#' if VARIABLE.fullmatch(segment) else segment for segment in path.split('/'))
        message = f'{method} {route} {status_template}'
        kind = 'http_5xx' if status >= 500 else 'warn'
    else:
        if stack:
            kind = 'traceback'
            if record.continuation:
                terminal = record.continuation[-1].strip()
                message = terminal if record.msg == TRACE else record.msg
                if not record.exc_type and re.match(r'^[\w.]+:', terminal):
                    record.exc_type = terminal.partition(':')[0]
        elif EMPTY.search(message) or (record.exc_type and not message.strip()):
            kind = 'empty_exception_message'
        else:
            kind = 'warn' if record.level == 'WARN' else 'error'
        message = VARIABLE.sub('#', redact(message)).strip()
    fingerprint = '|'.join(
        [record.service, record.module or record.file, record.func, record.exc_type, redact(message)]
    )
    return kind, fingerprint


def scan(files, allowlist, baselines):
    groups = {}
    totals = defaultdict(Counter)
    unknown = {}
    warn_counts = Counter()
    for path, service in files:
        with path.open(encoding='utf-8', errors='replace') as stream:
            for record in records(stream, service):
                counts = totals[record.service]
                counts['lines'] += 1 + len(record.continuation)
                if not record.level:
                    counts['unparsed'] += 1
                    if record.service not in unknown or not unknown[record.service]:
                        unknown[record.service] = redact(record.sample)[:400]
                    continue
                key = classify(record)
                if not key:
                    continue
                kind, fingerprint = key
                if kind == 'warn':
                    warn_counts[fingerprint] += 1
                if key not in groups:
                    groups[key] = dict(
                        kind=kind,
                        service=record.service,
                        fingerprint=fingerprint,
                        count=0,
                        first_ts=record.ts,
                        last_ts=record.ts,
                        sample=redact(record.sample)[:400],
                    )
                group = groups[key]
                group['count'] += 1
                if record.ts:
                    group['first_ts'] = min(record.ts, group['first_ts'] or record.ts)
                    group['last_ts'] = max(record.ts, group['last_ts'] or record.ts)
    anomalies = []
    for (kind, fingerprint), group in sorted(groups.items()):
        baseline = median([run.get(fingerprint, 0) for run in baselines]) if baselines and kind == 'warn' else None
        group['baseline_median'] = baseline
        count = group['count']
        if baseline is not None and count > max(2 * baseline, baseline + 20):
            group['kind'] = 'warn_growth'
        elif any(
            fnmatch.fnmatchcase(fingerprint, rule['pattern']) and count <= rule.get('max_count', count)
            for rule in allowlist
        ):
            continue
        anomalies.append(group)
    for service, counts in sorted(totals.items()):
        if counts['unparsed'] > 0.05 * counts['lines']:
            anomalies.append(
                dict(
                    kind='unparsed_ratio',
                    service=service,
                    fingerprint=f'{service}|unparsed',
                    count=counts['unparsed'],
                    baseline_median=None,
                    first_ts=None,
                    last_ts=None,
                    sample=unknown[service],
                )
            )
    return dict(
        services={svc: dict(lines=c['lines'], unparsed=c['unparsed']) for svc, c in totals.items()},
        warn_counts=warn_counts,
        anomalies=anomalies,
    )


def blocking_anomalies(report, *, strict=False):
    anomalies = report['anomalies']
    if strict:
        return list(anomalies)
    return [group for group in anomalies if group['kind'] in BLOCKING_KINDS]


def gate_summary(report, *, strict=False):
    blocking = blocking_anomalies(report, strict=strict)
    return dict(
        mode='strict' if strict else 'default',
        passed=not blocking,
        blocking_count=len(blocking),
        total_anomalies=len(report['anomalies']),
        blocking_kinds=sorted(BLOCKING_KINDS),
    )


def markdown(report, *, strict=False):
    anomalies = report['anomalies']
    gate = report.get('gate') or gate_summary(report, strict=strict)
    verdict = 'PASS' if gate['passed'] else 'FAIL'
    lines = [
        f'## Service logs: anomaly groups ({len(anomalies)})',
        '',
        f'Gate: **{verdict}** (`mode={gate["mode"]}`, `blocking={gate["blocking_count"]}`, `total={gate["total_anomalies"]}`)',
        '',
        'Service | Lines | Unparsed',
        '--- | ---: | ---:',
    ]
    for service, counts in sorted(report['services'].items()):
        lines.append(f'{service} | {counts["lines"]} | {counts["unparsed"]}')
    for group in anomalies[:30]:
        lines.extend(
            [
                '',
                f'- {group["service"]}: **{group["kind"]}** × {group["count"]} (baseline: {group["baseline_median"] if group["baseline_median"] is not None else "—"})',
                '',
                f'        {group["fingerprint"]}',
                f'        {group["first_ts"] or "—"} → {group["last_ts"] or "—"}',
                f'        {group["sample"]}',
            ]
        )
    if len(anomalies) > 30:
        lines.append('\nFull list in log-anomalies.json.')
    return '\n'.join(lines) + '\n'


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', nargs='+', required=True)
    parser.add_argument('--service-map', default='')
    parser.add_argument('--allowlist', type=Path, required=True)
    parser.add_argument('--baseline', nargs='+', type=Path, default=[])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument(
        '--strict',
        action='store_true',
        help='Fail on any unallowlisted anomaly (including warnings, warning growth, and unparsed ratio), not only blocking errors/tracebacks/5xx.',
    )
    args = parser.parse_args(argv)
    if not args.allowlist.is_file():
        parser.error(f'allowlist file not found: {args.allowlist}')
    mapping = dict(item.split('=', 1) for item in args.service_map.split(',') if item)
    paths = sorted(
        {
            Path(path).resolve()
            for pattern in args.input
            for path in glob.iglob(pattern, recursive=True)
            if Path(path).is_file()
        }
    )
    if not paths:
        parser.error('no input logs matched')
    raw_allowlist = yaml.safe_load(args.allowlist.read_text(encoding='utf-8'))
    if raw_allowlist is None:
        allowlist = []
    elif isinstance(raw_allowlist, list):
        allowlist = raw_allowlist
    else:
        parser.error('allowlist must be a YAML list of rules')
    files = [(path, mapping.get(path.name, path.stem)) for path in paths]
    baselines = [
        json.loads((path / 'log-anomalies.json' if path.is_dir() else path).read_text(encoding='utf-8'))['warn_counts']
        for path in args.baseline
    ]
    report = scan(files, allowlist, baselines)
    blocking = blocking_anomalies(report, strict=args.strict)
    report['gate'] = gate_summary(report, strict=args.strict)
    args.output.mkdir(exist_ok=True, parents=True)
    (args.output / 'log-anomalies.json').write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
    )
    (args.output / 'log-anomalies.md').write_text(markdown(report, strict=args.strict), encoding='utf-8')
    verdict = 'PASS' if report['gate']['passed'] else 'FAIL'
    summary_line = (
        f'log_scan: {verdict} '
        f'(mode={report["gate"]["mode"]}, services={len(report["services"])}, '
        f'total_anomalies={report["gate"]["total_anomalies"]}, blocking_anomalies={report["gate"]["blocking_count"]})'
    )
    if blocking:
        print(summary_line, file=sys.stderr)
        for group in blocking[:10]:
            print(
                f'  - [{group["kind"]}] {group["service"]} (x{group["count"]}): {group["fingerprint"]}',
                file=sys.stderr,
            )
        if len(blocking) > 10:
            print(f'  ... and {len(blocking) - 10} more blocking anomalies in log-anomalies.json', file=sys.stderr)
        return 1
    print(summary_line)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
