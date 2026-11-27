"""Opt-in, bounded comparisons of existing proxy paths against one controlled origin.

The caller owns the proxy core. Workers only perform HTTP measurements; terminating
a stalled worker therefore cannot orphan a core process or change host networking.
"""
import math
import multiprocessing
import random
import time
import urllib.parse

from . import bench

MAX_PATHS = 32
MAX_ROUNDS = 20
MAX_BUDGET = 3600
MAX_SAMPLE_TIMEOUT = 300
PROTOCOLS = frozenset(('direct', 'vless', 'vmess', 'trojan', 'ss', 'ssr', 'hysteria', 'hysteria2',
                       'tuic', 'wireguard', 'socks5', 'http', 'snell', 'ssh'))


def validate(origin, rounds=3, seed=0, budget=600, sample_timeout=120):
    if origin is None:
        raise ValueError('comparison requires an explicit --origin')
    try:
        bench.measurement_urls(origin)
    except (TypeError, ValueError):
        # urlsplit/port exceptions can include the input; never copy a private endpoint.
        raise ValueError('comparison origin must be HTTP(S), without credentials, path, query or fragment') from None
    for label, value, maximum in (('rounds', rounds, MAX_ROUNDS), ('budget', budget, MAX_BUDGET),
                                  ('sample timeout', sample_timeout, MAX_SAMPLE_TIMEOUT)):
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError('%s must be an integer between 1 and %d' % (label, maximum))
    if type(seed) is not int or not 0 <= seed <= 0xffffffff:
        raise ValueError('seed must be an integer between 0 and 4294967295')


def path_order(count, rounds, seed):
    """Shuffle once, then rotate so that each path occupies each position in a full cycle."""
    order = list(range(count))
    random.Random(seed).shuffle(order)
    return [order[index % count:] + order[:index % count] for index in range(rounds)]


def _worker(connection, proxy, quick, origin):
    try:
        result = bench.run(proxy, quick, log=lambda _: None, origin=origin)
        connection.send({'status': 'measured', 'result': result})
    except Exception as error:
        connection.send({'status': 'error', 'error_type': type(error).__name__})
    finally:
        connection.close()


def bounded_sample(proxy, quick, origin, timeout):
    """Enforce a wall-clock deadline even if a peer trickles data past socket timeouts."""
    context = multiprocessing.get_context('spawn')
    reader, writer = context.Pipe(duplex=False)
    worker = context.Process(target=_worker, args=(writer, proxy, quick, origin), daemon=True)
    started = time.monotonic()
    launched = False
    try:
        worker.start()
        launched = True
        writer.close()
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0 or not reader.poll(remaining):
            return {'status': 'timeout'}
        try:
            return reader.recv()
        except EOFError:
            return {'status': 'error', 'error_type': 'WorkerExited'}
    finally:
        reader.close()
        writer.close()
        if launched:
            # Successful senders normally exit immediately; all waits remain bounded.
            worker.join(0.1)
            if worker.is_alive():
                worker.terminate()
                worker.join(1)
            if worker.is_alive():
                worker.kill()
                worker.join(1)
            if worker.is_alive():
                raise RuntimeError('measurement worker could not be stopped')
        worker.close()


def _complete(result):
    def number(value, positive=True):
        return (type(value) in (int, float) and math.isfinite(value)
                and (value > 0 if positive else value >= 0))

    latency = result.get('latency', {})
    diagnostics = result.get('download_diagnostics', {})
    return (not result.get('errors') and latency.get('fails') == 0
            and number(latency.get('median'), positive=False)
            and all(number(result.get(key)) for key in ('down_1', 'down_4', 'up_1'))
            and all(diagnostics.get(key, {}).get('warmup_complete') is True
                    and not diagnostics[key].get('errors') for key in ('down_1', 'down_4')))


def run(paths, origin, quick=False, rounds=3, seed=0, budget=600, sample_timeout=120, log=print):
    """paths contain private {proxy, protocol}; output assigns anonymous IDs and retains failures.

    The budget covers sampling, including worker startup/cleanup. Stopping a worker
    can require up to 2.1 additional seconds after the deadline. Core setup is owned
    by the caller and is not part of this function's sampling budget.
    """
    validate(origin, rounds, seed, budget, sample_timeout)
    if not 1 <= len(paths) <= MAX_PATHS:
        raise ValueError('comparison requires between 1 and %d paths' % MAX_PATHS)
    public_paths = []
    for index, path in enumerate(paths):
        protocol = path.get('protocol')
        public_paths.append({'path_id': 'p%02d' % (index + 1),
                             'protocol': protocol if isinstance(protocol, str) and protocol in PROTOCOLS else 'other'})
    started = time.monotonic()
    deadline = started + budget
    output = {'schema': 'vps2vpn.protocol-comparison.v1', 'paths': public_paths, 'samples': [],
              'method': {'source_id': 'controlled', 'source_policy': 'controlled-no-fallback',
                         'redirect_policy': 'reject', 'origin_scheme': urllib.parse.urlsplit(origin).scheme,
                         'rounds': rounds, 'seed': seed, 'order': 'seeded-rotation', 'quick': quick,
                         'budget_seconds': budget, 'sample_timeout_seconds': sample_timeout,
                         'budget_scope': 'sampling', 'concurrent_samples': 1},
              'scheduled_samples': len(paths) * rounds, 'stopped': None}
    for round_index, order in enumerate(path_order(len(paths), rounds, seed), 1):
        for position, path_index in enumerate(order, 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                output['stopped'] = 'budget-exhausted'
                break
            path_id = public_paths[path_index]['path_id']
            log('round %d/%d, position %d: %s' % (round_index, rounds, position, path_id))
            sample_started = time.monotonic()
            sample = bounded_sample(paths[path_index].get('proxy'), quick, origin, min(sample_timeout, remaining))
            if sample['status'] == 'measured':
                sample['status'] = 'ok' if _complete(sample['result']) else 'incomplete'
            sample.update(round=round_index, position=position, path_id=path_id,
                          elapsed_seconds=round(time.monotonic() - sample_started, 3))
            output['samples'].append(sample)
        if output['stopped']:
            break
    output['attempted_samples'] = len(output['samples'])
    output['successful_samples'] = sum(sample['status'] == 'ok' for sample in output['samples'])
    output['complete'] = output['successful_samples'] == output['scheduled_samples']
    output['elapsed_seconds'] = round(time.monotonic() - started, 3)
    return output
