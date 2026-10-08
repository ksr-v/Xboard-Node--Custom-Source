<?php
/** Isolated CLI fixtures for the explicitly authorized panel integration test.
 * Credentials stay in a 0600 runtime manifest outside the repository. No global
 * setting, existing record, whole Redis keyspace or general worker is changed.
 * Run as the panel owner with PHP 8.3:
 *   php panel_fixture.php create --state=ABSOLUTE_PRIVATE_STATE --panel-root=ABSOLUTE_PANEL_ROOT
 *   php panel_fixture.php status|process-jobs --state=...
 *   php panel_fixture.php set-user-state --state=... --banned=true|false
 *   php panel_fixture.php reset-devices|cleanup --state=... --nodes-stopped=true
 * create requires --port-singbox, --port-xray, --cert-file and --key-file.
 * --private-result may designate private-result.json beside state.json for
 * an authorized coordinator; stdout and public records contain booleans only.
 * Stop every fixture Node before reset/cleanup; the flag is an explicit caller
 * attestation. process-jobs invokes only whitelisted fixture traffic/stat handle
 * methods, so it proves real enqueue/handler behavior, not a general worker.
 */
declare(strict_types=1);

use App\Models\Server;
use App\Models\ServerMachine;
use App\Models\User;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

ini_set('display_errors', '0');
umask(0077);
$phase = 'arguments';
$statePath = '';

function ensure(bool $condition, string $code): void
{
    if (!$condition) {
        throw new RuntimeException($code);
    }
}

function options(array $args): array
{
    $result = [];
    foreach ($args as $arg) {
        ensure(preg_match('/^--([a-z-]+)=(.*)$/s', $arg, $match) === 1, 'invalid_option');
        ensure(!isset($result[$match[1]]), 'duplicate_option');
        $result[$match[1]] = $match[2];
    }
    return $result;
}

function saveJson(string $path, array $value): void
{
    ensure(!is_link($path), 'refuse_symlink_output');
    $temp = $path . '.new-' . bin2hex(random_bytes(6));
    $stream = fopen($temp, 'x');
    ensure($stream !== false, 'cannot_create_private_file');
    try {
        ensure(chmod($temp, 0600), 'cannot_protect_private_file');
        $text = json_encode($value, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        ensure(fwrite($stream, $text) === strlen($text), 'cannot_write_private_file');
    } finally {
        fclose($stream);
    }
    ensure(rename($temp, $path), 'cannot_commit_private_file');
}

function publicProjection(string $command, array $result): array
{
    $checks = [['check' => $command . '-completed', 'passed' => true]];
    $baseline = $result['baseline'] ?? null;
    if (is_array($baseline)) {
        foreach (['original_configuration_unchanged', 'counts_restored'] as $name) {
            if (array_key_exists($name, $baseline)) {
                $checks[] = ['check' => $name, 'passed' => (bool) $baseline[$name]];
            }
        }
    }
    if (array_key_exists('original_configuration_unchanged', $result)) {
        $checks[] = ['check' => 'original_configuration_unchanged', 'passed' => (bool) $result['original_configuration_unchanged']];
    }
    if (isset($result['fixture_related_rows_remaining'])) {
        $checks[] = ['check' => 'fixture_rows_removed', 'passed' => array_sum($result['fixture_related_rows_remaining']) === 0];
    }
    $passed = array_reduce($checks, static fn (bool $carry, array $check): bool =>
        $carry && $check['passed'] === true, true);
    return ['passed' => $passed, 'checks' => $checks];
}

function fingerprint(): array
{
    $excluded = [
        'v2_user' => ['u', 'd', 't', 'online_count', 'last_online_at', 'last_login_at', 'updated_at'],
        'v2_server' => ['u', 'd', 'last_check_at', 'last_push_at', 'online', 'online_conn', 'updated_at'],
        'v2_server_machine' => ['last_seen_at', 'load_status', 'updated_at'],
        'v2_server_group' => [],
        'v2_settings' => [],
    ];
    $result = ['configuration_rows' => [], 'counts' => [], 'excluded_dynamic_fields' => $excluded];
    foreach ($excluded as $table => $skip) {
        $result['configuration_rows'][$table] = [];
        foreach (DB::table($table)->orderBy('id')->get() as $record) {
            $row = (array) $record;
            $id = (string) $row['id'];
            foreach ($skip as $column) {
                unset($row[$column]);
            }
            ksort($row);
            $result['configuration_rows'][$table][$id] = hash('sha256', json_encode($row, JSON_THROW_ON_ERROR));
        }
    }
    foreach (array_merge(array_keys($excluded), ['v2_stat_user', 'v2_stat_server', 'v2_server_machine_load_history', 'v2_traffic_reset_logs']) as $table) {
        if (Schema::hasTable($table)) {
            $result['counts'][$table] = DB::table($table)->count();
        }
    }
    return $result;
}

function compareBaseline(array $state): array
{
    $current = fingerprint();
    $changed = [];
    foreach ($state['baseline']['configuration_rows'] as $table => $rows) {
        foreach ($rows as $id => $hash) {
            if (($current['configuration_rows'][$table][$id] ?? null) !== $hash) {
                $changed[] = ['table' => $table, 'id' => (int) $id];
            }
        }
    }
    $countMismatch = [];
    foreach ($state['baseline']['counts'] as $table => $count) {
        if ($table !== 'v2_server_machine_load_history' && ($current['counts'][$table] ?? null) !== $count) {
            $countMismatch[] = $table;
        }
    }
    return [
        'original_configuration_unchanged' => count($changed) === 0,
        'changed_original_records' => $changed,
        'counts_restored' => count($countMismatch) === 0,
        'count_mismatch_tables' => $countMismatch,
        'all_observed_counts_equal' => $current['counts'] === $state['baseline']['counts'],
        'dynamic_count_exclusions' => ['v2_server_machine_load_history' => 'Existing machines may append heartbeat history; fixture history is independently required to be absent after cleanup.'],
        'baseline_counts' => $state['baseline']['counts'],
        'current_counts' => $current['counts'],
    ];
}

function loadState(string $path): array
{
    ensure(is_file($path) && !is_link($path), 'private_state_missing');
    ensure((fileperms($path) & 0077) === 0, 'private_state_permissions_too_open');
    $state = json_decode(file_get_contents($path), true, 64, JSON_THROW_ON_ERROR);
    ensure(($state['schema'] ?? null) === 1, 'invalid_state_schema');
    ensure(preg_match('/^xboard-node-test-[a-f0-9]{24}$/', $state['marker'] ?? '') === 1, 'invalid_state_marker');
    ensure(($state['state_path'] ?? '') === $path, 'state_path_changed');
    foreach (['group_id', 'user_id'] as $field) {
        ensure(is_int($state[$field] ?? null) && $state[$field] > 0, 'invalid_fixture_id');
    }
    ensure(array_keys($state['machines'] ?? []) === ['singbox', 'xray'], 'invalid_fixture_machines');
    return $state;
}

function guardFixture(array $state): void
{
    $marker = $state['marker'];
    $group = DB::table('v2_server_group')->where('id', $state['group_id'])->first();
    $user = DB::table('v2_user')->where('id', $state['user_id'])->first();
    ensure($group !== null && $group->name === $marker, 'group_marker_guard_failed');
    ensure($user !== null && $user->email === $marker . '@example.invalid'
        && $user->remarks === $marker && (int) $user->group_id === $state['group_id']
        && hash_equals($state['uuid'], (string) $user->uuid), 'user_marker_guard_failed');
    ensure(DB::table('v2_user')->where('group_id', $state['group_id'])->where('id', '<>', $state['user_id'])->count() === 0, 'group_contains_nonfixture_user');
    $nodeIds = [];
    foreach ($state['machines'] as $kernel => $fixture) {
        ensure(is_int($fixture['machine_id']) && is_int($fixture['node_id']), 'invalid_machine_node_id');
        $machine = DB::table('v2_server_machine')->where('id', $fixture['machine_id'])->first();
        $node = DB::table('v2_server')->where('id', $fixture['node_id'])->first();
        ensure($machine !== null && $machine->name === $marker . '-' . $kernel && $machine->notes === $marker
            && hash_equals($fixture['token'], (string) $machine->token), 'machine_marker_guard_failed');
        ensure($node !== null && $node->name === $marker . '-' . $kernel && $node->type === 'vless'
            && (int) $node->machine_id === $fixture['machine_id']
            && json_decode((string) $node->group_ids, true) === [(string) $state['group_id']]
            && in_array($marker, json_decode((string) $node->tags, true) ?? [], true), 'node_marker_guard_failed');
        ensure(DB::table('v2_server')->where('machine_id', $fixture['machine_id'])->where('id', '<>', $fixture['node_id'])->count() === 0, 'machine_contains_nonfixture_node');
        $nodeIds[] = $fixture['node_id'];
    }
    ensure(count(array_unique($nodeIds)) === 2, 'fixture_node_ids_overlap');
    foreach (DB::table('v2_server')->whereNotIn('id', $nodeIds)->get(['group_ids']) as $node) {
        $groups = json_decode((string) $node->group_ids, true) ?? [];
        ensure(!in_array((string) $state['group_id'], array_map('strval', $groups), true), 'group_contains_nonfixture_node');
    }
}

function queueRedis()
{
    ensure(config('queue.default') === 'redis', 'test_requires_real_redis_queue');
    return Redis::connection(config('queue.connections.redis.connection', 'default'));
}

function fixtureJob(string $raw, array $state): ?object
{
    $allowed = [App\Jobs\TrafficFetchJob::class, App\Jobs\StatUserJob::class, App\Jobs\StatServerJob::class];
    $payload = json_decode($raw, true);
    $serialized = $payload['data']['command'] ?? null;
    if (!is_string($serialized) || !in_array($payload['data']['commandName'] ?? '', $allowed, true)) {
        return null;
    }
    try {
        $job = @unserialize($serialized, ['allowed_classes' => $allowed, 'max_depth' => 32]);
        if (!is_object($job) || !in_array(get_class($job), $allowed, true)) {
            return null;
        }
        $reflection = new ReflectionObject($job);
        $server = $reflection->getProperty('server')->getValue($job);
        $data = $reflection->getProperty('data')->getValue($job);
        $protocol = $reflection->getProperty('protocol')->getValue($job);
        $ids = array_column($state['machines'], 'node_id');
        if (!is_array($server) || !in_array($server['id'] ?? null, $ids, true)
            || (float) ($server['rate'] ?? -1) !== 1.0 || $protocol !== 'vless'
            || !is_array($data) || count($data) !== 1 || array_key_first($data) !== $state['user_id']) {
            return null;
        }
        $traffic = reset($data);
        if (!is_array($traffic) || array_keys($traffic) !== [0, 1]) {
            return null;
        }
        foreach ($traffic as $bytes) {
            if (!is_int($bytes) || $bytes < 0 || $bytes > 1073741824) {
                return null;
            }
        }
        if ($reflection->hasProperty('recordType') && !in_array($reflection->getProperty('recordType')->getValue($job), ['d', 'm'], true)) {
            return null;
        }
        return $job;
    } catch (Throwable $error) {
        return null;
    }
}

function fixtureNodeSync(string $raw, array $state): bool
{
    $payload = json_decode($raw, true);
    if (($payload['data']['commandName'] ?? '') !== App\Jobs\NodeUserSyncJob::class || !is_string($payload['data']['command'] ?? null)) {
        return false;
    }
    try {
        $job = @unserialize($payload['data']['command'], ['allowed_classes' => [App\Jobs\NodeUserSyncJob::class], 'max_depth' => 16]);
        if (!$job instanceof App\Jobs\NodeUserSyncJob) {
            return false;
        }
        $reflection = new ReflectionObject($job);
        return $reflection->getProperty('userId')->getValue($job) === $state['user_id']
            && in_array($reflection->getProperty('oldGroupId')->getValue($job), [null, $state['group_id']], true)
            && in_array($reflection->getProperty('action')->getValue($job), ['created', 'updated', 'deleted'], true);
    } catch (Throwable $error) {
        return false;
    }
}

function queueStatus(array $state): array
{
    $redis = queueRedis();
    $result = [];
    foreach (['traffic_fetch', 'stat', 'node_sync', 'default'] as $queue) {
        $key = 'queues:' . $queue;
        $length = (int) $redis->llen($key);
        $classes = [];
        $fixture = 0;
        foreach ($redis->lrange($key, 0, 999) as $raw) {
            $payload = json_decode($raw, true);
            $class = $payload['data']['commandName'] ?? 'unknown';
            if (!is_string($class) || preg_match('/^[A-Za-z_\\\\][A-Za-z0-9_\\\\]*$/', $class) !== 1) {
                $class = 'unknown';
            }
            $classes[$class] = ($classes[$class] ?? 0) + 1;
            if (fixtureJob($raw, $state) !== null || fixtureNodeSync($raw, $state)) {
                $fixture++;
            }
        }
        $inflight = [];
        foreach (['reserved', 'delayed'] as $suffix) {
            ensure((int) $redis->zcard($key . ':' . $suffix) <= 1000, 'refuse_large_shared_inflight_queue');
            $inflight[$suffix] = 0;
            foreach ($redis->zrange($key . ':' . $suffix, 0, 999) as $raw) {
                if (fixtureJob($raw, $state) !== null || fixtureNodeSync($raw, $state)) {
                    $inflight[$suffix]++;
                }
            }
        }
        $result[$queue] = ['ready' => $length, 'reserved' => (int) $redis->zcard($key . ':reserved'),
            'delayed' => (int) $redis->zcard($key . ':delayed'), 'sample_truncated' => $length > 1000,
            'class_counts' => $classes, 'fixture_ready' => $fixture,
            'fixture_reserved' => $inflight['reserved'], 'fixture_delayed' => $inflight['delayed']];
    }
    return $result;
}

function publicStatus(array $state): array
{
    $user = DB::table('v2_user')->where('id', $state['user_id'])->first(['id', 'u', 'd', 'banned', 'device_limit', 'online_count', 'last_online_at', 't']);
    $machines = [];
    foreach ($state['machines'] as $kernel => $fixture) {
        $node = DB::table('v2_server')->where('id', $fixture['node_id'])->first(['id', 'u', 'd', 'enabled']);
        $machine = DB::table('v2_server_machine')->where('id', $fixture['machine_id'])->first(['id', 'last_seen_at']);
        $machines[$kernel] = ['node' => $node, 'machine' => $machine,
            'load_history_count' => DB::table('v2_server_machine_load_history')->where('machine_id', $fixture['machine_id'])->count(),
            'ws_alive' => (bool) Cache::get('node_ws_alive:' . $fixture['node_id']),
            'stat_rows' => DB::table('v2_stat_server')->where('server_id', $fixture['node_id'])->count()];
    }
    return ['user' => $user, 'group_id' => $state['group_id'], 'machines' => $machines,
        'legacy_global_server_token_configured' => (string) admin_setting('server_token', '') !== '',
        'user_stat_rows' => DB::table('v2_stat_user')->where('user_id', $state['user_id'])->count(),
        'pending_check_fixture' => (bool) Redis::sismember('traffic:pending_check', (string) $state['user_id']),
        'queues' => queueStatus($state)];
}

function processJobs(array $state): array
{
    $redis = queueRedis();
    $processed = [];
    $skipped = 0;
    foreach (['traffic_fetch', 'stat'] as $queue) {
        $key = 'queues:' . $queue;
        ensure((int) $redis->llen($key) <= 1000, 'refuse_large_shared_queue');
        foreach ($redis->lrange($key, 0, 999) as $raw) {
            $job = fixtureJob($raw, $state);
            if ($job === null) {
                $skipped++;
                continue;
            }
            // Remove this exact approved payload only; never pop a shared queue.
            if ((int) $redis->lrem($key, 1, $raw) !== 1) {
                continue; // A real worker may have taken it concurrently.
            }
            try {
                DB::transaction(static function () use ($job): void { $job->handle(); });
            } catch (Throwable $error) {
                $redis->lpush($key, $raw); // Preserve the original fixture job for review/retry.
                throw new RuntimeException('fixture_job_handler_failed', 0, $error);
            }
            $class = get_class($job);
            $processed[$class] = ($processed[$class] ?? 0) + 1;
        }
    }
    return ['handler_mode' => 'fixture_allowlist_original_job_handle', 'processed_classes' => $processed,
        'other_jobs_skipped' => $skipped, 'status' => publicStatus($state)];
}

function clearDeviceCaches(array $state, bool $cleanup): array
{
    $uid = $state['user_id'];
    $deleted = (int) Redis::del('user_devices:' . $uid, 'device:db_throttle:' . $uid);
    DB::table('v2_user')->where('id', $uid)->update(['online_count' => 0]);
    $forgotten = 0;
    foreach ($state['machines'] as $fixture) {
        $nid = $fixture['node_id'];
        Redis::srem('device:push_pending_nodes', (string) $nid);
        $keys = ['node_ws_alive:' . $nid];
        foreach (['vless', 'VLESS'] as $type) {
            foreach (['ONLINE_USER', 'LAST_CHECK_AT', 'LAST_PUSH_AT', 'LOAD_STATUS', 'LAST_LOAD_AT', 'METRICS'] as $suffix) {
                $keys[] = "SERVER_{$type}_{$suffix}_{$nid}";
            }
            $keys[] = "USER_ONLINE_CONN_{$type}_{$nid}_{$uid}";
        }
        foreach ($keys as $key) {
            $forgotten += Cache::forget($key) ? 1 : 0;
        }
    }
    if ($cleanup) {
        Redis::srem('traffic:pending_check', (string) $uid);
    }
    return ['fixture_redis_keys_deleted' => $deleted, 'fixture_cache_keys_forgotten' => $forgotten];
}

try {
    ensure(PHP_SAPI === 'cli', 'cli_only');
    $command = $argv[1] ?? '';
    ensure(in_array($command, ['create', 'status', 'process-jobs', 'reset-devices', 'set-user-state', 'cleanup'], true), 'invalid_command');
    $opts = options(array_slice($argv, 2));
    $statePath = $opts['state'] ?? '';
    $dir = dirname($statePath);
    ensure(basename($statePath) === 'state.json' && str_starts_with($dir, '/') && $dir !== '/'
        && is_dir($dir) && realpath($dir) === $dir && !is_link($dir)
        && (fileperms($dir) & 0077) === 0, 'unsafe_runtime_state_path');
    $privateResultPath = $opts['private-result'] ?? null;
    if ($privateResultPath !== null) {
        ensure(dirname($privateResultPath) === $dir && basename($privateResultPath) === 'private-result.json', 'unsafe_private_result_path');
    }
    $lock = fopen($dir . '/fixture.lock', 'c');
    ensure($lock !== false && flock($lock, LOCK_EX), 'fixture_lock_failed');
    $phase = 'bootstrap';
    $panelRoot = $opts['panel-root'] ?? '';
    ensure(realpath($panelRoot) === $panelRoot && is_file($panelRoot . '/vendor/autoload.php'), 'panel_root_missing');
    ob_start();
    require $panelRoot . '/vendor/autoload.php';
    $app = require $panelRoot . '/bootstrap/app.php';
    $app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
    ob_end_clean();
    $phase = $command;
    if ($command === 'create') {
        ensure(!file_exists($statePath), 'refuse_existing_state');
        $baseline = fingerprint();
        $marker = 'xboard-node-test-' . bin2hex(random_bytes(12));
        $ports = ['singbox' => (int) ($opts['port-singbox'] ?? 0), 'xray' => (int) ($opts['port-xray'] ?? 0)];
        ensure($ports['singbox'] !== $ports['xray'], 'fixture_ports_overlap');
        foreach ($ports as $port) {
            ensure($port >= 1024 && $port <= 65535, 'invalid_fixture_port');
        }
        $cert = $opts['cert-file'] ?? '';
        $key = $opts['key-file'] ?? '';
        ensure(str_starts_with($cert, '/') && str_starts_with($key, '/'), 'absolute_node_cert_paths_required');
        $state = ['schema' => 1, 'phase' => 'active', 'marker' => $marker, 'state_path' => $statePath,
            'created_at' => time(), 'baseline' => $baseline, 'machines' => []];
        DB::transaction(function () use (&$state, $marker, $ports, $cert, $key, $statePath): void {
            $state['group_id'] = (int) DB::table('v2_server_group')->insertGetId(['name' => $marker, 'created_at' => time(), 'updated_at' => time()]);
            $user = User::withoutEvents(static fn () => User::create([
                'email' => $marker . '@example.invalid', 'password' => password_hash(bin2hex(random_bytes(32)), PASSWORD_BCRYPT),
                'uuid' => (string) Str::uuid(), 'token' => Str::random(32), 'group_id' => $state['group_id'], 'plan_id' => null,
                'transfer_enable' => 10737418240, 'u' => 0, 'd' => 0, 'banned' => 0, 'is_admin' => 0, 'is_staff' => 0,
                'device_limit' => 1, 'speed_limit' => 0, 'expired_at' => time() + 86400, 'remind_expire' => 0,
                'remind_traffic' => 0, 'remarks' => $marker,
            ]));
            $state['user_id'] = (int) $user->id;
            $state['uuid'] = (string) $user->uuid;
            foreach ($ports as $kernel => $port) {
                $machine = ServerMachine::withoutEvents(static fn () => ServerMachine::create([
                    'name' => $marker . '-' . $kernel, 'notes' => $marker, 'token' => Str::random(32), 'is_active' => true,
                ]));
                $node = Server::withoutEvents(static fn () => Server::create([
                    'type' => 'vless', 'name' => $marker . '-' . $kernel, 'rate' => 1, 'host' => '127.0.0.1',
                    'port' => (string) $port, 'server_port' => $port, 'group_ids' => [(string) $state['group_id']],
                    'route_ids' => [], 'protocol_settings' => ['tls' => 1, 'network' => 'tcp', 'flow' => '',
                        'tls_settings' => ['server_name' => 'localhost', 'allow_insecure' => false]],
                    'cert_config' => ['cert_mode' => 'file', 'cert_file' => $cert, 'key_file' => $key],
                    'show' => false, 'enabled' => true, 'machine_id' => $machine->id, 'u' => 0, 'd' => 0, 'tags' => [$marker],
                ]));
                $state['machines'][$kernel] = ['machine_id' => (int) $machine->id, 'node_id' => (int) $node->id,
                    'token' => (string) $machine->token, 'port' => $port];
            }
            saveJson($statePath, $state);
        });
        guardFixture($state);
        $result = ['user_id' => $state['user_id'], 'group_id' => $state['group_id'],
            'machines' => array_map(static fn ($m) => array_diff_key($m, ['token' => true]), $state['machines']),
            'baseline_counts' => $baseline['counts'], 'original_configuration_unchanged' => compareBaseline($state)['original_configuration_unchanged']];
    } else {
        $state = loadState($statePath);
        if ($state['phase'] === 'cleaned') {
            ensure(in_array($command, ['status', 'cleanup'], true), 'fixture_already_cleaned');
            $result = ['already_cleaned' => true, 'baseline' => compareBaseline($state)];
        } else {
            guardFixture($state);
            if ($command === 'status') {
                $result = publicStatus($state);
                $result['baseline'] = compareBaseline($state);
            } elseif ($command === 'process-jobs') {
                $result = processJobs($state);
            } elseif ($command === 'set-user-state') {
                ensure(in_array($opts['banned'] ?? '', ['true', 'false'], true), 'banned_boolean_required');
                DB::table('v2_user')->where('id', $state['user_id'])->update(['banned' => $opts['banned'] === 'true' ? 1 : 0]);
                foreach ($state['machines'] as $fixture) {
                    App\Services\NodeSyncService::notifyFullSync($fixture['node_id']);
                }
                $result = ['user_id' => $state['user_id'], 'banned' => $opts['banned'] === 'true',
                    'notified_fixture_node_ids' => array_column($state['machines'], 'node_id')];
            } elseif ($command === 'reset-devices') {
                ensure(($opts['nodes-stopped'] ?? '') === 'true', 'nodes_stopped_confirmation_required');
                $result = clearDeviceCaches($state, false);
                $result['status'] = publicStatus($state);
            } else {
                ensure(($opts['nodes-stopped'] ?? '') === 'true', 'nodes_stopped_confirmation_required');
                $result = ['processed_pending_jobs' => processJobs($state)];
                $queueState = queueStatus($state);
                foreach (['traffic_fetch', 'stat', 'node_sync', 'default'] as $queue) {
                    ensure(!$queueState[$queue]['sample_truncated'], 'refuse_large_shared_queue_cleanup');
                    ensure($queueState[$queue]['fixture_reserved'] === 0 && $queueState[$queue]['fixture_delayed'] === 0, 'refuse_fixture_inflight_queue_cleanup');
                }
                foreach (['traffic_fetch', 'stat'] as $queue) {
                    ensure($queueState[$queue]['fixture_ready'] === 0, 'fixture_jobs_remain');
                }
                $syncRemoved = 0;
                foreach (['node_sync', 'default'] as $queue) {
                    foreach (queueRedis()->lrange('queues:' . $queue, 0, 999) as $raw) {
                        if (fixtureNodeSync($raw, $state)) {
                            $syncRemoved += (int) queueRedis()->lrem('queues:' . $queue, 1, $raw);
                        }
                    }
                }
                $result['fixture_sync_jobs_removed'] = $syncRemoved;
                guardFixture($state);
                $result['cache_cleanup'] = clearDeviceCaches($state, true);
                $ids = array_column($state['machines'], 'node_id');
                $machineIds = array_column($state['machines'], 'machine_id');
                $result['deleted'] = DB::transaction(function () use ($state, $ids, $machineIds): array {
                    guardFixture($state);
                    $deleted = [];
                    foreach (['v2_stat_user', 'v2_traffic_reset_logs'] as $table) {
                        if (Schema::hasTable($table)) {
                            $deleted[$table] = DB::table($table)->where('user_id', $state['user_id'])->delete();
                        }
                    }
                    $deleted['v2_stat_server'] = DB::table('v2_stat_server')->whereIn('server_id', $ids)->delete();
                    $deleted['v2_server_machine_load_history'] = DB::table('v2_server_machine_load_history')->whereIn('machine_id', $machineIds)->delete();
                    $deleted['v2_server'] = DB::table('v2_server')->whereIn('id', $ids)->delete();
                    $deleted['v2_server_machine'] = DB::table('v2_server_machine')->whereIn('id', $machineIds)->delete();
                    $deleted['v2_user'] = DB::table('v2_user')->where('id', $state['user_id'])->delete();
                    $deleted['v2_server_group'] = DB::table('v2_server_group')->where('id', $state['group_id'])->delete();
                    return $deleted;
                });
                $state['phase'] = 'cleaned';
                $state['cleaned_at'] = time();
                saveJson($statePath, $state);
                $result['baseline'] = compareBaseline($state);
                $result['fixture_related_rows_remaining'] = [
                    'users' => DB::table('v2_user')->where('id', $state['user_id'])->count(),
                    'groups' => DB::table('v2_server_group')->where('id', $state['group_id'])->count(),
                    'servers' => DB::table('v2_server')->whereIn('id', $ids)->count(),
                    'machines' => DB::table('v2_server_machine')->whereIn('id', $machineIds)->count(),
                    'machine_history' => DB::table('v2_server_machine_load_history')->whereIn('machine_id', $machineIds)->count(),
                    'user_stats' => DB::table('v2_stat_user')->where('user_id', $state['user_id'])->count(),
                    'server_stats' => DB::table('v2_stat_server')->whereIn('server_id', $ids)->count(),
                ];
                ensure(array_sum($result['fixture_related_rows_remaining']) === 0, 'fixture_rows_remain');
                ensure($result['baseline']['original_configuration_unchanged'], 'original_configuration_changed');
                ensure($result['baseline']['counts_restored'], 'baseline_counts_not_restored');
            }
        }
    }
    if ($privateResultPath !== null) {
        saveJson($privateResultPath, $result);
    }
    $public = publicProjection($command, $result);
    saveJson($dir . '/' . $command . '-' . gmdate('Ymd-His') . '-' . bin2hex(random_bytes(3)) . '.json', $public);
    echo json_encode($public, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n";
} catch (Throwable $error) {
    while (ob_get_level() > 0) { ob_end_clean(); }
    // Exception messages may contain SQL bindings. Return only our fixed code,
    // class and phase, never framework messages, payloads or stack traces.
    $code = $error instanceof RuntimeException && preg_match('/^[a-z_]+$/', $error->getMessage()) === 1
        ? $error->getMessage() : 'operation_failed';
    echo json_encode(['passed' => false, 'checks' => [['check' => $phase . '-completed', 'passed' => false]]]) . "\n";
    exit(1);
}
