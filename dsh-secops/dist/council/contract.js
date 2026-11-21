/**
 * 统一任务契约与 Adapter 层。
 *
 * 系统里有三种执行体：确定性代码工具（nuclei/semgrep/rabin2）、专项 agent、
 * 自研 worker。它们形态各异，但对外必须收敛成同一种东西——否则每加一个工具
 * 就要在下游到处加分支，三公的职责也就落不到实处。
 *
 * 契约固定四件事：干什么（direction+target）、谁批准（requestedBy）、
 * 花多少（estimatedCost）、产出归谁（claimId）。其余都是执行细节。
 */
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
export class AdapterRegistry {
    adapters = new Map();
    register(adapter) {
        this.adapters.set(adapter.kind, adapter);
    }
    resolve(kind) {
        return this.adapters.get(kind);
    }
    kinds() {
        return [...this.adapters.keys()];
    }
    describe() {
        return [...this.adapters.values()].map((a) => ({ kind: a.kind, describe: a.describe }));
    }
}
const HASH_CHUNK = 1024 * 1024;
/** 单个证据文件的哈希上限。超过就只记大小不记哈希，免得一个 40G 的 pcap 把派活卡死。 */
const MAX_HASH_BYTES = 256 * 1024 * 1024;
function sha256File(file, size) {
    if (size > MAX_HASH_BYTES)
        return `skipped:${size}`;
    const hash = createHash('sha256');
    const fd = fs.openSync(file, 'r');
    try {
        const buf = Buffer.allocUnsafe(HASH_CHUNK);
        let read = 0;
        // 分块读：证据里可能有很大的抓包或日志，一次性读进内存会直接 OOM。
        for (;;) {
            read = fs.readSync(fd, buf, 0, HASH_CHUNK, null);
            if (read <= 0)
                break;
            hash.update(buf.subarray(0, read));
        }
    }
    finally {
        fs.closeSync(fd);
    }
    return hash.digest('hex');
}
/**
 * 给证据目录做一份带哈希的清单。
 *
 * 这是「原始证据及哈希」的落点：事后要证明某份日志没被改过，只有内容哈希
 * 是可信的，mtime 谁都能改。清单本身也写进目录，随证据一起走。
 */
export function buildEvidenceManifest(dir) {
    const capturedAt = Date.now();
    const entries = [];
    const walk = (current, prefix) => {
        for (const name of fs.readdirSync(current).sort()) {
            const full = path.join(current, name);
            const rel = prefix === '' ? name : `${prefix}/${name}`;
            const stat = fs.statSync(full);
            if (stat.isDirectory()) {
                walk(full, rel);
                continue;
            }
            if (!stat.isFile())
                continue;
            entries.push({ path: rel, sha256: sha256File(full, stat.size), size: stat.size });
        }
    };
    try {
        walk(dir, '');
    }
    catch (error) {
        return { dir, entries, capturedAt, error: String(error) };
    }
    const manifest = { dir, entries, capturedAt };
    try {
        fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf8');
    }
    catch {
        /* 目录只读就只返回不落盘，不因为写不了清单而让整次派活失败 */
    }
    return manifest;
}
/** 清单的摘要，用于把「这批证据是哪一批」压成一个可比较的值。 */
export function manifestDigest(manifest) {
    const h = createHash('sha256');
    for (const e of manifest.entries)
        h.update(`${e.path}\u0000${e.sha256}\u0000${e.size}\u0000`);
    return h.digest('hex');
}
let sequence = 0;
/** 生成任务 id。带方向与序号，便于在证据目录里一眼看出是哪条。 */
export function nextTaskId(direction, kind) {
    sequence += 1;
    return `${direction}-${kind}-${sequence}-${Date.now().toString(36)}`;
}
