// nginx 日志统计分析 - Zig 版本
// 设计要点:
//  1. 输入统一 mmap: 无论文件多大(6G+)都只占虚拟地址空间, 物理页按需
//     缺页、用完即被内核回收, 不会 OOM; stdin 先转存匿名临时文件再映射
//  2. 按行零拷贝解析 (字段均为指向映射区的切片)
//  3. 自研开放寻址哈希表; 窗口模式下新 key 复制进分块 arena, 保证映射解除后不悬空
//  4. FNV1A-Pippip 哈希 (与 C 版同算法)
//  5. 请求表融合"次数 + 发送字节"(Slot.value2), 省掉一张 46 万键的大表和每行一次探测,
//     并避免同一请求 key 被重复 intern
//  6. 超 1G 走窗口模式: 每窗口 512MB, 解析完立即 munmap 归还物理页;
//     解析当前窗口前用 posix_fadvise/F_RDADVISE 异步预读下一窗口, 让磁盘 I/O 与解析重叠
//  7. 多线程并行解析 + 并行合并各字段表
//  8. top-100 采用小顶堆选择, 而非全量排序
//  兼容 macOS / Linux

const std = @import("std");
const builtin = @import("builtin");

const ca = std.heap.c_allocator;
const STDOUT: c_int = 1;
const STDERR: c_int = 2;

inline fn sysRead(fd: c_int, buf: []u8) usize {
    const n = std.c.read(fd, buf.ptr, buf.len);
    if (n <= 0) return 0;
    return @intCast(n);
}

inline fn sysWrite(fd: c_int, buf: []const u8) void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = std.c.write(fd, buf.ptr + off, buf.len - off);
        if (n <= 0) return;
        off += @intCast(n);
    }
}

// ==================== FNV1A-Pippip 哈希 ====================

inline fn readU64(p: [*]const u8) u64 {
    return std.mem.readInt(u64, @as(*const [8]u8, @ptrCast(p)), .little);
}

fn hashKey(s: []const u8) u32 {
    const len = s.len;
    if (len == 0) return 0;
    const p = s.ptr;
    const PRIME: u32 = 591798841;
    var h64: u64 = 14695981039346656037;
    if (len > 8) {
        const cycles = ((len - 1) >> 4) + 1;
        const ndhead = len - (cycles << 3);
        var i: usize = 0;
        while (i < cycles) : (i += 1) {
            h64 = (h64 ^ readU64(p + 8 * i)) *% PRIME;
            h64 = (h64 ^ readU64(p + 8 * i + ndhead)) *% PRIME;
        }
    } else {
        const sh: u6 = @intCast((8 - len) << 3);
        const raw = readU64(p);
        const padded = (raw << sh) >> sh;
        h64 = (h64 ^ padded) *% PRIME;
    }
    const h32: u32 = @truncate(h64 ^ (h64 >> 32));
    return h32 ^ (h32 >> 16);
}

// ==================== 哈希表 ====================

const Slot = struct {
    key_ptr: ?[*]const u8 = null,
    hcode: u32 = 0,
    key_len: u32 = 0, // 单行最长 MAXLINE(16MB), u32 足够; 槽位保持 32 字节
    value: u64 = 0,
    value2: u64 = 0, // 仅 HTTP请求表使用: 同一请求的发送字节数 (原独立流量表)
};

inline fn slotKey(s: Slot) []const u8 {
    return s.key_ptr.?[0..s.key_len];
}

const Table = struct {
    arr: []Slot = &.{},
    count: usize = 0,

    fn init(cap_pow2: usize) Table {
        return .{ .arr = allocSlots(cap_pow2), .count = 0 };
    }

    fn enlargeTo(self: *Table, newcap: usize) void {
        const newArr = allocSlots(newcap);
        const m = newcap - 1;
        for (self.arr) |s| {
            if (s.key_ptr == null) continue;
            var j = s.hcode & m;
            while (newArr[j].key_ptr != null) j = (j + 1) & m;
            newArr[j] = s;
        }
        ca.free(self.arr);
        self.arr = newArr;
    }

    fn enlarge(self: *Table) void {
        self.enlargeTo(self.arr.len * 2);
    }

    // 保证可容纳 need 个成员
    fn ensureCap(self: *Table, need: usize) void {
        var cap = self.arr.len;
        while (cap * 2 < need * 3) cap *= 2;
        if (cap > self.arr.len) self.enlargeTo(cap);
    }

    inline fn keyMatch(s: Slot, key: []const u8, hc: u32) bool {
        return s.hcode == hc and @as(usize, s.key_len) == key.len and
            std.mem.eql(u8, s.key_ptr.?[0..s.key_len], key);
    }

    fn incrH(self: *Table, key: []const u8, hc: u32, n: u64) void {
        if (self.arr.len * 2 < (self.count + 1) * 3) self.enlarge();
        const m = self.arr.len - 1;
        var h = hc & m;
        while (self.arr[h].key_ptr != null) {
            if (keyMatch(self.arr[h], key, hc)) {
                self.arr[h].value += n;
                return;
            }
            h = (h + 1) & m;
        }
        self.arr[h] = .{ .key_ptr = key.ptr, .key_len = @intCast(key.len), .hcode = hc, .value = n };
        self.count += 1;
    }

    inline fn incr(self: *Table, key: []const u8, n: u64) void {
        self.incrH(key, hashKey(key), n);
    }

    // 同 incrH, 但新键的 key 复制到持久化 arena (缓冲区会被复用/解除映射的场景)
    fn incrHInterned(self: *Table, arena: *KeyArena, key: []const u8, hc: u32, n: u64) void {
        if (self.arr.len * 2 < (self.count + 1) * 3) self.enlarge();
        const m = self.arr.len - 1;
        var h = hc & m;
        while (self.arr[h].key_ptr != null) {
            if (Table.keyMatch(self.arr[h], key, hc)) {
                self.arr[h].value += n;
                return;
            }
            h = (h + 1) & m;
        }
        self.arr[h] = .{ .key_ptr = arena.intern(key), .key_len = @intCast(key.len), .hcode = hc, .value = n };
        self.count += 1;
    }

    // 融合插入 (整文件模式): 同一请求行同时累计 次数(value) 与 发送字节(value2)
    fn incrH2(self: *Table, key: []const u8, hc: u32, n1: u64, n2: u64) void {
        if (self.arr.len * 2 < (self.count + 1) * 3) self.enlarge();
        const m = self.arr.len - 1;
        var h = hc & m;
        while (self.arr[h].key_ptr != null) {
            if (keyMatch(self.arr[h], key, hc)) {
                self.arr[h].value += n1;
                self.arr[h].value2 += n2;
                return;
            }
            h = (h + 1) & m;
        }
        self.arr[h] = .{ .key_ptr = key.ptr, .key_len = @intCast(key.len), .hcode = hc, .value = n1, .value2 = n2 };
        self.count += 1;
    }

    // 融合插入 (窗口模式, key 需 intern)
    fn incrH2Interned(self: *Table, arena: *KeyArena, key: []const u8, hc: u32, n1: u64, n2: u64) void {
        if (self.arr.len * 2 < (self.count + 1) * 3) self.enlarge();
        const m = self.arr.len - 1;
        var h = hc & m;
        while (self.arr[h].key_ptr != null) {
            if (Table.keyMatch(self.arr[h], key, hc)) {
                self.arr[h].value += n1;
                self.arr[h].value2 += n2;
                return;
            }
            h = (h + 1) & m;
        }
        self.arr[h] = .{ .key_ptr = arena.intern(key), .key_len = @intCast(key.len), .hcode = hc, .value = n1, .value2 = n2 };
        self.count += 1;
    }

    // 合并: 将一个已有的 slot 插入 (复用其 hcode)
    fn insertSlot(self: *Table, s: Slot) void {
        const key = slotKey(s);
        const m = self.arr.len - 1;
        var h = s.hcode & m;
        while (self.arr[h].key_ptr != null) {
            if (keyMatch(self.arr[h], key, s.hcode)) {
                self.arr[h].value += s.value;
                self.arr[h].value2 += s.value2;
                return;
            }
            h = (h + 1) & m;
        }
        self.arr[h] = s;
        self.count += 1;
    }
};

// calloc: 大块走 mmap 时直接得到已清零页, 免去显式 memset 的全量触碰
fn allocSlots(n: usize) []Slot {
    const raw = std.c.calloc(n, @sizeOf(Slot)) orelse @panic("out of memory");
    const p: [*]Slot = @ptrCast(@alignCast(raw));
    return p[0..n];
}

// ==================== 数字格式化 ====================

// 将 v 的十进制写入 tb[20-n..20], 返回 n
fn u64ToBuf(v: u64, tb: *[20]u8) usize {
    if (v == 0) {
        tb[19] = '0';
        return 1;
    }
    var x = v;
    var n: usize = 0;
    while (x > 0) {
        n += 1;
        tb[20 - n] = '0' + @as(u8, @intCast(x % 10));
        x /= 10;
    }
    return n;
}

// ==================== 行解析 ====================

const Fields = struct {
    remote_addr: []const u8 = &.{},
    remote_user: []const u8 = &.{},
    time_local: []const u8 = &.{},
    request_line: []const u8 = &.{},
    status_code: []const u8 = &.{},
    referer: []const u8 = &.{},
    ua: []const u8 = &.{},
    xff: []const u8 = &.{},
    body_bytes: u64 = 0,
};

inline fn skipSpaces(line: []const u8, i: *usize) void {
    const n = line.len;
    while (i.* < n and line[i.*] == ' ') i.* += 1;
}

inline fn readUntilSpace(line: []const u8, i: *usize) ?[]const u8 {
    skipSpaces(line, i);
    const start = i.*;
    const n = line.len;
    while (i.* < n and line[i.*] != ' ') i.* += 1;
    if (i.* == start) return null;
    return line[start..i.*];
}

inline fn readWrap(line: []const u8, i: *usize, left: u8, right: u8) ?[]const u8 {
    skipSpaces(line, i);
    if (i.* >= line.len or line[i.*] != left) return null;
    i.* += 1;
    const start = i.*;
    const j = std.mem.findScalarPos(u8, line, i.*, right) orelse return null;
    i.* = j + 1;
    return line[start..j];
}

fn parseDigits(s: []const u8) u64 {
    var v: u64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') break;
        v = v * 10 + (c - '0');
    }
    return v;
}

// 解析一行 (不含结尾换行), 成功返回 true 并填充 f
fn parseLine(line: []const u8, f: *Fields) bool {
    var i: usize = 0;
    const n = line.len;

    f.remote_addr = readUntilSpace(line, &i) orelse return false;

    // remote_user: 跳过前导 '-' (nginx 固定的 ident 字段), 再读取
    skipSpaces(line, &i);
    while (i < n and line[i] == '-') i += 1;
    f.remote_user = readUntilSpace(line, &i) orelse return false;

    f.time_local = readWrap(line, &i, '[', ']') orelse return false;
    f.request_line = readWrap(line, &i, '"', '"') orelse return false;

    f.status_code = readUntilSpace(line, &i) orelse return false;
    if (f.status_code.len != 3) return false;

    const bytes = readUntilSpace(line, &i) orelse return false;
    f.body_bytes = parseDigits(bytes);

    f.referer = readWrap(line, &i, '"', '"') orelse return false;
    f.ua = readWrap(line, &i, '"', '"') orelse return false;
    f.xff = readWrap(line, &i, '"', '"') orelse return false;
    return true;
}

// ==================== 工作区 ====================

const F_REMOTE_ADDR = 0;
const F_REMOTE_USER = 1;
const F_TIME_LOCAL = 2;
const F_REQUEST = 3;
const F_STATUS = 4;
const F_REFERER = 5;
const F_UA = 6;
const F_XFF = 7;
// 流量统计不再独立建表: 复用 F_REQUEST 的槽位 value2, 省一张 46 万键的大表 + 每行一次探测
const NFIELDS = 8;

const Span = struct { start: usize, end: usize };

const Workspace = struct {
    tables: [NFIELDS]Table = undefined,
    bad: [1000]?Table = .{null} ** 1000,
    total_lines: u64 = 0,
    total_bytes: u64 = 0,
    buf: []const u8 = &.{},
    span: Span = .{ .start = 0, .end = 0 },
    intern_mode: bool = false, // 窗口模式: key 必须复制到 arena (缓冲区会被复用/解除映射)
    arena: KeyArena = .{},

    fn init(buf: []const u8, span: Span) Workspace {
        var w: Workspace = .{ .buf = buf, .span = span };
        for (&w.tables) |*t| t.* = Table.init(64);
        return w;
    }

    // 插入字段计数 (intern_mode 时把 key 复制到持久化 arena)
    inline fn put(self: *Workspace, fi: usize, key: []const u8, n: u64) void {
        self.putH(fi, key, hashKey(key), n);
    }

    inline fn putH(self: *Workspace, fi: usize, key: []const u8, hc: u32, n: u64) void {
        if (self.intern_mode) {
            self.tables[fi].incrHInterned(&self.arena, key, hc, n);
        } else {
            self.tables[fi].incrH(key, hc, n);
        }
    }

    // 请求表融合插入: 一次探测同时累计 次数(value) 与 发送字节(value2)
    inline fn putRequest(self: *Workspace, key: []const u8, hc: u32, bb: u64) void {
        if (self.intern_mode) {
            self.tables[F_REQUEST].incrH2Interned(&self.arena, key, hc, 1, bb);
        } else {
            self.tables[F_REQUEST].incrH2(key, hc, 1, bb);
        }
    }

    // 非 200 状态码: 单独按状态码建表
    inline fn putBad(self: *Workspace, code: usize, key: []const u8, hc: u32) void {
        if (self.bad[code] == null) self.bad[code] = Table.init(1024);
        if (self.intern_mode) {
            self.bad[code].?.incrHInterned(&self.arena, key, hc, 1);
        } else {
            self.bad[code].?.incrH(key, hc, 1);
        }
    }
};

fn tableAt(w: *Workspace, kind: u8, idx: u32) ?*Table {
    if (kind == 0) return &w.tables[idx];
    if (w.bad[idx]) |*t| return t;
    return null;
}

fn processSpan(w: *Workspace) void {
    const buf = w.buf;
    var i = w.span.start;
    const end = w.span.end;
    var f: Fields = undefined;
    while (i < end) {
        const j = std.mem.findScalarPos(u8, buf, i, '\n') orelse end;
        const line = buf[i..j];
        i = j + 1;
        if (parseLine(line, &f)) {
            w.total_lines += 1;
            const bb = f.body_bytes;
            w.total_bytes += bb;
            w.put(F_REMOTE_ADDR, f.remote_addr, 1);
            w.put(F_REMOTE_USER, f.remote_user, 1);
            w.put(F_TIME_LOCAL, f.time_local, 1);
            const rhc = hashKey(f.request_line);
            w.putRequest(f.request_line, rhc, bb);
            w.put(F_STATUS, f.status_code, 1);
            w.put(F_REFERER, f.referer, 1);
            w.put(F_UA, f.ua, 1);
            w.put(F_XFF, f.xff, 1);
            if (f.status_code[0] != '2' or f.status_code[1] != '0' or
                f.status_code[2] != '0')
            {
                const code = parseDigits(f.status_code);
                if (code < 1000) w.putBad(code, f.request_line, rhc);
            }
        } else {
            sysWrite(STDERR, line);
            sysWrite(STDERR, "\n");
        }
    }
}

// ==================== 输出 ====================

const pad_spaces: [256]u8 = .{' '} ** 256;

const Out = struct {
    buf: [32768]u8 = undefined,
    pos: usize = 0,

    fn flush(self: *Out) void {
        if (self.pos > 0) {
            sysWrite(STDOUT, self.buf[0..self.pos]);
            self.pos = 0;
        }
    }

    fn write(self: *Out, s: []const u8) void {
        if (self.pos + s.len > self.buf.len) self.flush();
        if (s.len > self.buf.len) {
            sysWrite(STDOUT, s);
            return;
        }
        @memcpy(self.buf[self.pos..][0..s.len], s);
        self.pos += s.len;
    }

    fn byte(self: *Out, c: u8) void {
        if (self.pos >= self.buf.len) self.flush();
        self.buf[self.pos] = c;
        self.pos += 1;
    }

    fn pad(self: *Out, k: usize) void {
        var rem = k;
        while (rem > 0) {
            const c = if (rem <= pad_spaces.len) rem else pad_spaces.len;
            self.write(pad_spaces[0..c]);
            rem -= c;
        }
    }

    fn u64d(self: *Out, v: u64) void {
        var tb: [20]u8 = undefined;
        const n = u64ToBuf(v, &tb);
        self.write(tb[20 - n .. 20]);
    }

    // 右对齐数字, 宽度 w (等同 %6d)
    fn numW(self: *Out, v: u64, w: usize) void {
        var tb: [20]u8 = undefined;
        const n = u64ToBuf(v, &tb);
        if (w > n) self.pad(w - n);
        self.write(tb[20 - n .. 20]);
    }

    // 左对齐, 最小宽度 w, 最多 maxc 个字符 (等同 %-N.*s)
    fn field(self: *Out, s: []const u8, w: usize, maxc: usize) void {
        const n = if (s.len <= maxc) s.len else maxc;
        self.write(s[0..n]);
        if (w > n) self.pad(w - n);
    }

    // 浮点数四舍五入到 2 位小数 (与 printf %.2f 的舍入一致, 严格按 f64 精确值进行 half-even)
    fn round2(d: f64) u64 {
        const bits = @as(u64, @bitCast(d));
        const exp = (bits >> 52) & 0x7FF;
        const mant = bits & 0xFFFFFFFFFFFFF;
        const m: u128 = if (exp == 0) mant else (mant | (@as(u64, 1) << 52));
        const e: i32 = if (exp == 0) -1074 else (@as(i32, @intCast(exp)) - 1023 - 52);
        const M: u128 = m * 100;
        if (e >= 0) return @intCast(M << @as(u7, @intCast(e)));
        const shift: u7 = @intCast(-e);
        const q = M >> shift;
        const r = M & ((@as(u128, 1) << shift) - 1);
        const half = @as(u128, 1) << (shift - 1);
        if (r > half) return @intCast(q + 1);
        if (r == half) return @intCast(q + (q & 1));
        return @intCast(q);
    }

    // 打印 N/100 的两位小数形式 (N = 值x100)
    fn writeScaled(self: *Out, N: u64) void {
        self.u64d(N / 100);
        self.byte('.');
        const frac = N % 100;
        self.byte('0' + @as(u8, @intCast(frac / 10)));
        self.byte('0' + @as(u8, @intCast(frac % 10)));
    }

    // num/denom*100, 保留两位小数
    fn pct(self: *Out, num: u64, denom: u64) void {
        if (denom == 0) {
            self.write("0.00");
            return;
        }
        const d = @as(f64, @floatFromInt(num)) / @as(f64, @floatFromInt(denom)) * 100.0;
        self.writeScaled(round2(d));
    }

    // (num*100)/denom, 保留两位小数
    fn pctMul100(self: *Out, num: u64, denom: u64) void {
        if (denom == 0) {
            self.write("0.00");
            return;
        }
        const d = @as(f64, @floatFromInt(100 * num)) / @as(f64, @floatFromInt(denom));
        self.writeScaled(round2(d));
    }
};

// 字节数格式化, 写入 buf, 返回长度 (等同 C 版 byteFormat + sprintf %.2f %cB)
fn byteFormatToBuf(buf: *[64]u8, pos: *usize, v: u64) void {
    if (v < 1024) {
        var tb: [20]u8 = undefined;
        const n = u64ToBuf(v, &tb);
        @memcpy(buf.*[pos.* .. pos.* + n], tb[20 - n .. 20]);
        pos.* += n;
        buf.*[pos.*] = ' ';
        pos.* += 1;
        buf.*[pos.*] = 'B';
        pos.* += 1;
        return;
    }
    var n: f64 = @floatFromInt(v);
    const units = "KMGTPEZY";
    var u: usize = 0;
    while (n >= 1024) {
        n /= 1024;
        u += 1;
    }
    const N: u64 = round2f(n);
    {
        var tb: [20]u8 = undefined;
        const ln = u64ToBuf(N / 100, &tb);
        @memcpy(buf.*[pos.* .. pos.* + ln], tb[20 - ln .. 20]);
        pos.* += ln;
    }
    buf.*[pos.*] = '.';
    pos.* += 1;
    const frac = N % 100;
    buf.*[pos.*] = '0' + @as(u8, @intCast(frac / 10));
    pos.* += 1;
    buf.*[pos.*] = '0' + @as(u8, @intCast(frac % 10));
    pos.* += 1;
    buf.*[pos.*] = ' ';
    pos.* += 1;
    buf.*[pos.*] = units[u - 1]; // C 版 unit-- 起始, 每次除法后 unit++, 故 K 对应 1 次除法
    pos.* += 1;
    buf.*[pos.*] = 'B';
    pos.* += 1;
}

fn round2f(d: f64) u64 {
    const bits = @as(u64, @bitCast(d));
    const exp = (bits >> 52) & 0x7FF;
    const mant = bits & 0xFFFFFFFFFFFFF;
    const m: u128 = if (exp == 0) mant else (mant | (@as(u64, 1) << 52));
    const e: i32 = if (exp == 0) -1074 else (@as(i32, @intCast(exp)) - 1023 - 52);
    const M: u128 = m * 100;
    if (e >= 0) return @intCast(M << @as(u7, @intCast(e)));
    const shift: u7 = @intCast(-e);
    const q = M >> shift;
    const r = M & ((@as(u128, 1) << shift) - 1);
    const half = @as(u128, 1) << (shift - 1);
    if (r > half) return @intCast(q + 1);
    if (r == half) return @intCast(q + (q & 1));
    return @intCast(q);
}

// ==================== top-K 选择 ====================

const K = 100;

fn siftUp(comptime field: []const u8, heap: *[K]Slot, i: usize) void {
    var c = i;
    while (c > 0) {
        const p = (c - 1) / 2;
        if (@field(heap[c], field) < @field(heap[p], field)) {
            const t = heap[c];
            heap[c] = heap[p];
            heap[p] = t;
            c = p;
        } else break;
    }
}

fn siftDown(comptime field: []const u8, heap: *[K]Slot, size: usize, i: usize) void {
    var c = i;
    while (true) {
        const l = 2 * c + 1;
        const r = 2 * c + 2;
        var sml = c;
        if (l < size and @field(heap[l], field) < @field(heap[sml], field)) sml = l;
        if (r < size and @field(heap[r], field) < @field(heap[sml], field)) sml = r;
        if (sml == c) break;
        const t = heap[c];
        heap[c] = heap[sml];
        heap[sml] = t;
        c = sml;
    }
}

fn LessDesc(comptime field: []const u8) type {
    return struct {
        fn less(_: void, a: Slot, b: Slot) bool {
            return @field(a, field) > @field(b, field);
        }
    };
}

// 选出指定字段最大的 K 项并降序排序 (field 为 "value" 或 "value2")
fn topK(comptime field: []const u8, t: *const Table, heap: *[K]Slot) usize {
    var hs: usize = 0;
    for (t.arr) |s| {
        if (s.key_ptr == null) continue;
        if (hs < K) {
            heap[hs] = s;
            hs += 1;
            siftUp(field, heap, hs - 1);
        } else if (@field(s, field) > @field(heap[0], field)) {
            heap[0] = s;
            siftDown(field, heap, hs, 0);
        }
    }
    if (hs > 1) std.sort.block(Slot, heap[0..hs], {}, LessDesc(field).less);
    return hs;
}

// ==================== 统计打印 ====================

const Width = struct {
    tw: usize, // 统计表 key 列宽
    tp: usize, // 统计表 key 最大字符数
    sw: usize, // 流量表 key 列宽
    sp: usize, // 流量表 key 最大字符数
};

fn getTerminalWidth() u16 {
    var ws: std.posix.winsize = .{ .row = 0, .col = 0, .xpixel = 0, .ypixel = 0 };
    const fds = [_]c_int{ 0, 1, 2 };
    for (fds) |fd| {
        const r = std.c.ioctl(fd, @as(c_int, @intCast(std.c.T.IOCGWINSZ)), @as(*anyopaque, @ptrCast(&ws)));
        if (r != -1) return ws.col;
    }
    return 0;
}

fn makeWidth(col: u16) Width {
    const ws: usize = col;
    if (ws >= 23) {
        return .{ .tw = ws - 16, .tp = ws - 16, .sw = ws - 22, .sp = ws - 22 };
    }
    if (ws >= 17) {
        return .{ .tw = ws - 16, .tp = ws - 16, .sw = 22, .sp = std.math.maxInt(usize) };
    }
    // 输出重定向时 C 版的 %d 溢出技巧最终等价于: 宽度 16/22, 不截断
    return .{ .tw = 16, .tp = std.math.maxInt(usize), .sw = 22, .sp = std.math.maxInt(usize) };
}

// 写入 "a/b" 形式
fn writeFraction(buf: *[64]u8, pos: *usize, a: u64, b: u64) void {
    var tb: [20]u8 = undefined;
    const la = u64ToBuf(a, &tb);
    @memcpy(buf.*[pos.* .. pos.* + la], tb[20 - la .. 20]);
    pos.* += la;
    buf.*[pos.*] = '/';
    pos.* += 1;
    const lb = u64ToBuf(b, &tb);
    @memcpy(buf.*[pos.* .. pos.* + lb], tb[20 - lb .. 20]);
    pos.* += lb;
}

fn printStat(out: *Out, name: []const u8, t: *const Table, denom: u64, w: Width) void {
    out.write("\n\x1b[1;34m");
    out.write(name);
    out.write("\x1b[00m\n");

    var heap: [K]Slot = undefined;
    const cnt = topK("value", t, &heap);
    var n: u64 = 0;
    for (heap[0..cnt]) |s| {
        out.field(slotKey(s), w.tw, w.tp);
        out.write(" ");
        out.numW(s.value, 6);
        out.write(" ");
        out.pct(s.value, denom);
        out.write("%\n");
        n += s.value;
    }

    var tmp: [64]u8 = undefined;
    var pos: usize = 0;
    writeFraction(&tmp, &pos, n, denom);

    out.write("前");
    out.u64d(K);
    out.write("项占比\n");
    out.field(tmp[0..pos], w.tw, w.tp);
    out.write(" ");
    out.numW(t.count, 6);
    out.write(" ");
    out.pct(n, denom);
    out.write("%\n\n");
}

fn printSent(out: *Out, name: []const u8, t: *const Table, total_bytes: u64, w: Width) void {
    out.write("\n\x1b[1;34m");
    out.write(name);
    out.write("\x1b[00m\n");

    var heap: [K]Slot = undefined;
    const cnt = topK("value2", t, &heap); // 融合表: 按发送字节数排序
    var n: u64 = 0;
    for (heap[0..cnt]) |s| {
        out.field(slotKey(s), w.sw, w.sp);
        out.write(" ");
        var tb: [64]u8 = undefined;
        var tp: usize = 0;
        byteFormatToBuf(&tb, &tp, s.value2);
        if (12 > tp) out.pad(12 - tp);
        out.write(tb[0..tp]);
        out.write(" ");
        out.pct(s.value2, total_bytes);
        out.write("%\n");
        n += s.value2;
    }

    var b1: [64]u8 = undefined;
    var b1l: usize = 0;
    byteFormatToBuf(&b1, &b1l, n);
    var b2: [64]u8 = undefined;
    var b2l: usize = 0;
    byteFormatToBuf(&b2, &b2l, total_bytes);

    var tmp: [160]u8 = undefined;
    var pos: usize = 0;
    @memcpy(tmp[pos .. pos + b1l], b1[0..b1l]);
    pos += b1l;
    tmp[pos] = '/';
    pos += 1;
    @memcpy(tmp[pos .. pos + b2l], b2[0..b2l]);
    pos += b2l;

    out.write("前");
    out.u64d(K);
    out.write("项占比\n");
    out.field(tmp[0..pos], w.sw, w.sp);
    out.write(" ");
    out.numW(t.count, 12);
    out.write(" ");
    out.pct(n, total_bytes);
    out.write("%\n\n");
}

fn printCode(out: *Out, code: u32, t: *const Table, total_lines: u64, w: Width) void {
    var total: u64 = 0;
    for (t.arr) |s| {
        if (s.key_ptr == null) continue;
        total += s.value;
    }
    out.write("\n\x1b[1;34m状态码");
    out.u64d(code);
    out.write(",共");
    out.u64d(total);
    out.write("次,占比");
    out.pctMul100(total, total_lines);
    out.write("%\x1b[00m\n");

    var heap: [K]Slot = undefined;
    const cnt = topK("value", t, &heap);
    var n: u64 = 0;
    for (heap[0..cnt]) |s| {
        out.field(slotKey(s), w.tw, w.tp);
        out.write(" ");
        out.numW(s.value, 6);
        out.write(" ");
        out.pct(s.value, total);
        out.write("%\n");
        n += s.value;
    }

    var tmp: [64]u8 = undefined;
    var pos: usize = 0;
    writeFraction(&tmp, &pos, n, total);

    out.write("前");
    out.u64d(K);
    out.write("项占比\n");
    out.field(tmp[0..pos], w.tw, w.tp);
    out.write(" ");
    out.numW(t.count, 6);
    out.write(" ");
    out.pct(n, total);
    out.write("%\n\n");
}

// ==================== 合并 ====================

const Task = struct { kind: u8, idx: u32 };

fn mergeTask(ws: []*Workspace, kind: u8, idx: u32) void {
    var maxi: usize = 0;
    var maxc: usize = 0;
    var total: usize = 0;
    for (ws, 0..) |w, k| {
        const t = tableAt(w, kind, idx);
        if (t == null) continue;
        total += t.?.count;
        if (t.?.count > maxc) {
            maxc = t.?.count;
            maxi = k;
        }
    }
    if (total == 0) return;
    const dst = tableAt(ws[maxi], kind, idx).?;
    dst.ensureCap(total);
    for (ws, 0..) |w, k| {
        if (k == maxi) continue;
        const t = tableAt(w, kind, idx) orelse continue;
        for (t.arr) |s| {
            if (s.key_ptr == null) continue;
            dst.insertSlot(s);
        }
    }
}

fn mergeWorker(ws: []*Workspace, tasks: []const Task, tid: usize, nthreads: usize) void {
    for (tasks, 0..) |t, k| {
        if (k % nthreads == tid) mergeTask(ws, t.kind, t.idx);
    }
}

// ==================== 主流程 ====================

const Result = struct {
    tables: [NFIELDS]Table = undefined,
    bad: [1000]?Table = .{null} ** 1000,
    total_lines: u64 = 0,
    total_bytes: u64 = 0,

    fn init() Result {
        var r: Result = .{};
        for (&r.tables) |*t| t.* = Table.init(64);
        return r;
    }
};

fn splitSpans(buf: []const u8, n: usize) []Span {
    const spans = ca.alloc(Span, n) catch unreachable;
    const total = buf.len;
    var start: usize = 0;
    for (0..n) |k| {
        var target = if (k == n - 1) total else total * (k + 1) / n;
        if (target > total) target = total;
        var e = target;
        if (e > start) {
            while (e < total and buf[e] != '\n') e += 1;
            if (e < total) e += 1; // 包含换行符
        } else {
            e = start;
        }
        spans[k] = .{ .start = start, .end = e };
        start = e;
    }
    spans[n - 1].end = total;
    return spans;
}

// 异步预读文件区间 (不阻塞): Linux 用 posix_fadvise, macOS 用 fcntl(F_RDADVISE)
// 目的: 当前窗口解析的同时让内核把下一窗口读进 page cache
fn adviseReadahead(fd: c_int, off: u64, len: u64) void {
    if (len == 0) return;
    switch (builtin.os.tag) {
        .linux => {
            _ = posix_fadvise(fd, @intCast(off), @intCast(len), POSIX_FADV_WILLNEED);
        },
        .macos => {
            var ra = Radvisory{ .offset = @intCast(off), .count = @intCast(@min(len, std.math.maxInt(i32))) };
            _ = std.c.fcntl(fd, F_RDADVISE, &ra);
        },
        else => {},
    }
}

const F_RDADVISE: c_int = 0x2c; // macOS fcntl 命令: 读预取
const POSIX_FADV_WILLNEED: c_int = 3; // Linux: 预读进 page cache
const Radvisory = extern struct { offset: i64, count: c_int };

// 仅在 Linux 分支被引用 (comptime switch 会裁剪), macOS 上不参与链接
extern "c" fn posix_fadvise(fd: c_int, offset: i64, len: i64, advice: c_int) c_int;

// 取文件大小 (lseek 方式, 跨 macOS/Linux; std.c.fstat 在 Linux 上不可用)
fn fileSize(fd: c_int) !u64 {
    const sz = std.c.lseek(fd, 0, 2); // SEEK_END
    if (sz < 0) return error.SeekFailed;
    _ = std.c.lseek(fd, 0, 0); // 复位
    return @intCast(sz);
}

// 映射 fd 的 [0, size) 区间, 并保证末尾至少 64 字节零填充 (哈希读取越界安全)
// 大文件只占用虚拟地址空间, 物理页由内核按需加载/回收
fn mapInput(fd: c_int, size: usize) ![]u8 {
    const ps = std.heap.page_size_min;
    const map_len = ((size + 64 + ps - 1) / ps) * ps;
    if (map_len == 0) {
        // 空输入: 返回一段零内存
        const buf = ca.alloc(u8, 64) catch unreachable;
        @memset(buf, 0);
        return buf;
    }
    const m = std.posix.mmap(null, map_len, .{ .READ = true }, .{ .TYPE = .PRIVATE }, fd, 0) catch {
        // mmap 失败时仅对小文件回退到堆读取, 避免大文件 OOM
        if (size > 2 * 1024 * 1024 * 1024) return error.UnsupportedMmap;
        const buf = ca.alloc(u8, size + 64) catch return error.OutOfMemory;
        var off: usize = 0;
        while (off < size) {
            const n = sysRead(fd, buf[off..size]);
            if (n == 0) break;
            off += n;
        }
        @memset(buf[off .. off + 64], 0);
        return buf[0 .. off + 64];
    };
    // 顺序只读: 提示内核已读页可立即回收, 6G+ 文件也不会撑爆物理内存
    std.posix.madvise(m.ptr, map_len, std.posix.MADV.SEQUENTIAL) catch {};
    return m[0 .. size + 64];
}

// 把 stdin 流式写入一个立即删除的临时文件 (匿名 inode), 返回其 fd
// 目录优先级: TMPDIR/TMP → /var/tmp → /tmp
// 优先 /var/tmp: Linux 上 /tmp 常被挂成 tmpfs(内存), 转存数 GB 日志会撑爆内存/ENOSPC
fn spoolStdin() !c_int {
    var dirs: [4][]const u8 = undefined;
    var nd: usize = 0;
    const env_names = [_][*:0]const u8{ "TMPDIR", "TMP" };
    for (env_names) |v| {
        if (std.c.getenv(v)) |val| {
            const s = std.mem.span(val);
            if (s.len > 0) {
                dirs[nd] = s;
                nd += 1;
            }
        }
    }
    dirs[nd] = "/var/tmp";
    nd += 1;
    dirs[nd] = "/tmp";
    nd += 1;

    var path_buf: [320]u8 = undefined;
    var name_buf: [32]u8 = undefined;
    var seed: u64 = @intFromPtr(&path_buf) ^ 0x9E3779B97F4A7C15;
    // 逐个目录尝试; 同一目录内换随机名重试(防并发冲突)
    for (dirs[0..nd]) |dir| {
        var attempt: u32 = 0;
        while (attempt < 64) : (attempt += 1) {
            seed = seed *% 6364136223846793005 +% 1442695040888963407;
            const name = std.fmt.bufPrint(&name_buf, "{x}", .{seed}) catch break;
            const plen = std.fmt.bufPrint(&path_buf, "{s}/ngx_zig.{s}", .{ dir, name }) catch break;
            path_buf[plen.len] = 0;
            const path: [*:0]const u8 = @ptrCast(path_buf[0..plen.len :0].ptr);
            const fd = std.c.open(path, .{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true }, @as(c_uint, 0o600));
            if (fd < 0) continue; // 目录不可用或名字冲突, 重试/换目录
            // 立即删除: 映射建立后仍有效, 进程退出自动归还磁盘空间
            _ = std.c.unlink(path);
            var tmp: [1 << 20]u8 = undefined;
            while (true) {
                const n = sysRead(0, &tmp);
                if (n == 0) break;
                var off: usize = 0;
                while (off < n) {
                    const w = std.c.write(fd, tmp[off..].ptr, n - off);
                    if (w <= 0) return error.WriteFailed;
                    off += @intCast(w);
                }
            }
            return fd;
        }
    }
    return error.TmpFileBusy;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var args = std.process.Args.Iterator.init(init.args);
    _ = args.next();
    const path = args.next();

    // ---------- 读取输入 ----------
    // 统一以 mmap 方式获取数据: 无论文件多大(6G+)都只占用虚拟地址空间,
    // 物理页按需缺页、用完即被内核回收, 不会 OOM
    var fd: c_int = -1;
    var size: u64 = 0;
    if (path) |p| {
        fd = std.c.open(p.ptr, .{ .ACCMODE = .RDONLY }, @as(c_uint, 0));
        if (fd < 0) {
            sysWrite(STDERR, "cannot open file: ");
            sysWrite(STDERR, p);
            sysWrite(STDERR, "\n");
            return;
        }
        size = fileSize(fd) catch {
            sysWrite(STDERR, "cannot stat file\n");
            _ = std.c.close(fd);
            return;
        };
    } else {
        // stdin: 流式转存到匿名临时文件, 再按窗口映射, 避免大数据撑爆堆内存
        fd = spoolStdin() catch {
            sysWrite(STDERR, "cannot create tmpfile for stdin\n");
            return;
        };
        size = fileSize(fd) catch {
            sysWrite(STDERR, "cannot stat tmpfile\n");
            return;
        };
    }

    var result = Result.init();
    var total_lines: u64 = 0;
    var total_bytes: u64 = 0;

    if (size <= WINDOW_THRESHOLD) {
        // 整文件 mmap 快速路径
        const data = mapInput(fd, size) catch |err| {
            if (err == error.UnsupportedMmap) {
                sysWrite(STDERR, "mmap unsupported for this file, use a regular file\n");
            } else {
                sysWrite(STDERR, "mmap failed\n");
            }
            _ = std.c.close(fd);
            return;
        };
        _ = std.c.close(fd);
        parseWhole(data, &result, &total_lines, &total_bytes);
    } else {
        // 窗口式 mmap: 超大文件每次只驻留一个窗口, 解析完立即归还物理页
        runWindowed(fd, size, &result, &total_lines, &total_bytes);
        _ = std.c.close(fd);
    }

    // ---------- 输出 ----------
    var out = Out{};
    const col = getTerminalWidth();
    const w = makeWidth(col);

    {
        var tb: [64]u8 = undefined;
        var tp: usize = 0;
        byteFormatToBuf(&tb, &tp, total_bytes);
        out.write("\n共计\x1b[1;34m");
        out.u64d(total_lines);
        out.write("\x1b[00m次访问\n发送总流量\x1b[1;32m");
        out.write(tb[0..tp]);
        out.write("\x1b[00m\n独立IP数\x1b[1;31m");
        out.u64d(result.tables[F_REMOTE_ADDR].count);
        out.write("\x1b[00m\n");
    }

    if (total_lines > 0) {
        printStat(&out, "来访IP统计", &result.tables[F_REMOTE_ADDR], total_lines, w);
        printStat(&out, "用户统计", &result.tables[F_REMOTE_USER], total_lines, w);
        printStat(&out, "代理IP统计", &result.tables[F_XFF], total_lines, w);
        printStat(&out, "HTTP请求统计", &result.tables[F_REQUEST], total_lines, w);
        printStat(&out, "User-Agent统计", &result.tables[F_UA], total_lines, w);
        printStat(&out, "HTTP REFERER 统计", &result.tables[F_REFERER], total_lines, w);
        printStat(&out, "请求时间统计", &result.tables[F_TIME_LOCAL], total_lines, w);
        printStat(&out, "HTTP响应状态统计", &result.tables[F_STATUS], total_lines, w);
        printSent(&out, "HTTP流量占比统计", &result.tables[F_REQUEST], total_bytes, w);
        for (0..1000) |c| {
            if (result.bad[c]) |*t| printCode(&out, @intCast(c), t, total_lines, w);
        }
    }
    out.flush();
}

// ==================== 解析执行 ====================

const WINDOW_THRESHOLD: u64 = 1 * 1024 * 1024 * 1024; // 超过 1G 走窗口模式
const WINDOW_SIZE: usize = 512 * 1024 * 1024; // 每窗口 512MB
const MAXLINE: usize = 16 * 1024 * 1024; // 单行最大容忍长度

// 整文件快速路径: 一次性 mmap, 多线程并行解析 + 并行合并
fn parseWhole(data: []const u8, result: *Result, total_lines: *u64, total_bytes: *u64) void {
    var nthreads: usize = 1;
    if (data.len > 2 * 1024 * 1024) {
        nthreads = std.Thread.getCpuCount() catch 1;
        if (nthreads < 1) nthreads = 1;
        if (nthreads > 16) nthreads = 16;
    }
    const parse_len = if (data.len >= 64) data.len - 64 else 0;

    if (nthreads == 1) {
        var ws = Workspace.init(data, .{ .start = 0, .end = parse_len });
        processSpan(&ws);
        result.tables = ws.tables;
        result.bad = ws.bad;
        total_lines.* = ws.total_lines;
        total_bytes.* = ws.total_bytes;
    } else {
        const spans = splitSpans(data[0..parse_len], nthreads);
        const workspaces = ca.alloc(Workspace, nthreads) catch unreachable;
        for (0..nthreads) |k| {
            workspaces[k] = Workspace.init(data, spans[k]);
        }
        const ws_ptrs = ca.alloc(*Workspace, nthreads) catch unreachable;
        for (0..nthreads) |k| ws_ptrs[k] = &workspaces[k];

        var threads = ca.alloc(std.Thread, nthreads) catch unreachable;
        var spawned: usize = 0;
        while (spawned < nthreads) {
            threads[spawned] = std.Thread.spawn(.{}, processSpan, .{&workspaces[spawned]}) catch {
                // 线程创建失败则由本线程直接解析剩余部分
                for (spawned..nthreads) |i| processSpan(&workspaces[i]);
                break;
            };
            spawned += 1;
        }
        for (0..spawned) |k| threads[k].join();

        finalMerge(ws_ptrs, nthreads, result, total_lines, total_bytes);
    }
}

// 窗口式处理: 每次只映射 WINDOW_SIZE 字节, 解析完立即 MADV_DONTNEED 归还物理页
// 内存占用恒定 (一个窗口 + 结果表), 不随文件大小增长, 6G+ 也不会 OOM
fn runWindowed(fd: c_int, size: u64, result: *Result, total_lines: *u64, total_bytes: *u64) void {
    const ps = std.heap.page_size_min;
    var nthreads: usize = std.Thread.getCpuCount() catch 1;
    if (nthreads < 1) nthreads = 1;
    if (nthreads > 16) nthreads = 16;

    // 工作区表跨窗口累积, 全程只扩容一次; key 在解析时即 intern 到持久化 arena
    const workspaces = ca.alloc(Workspace, nthreads) catch unreachable;
    for (0..nthreads) |k| {
        workspaces[k] = Workspace.init(&.{}, .{ .start = 0, .end = 0 });
        workspaces[k].intern_mode = true;
    }
    const ws_ptrs = ca.alloc(*Workspace, nthreads) catch unreachable;
    for (0..nthreads) |k| ws_ptrs[k] = &workspaces[k];
    const threads = ca.alloc(std.Thread, nthreads) catch unreachable;

    var pos: u64 = 0;
    while (pos < size) {
        const map_start: u64 = (pos / ps) * ps;
        const remain: u64 = size - map_start;
        // 本窗口映射覆盖的逻辑字节 (不含尾部 64 零填充)
        const want: u64 = if (remain > WINDOW_SIZE + MAXLINE) WINDOW_SIZE + MAXLINE else remain;
        const map_len: usize = @intCast(((want + 64 + ps - 1) / ps) * ps);
        const m = std.posix.mmap(null, map_len, .{ .READ = true }, .{ .TYPE = .PRIVATE }, fd, @intCast(map_start)) catch unreachable;
        const data = m[0 .. @intCast(want + 64)];

        // 异步预读下一窗口: 让磁盘 I/O 与本次解析重叠 (缓存命中时是零成本空操作)
        const next_off = map_start + want;
        if (next_off < size) {
            adviseReadahead(fd, next_off, @min(size - next_off, WINDOW_SIZE + MAXLINE));
        }

        // 在行边界处截断, 保证不切分日志行 (超长行强制截断)
        var logical_end: u64 = want;
        if (want > WINDOW_SIZE and map_start + want < size) {
            if (std.mem.findScalarPos(u8, data, WINDOW_SIZE, '\n')) |nl| {
                logical_end = nl + 1;
            }
        }
        const le: usize = @intCast(logical_end);
        // 跳过上一窗口已解析的页对齐重叠片段: pos 必在行边界, 从 pos 起解析既不漏行也不重解析
        const start_off: usize = @intCast(pos - map_start);
        const body = data[start_off..];
        const blen: usize = le - start_off;

        // 多线程并行解析本窗口 (工作区表持续累积, 不重置)
        const spans = splitSpans(body[0..blen], nthreads);
        for (0..nthreads) |k| {
            workspaces[k].buf = body;
            workspaces[k].span = spans[k];
        }
        var spawned: usize = 0;
        while (spawned < nthreads) {
            threads[spawned] = std.Thread.spawn(.{}, processSpan, .{&workspaces[spawned]}) catch {
                for (spawned..nthreads) |i| processSpan(&workspaces[i]);
                break;
            };
            spawned += 1;
        }
        for (0..spawned) |k| threads[k].join();

        // 立即解除本窗口映射: 物理页彻底释放, 内存占用恒定, 不随文件大小增长
        // (key 已全部 intern 到各工作区的持久化 arena, 不会成为悬空指针)
        std.posix.munmap(m);

        pos = map_start + logical_end;
    }

    // 全部窗口解析完毕, 最终一次性合并
    finalMerge(ws_ptrs, nthreads, result, total_lines, total_bytes);
}

// 各工作区表合并进结果: 整文件路径与窗口路径共用
fn finalMerge(ws_ptrs: []*Workspace, nthreads: usize, result: *Result, total_lines: *u64, total_bytes: *u64) void {
    // 收集需要合并的任务
    var tasks = std.ArrayList(Task).empty;
    for (0..NFIELDS) |fi| tasks.append(ca, .{ .kind = 0, .idx = @intCast(fi) }) catch unreachable;
    var active = [_]bool{false} ** 1000;
    for (ws_ptrs[0..nthreads]) |w| {
        for (w.bad, 0..) |b, c| if (b != null) {
            active[c] = true;
        };
    }
    for (0..1000) |c| if (active[c]) tasks.append(ca, .{ .kind = 1, .idx = @intCast(c) }) catch unreachable;

    // 并行合并
    const nt2 = if (tasks.items.len < nthreads) tasks.items.len else nthreads;
    if (nt2 > 1) {
        var mthreads = ca.alloc(std.Thread, nt2) catch unreachable;
        var mspawned: usize = 0;
        while (mspawned < nt2) {
            mthreads[mspawned] = std.Thread.spawn(.{}, mergeWorker, .{ ws_ptrs, tasks.items, mspawned, nt2 }) catch {
                for (mspawned..nt2) |i| mergeWorker(ws_ptrs, tasks.items, i, nt2);
                break;
            };
            mspawned += 1;
        }
        for (0..mspawned) |k| mthreads[k].join();
    } else {
        for (tasks.items) |t| mergeTask(ws_ptrs, t.kind, t.idx);
    }

    // 汇总结果
    for (ws_ptrs[0..nthreads]) |w| {
        total_lines.* += w.total_lines;
        total_bytes.* += w.total_bytes;
    }
    for (tasks.items) |t| {
        var maxi: usize = 0;
        var maxc: usize = 0;
        for (ws_ptrs[0..nthreads], 0..) |w, k| {
            const tb = tableAt(w, t.kind, t.idx) orelse continue;
            if (tb.count > maxc) {
                maxc = tb.count;
                maxi = k;
            }
        }
        if (t.kind == 0) {
            result.tables[t.idx] = ws_ptrs[maxi].tables[t.idx];
        } else {
            result.bad[t.idx] = ws_ptrs[maxi].bad[t.idx];
        }
    }
}

// 持久化 key 存储: 分块分配, 永不 realloc, 已返回的指针终身有效
const KeyArena = struct {
    chunks: std.ArrayList([]u8) = .empty,
    cur: []u8 = &.{},
    off: usize = 0,
    next_chunk: usize = 1 * 1024 * 1024, // 首块 1MB, 每次翻倍 (上限 64MB)
    const max_chunk: usize = 64 * 1024 * 1024;

    fn intern(self: *KeyArena, key: []const u8) [*]const u8 {
        if (self.off + key.len > self.cur.len) {
            const need: usize = if (key.len >= self.next_chunk) key.len + 4096 else self.next_chunk;
            self.cur = ca.alloc(u8, need) catch unreachable;
            self.off = 0;
            self.chunks.append(ca, self.cur) catch unreachable;
            if (self.next_chunk < max_chunk) {
                self.next_chunk = if (self.next_chunk * 2 > max_chunk) max_chunk else self.next_chunk * 2;
            }
        }
        const dst = self.cur[self.off .. self.off + key.len];
        @memcpy(dst, key);
        self.off += key.len;
        return dst.ptr;
    }
};

// 释放工作区的哈希槽位数组 (每窗口结束后调用, 内存不随窗口数累积)
fn freeWorkspaceSlots(w: *Workspace) void {
    for (&w.tables) |*t| {
        if (t.arr.len > 0) ca.free(t.arr);
        t.* = .{};
    }
    for (&w.bad) |*bt| {
        if (bt.*) |*t| {
            if (t.arr.len > 0) ca.free(t.arr);
            bt.* = null;
        }
    }
}
