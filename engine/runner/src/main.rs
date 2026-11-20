//! nai-run —— 进程监管器（Rust 执行层）
//!
//! ## 为什么需要它
//!
//! Python 侧原来的做法是 `subprocess.Popen` + `os.killpg`，实战中出了三类问题：
//!
//! 1. **`pkill -f` 自匹配**。用字符串匹配找进程，结果把自己的 shell 也匹配进去，
//!    六次把自己 SIGKILL 掉。字符串匹配根本不具备识别力。
//! 2. **孤儿进程占着内存不放**。浏览器主进程死了，它的一堆 contentproc 还在，
//!    合计 1.3GB，只能靠人工 `ps` 去找。`killpg` 杀的是进程组，而 setsid 出来的
//!    孙进程早就不在原组里了。
//! 3. **OOM 时无法归因**。两路 QEMU 各吃 2G，把机器压死，但事后说不清是谁吃的。
//!
//! 这三件事的共同解法是：**让内核记账，而不是靠字符串猜**。
//! - 用 **cgroup v2** 把一棵进程树圈在一起，内存/CPU/PID 限额由内核强制执行
//! - 靠 **cgroup.procs** 枚举真正的成员，不靠名字匹配
//! - 从 **memory.peak** 读峰值，而不是采样猜
//!
//! ## 关键取舍
//!
//! - **不依赖 PR_SET_PDEATHSIG**：它在 exec 之后会被清空，对长命令无效。
//!   真正可靠的是 cgroup——子进程即使 exec 过、setsid 过，只要还被放进 cgroup，
//!   就一定能被枚举出来杀掉。
//! - **不用 cgroup.kill**：本机内核（6.19）没编这个文件。退化为遍历 `cgroup.procs`
//!   逐个 SIGKILL，效果等价，代价是多几次系统调用。
//! - **只用 libc**：supervisor 要的是系统调用本身，不需要异步运行时。
//!   编译快、二进制小、出问题好定位。
//!
//! ## 用法
//!
//! ```text
//! nai-run --mem 1G --cpu 2 --pids 256 --timeout 900 --log out.log -- cmd args...
//! ```
//!
//! stdout 输出一行 JSON：退出码、信号、耗时、峰值内存、是否超时、清理了几个进程。

use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::{Duration, Instant};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

#[derive(Debug, Default)]
struct Opts {
    mem: Option<u64>,      // 字节
    cpu: Option<(u64, u64)>, // (quota_us, period_us)
    pids: Option<u64>,
    timeout: Duration,
    idle: Duration,   // 日志连续这么久没有新字节就判定卡死；0 表示不启用
    grace: Duration,
    cwd: Option<PathBuf>,
    log: Option<PathBuf>,
    cmd: Vec<String>,
}

fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('k') | Some('K') => (&s[..s.len() - 1], 1024u64),
        Some('m') | Some('M') => (&s[..s.len() - 1], 1024 * 1024),
        Some('g') | Some('G') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    num.parse::<u64>()
        .map(|n| n * mult)
        .map_err(|_| format!("无法解析容量 {s:?}"))
}

fn parse_args() -> Result<Opts, String> {
    let mut o = Opts {
        timeout: Duration::from_secs(900),
        idle: Duration::from_secs(0),
        grace: Duration::from_secs(10),
        ..Default::default()
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--mem" => { i += 1; o.mem = Some(parse_size(argv.get(i).ok_or("--mem 缺值")?)?); }
            "--cpu" => {
                i += 1;
                let v: f64 = argv.get(i).ok_or("--cpu 缺值")?.parse()
                    .map_err(|_| "--cpu 需要数字")?;
                // cgroup v2 的 cpu.max 形如 "200000 100000"（= 2 核）
                o.cpu = Some(((v * 100_000.0) as u64, 100_000));
            }
            "--pids" => { i += 1; o.pids = Some(argv.get(i).ok_or("--pids 缺值")?.parse().map_err(|_| "--pids 需要整数")?); }
            "--timeout" => { i += 1; o.timeout = Duration::from_secs(argv.get(i).ok_or("--timeout 缺值")?.parse().map_err(|_| "--timeout 需要秒数")?); }
            "--grace" => { i += 1; o.grace = Duration::from_secs(argv.get(i).ok_or("--grace 缺值")?.parse().map_err(|_| "--grace 需要秒数")?); }
            "--idle-timeout" => { i += 1; o.idle = Duration::from_secs(argv.get(i).ok_or("--idle-timeout 缺值")?.parse().map_err(|_| "--idle-timeout 需要秒数")?); }
            "--cwd" => { i += 1; o.cwd = Some(PathBuf::from(argv.get(i).ok_or("--cwd 缺值")?)); }
            "--log" => { i += 1; o.log = Some(PathBuf::from(argv.get(i).ok_or("--log 缺值")?)); }
            "--" => { o.cmd = argv[i + 1..].to_vec(); break; }
            other => return Err(format!("未知参数 {other}")),
        }
        i += 1;
    }
    if o.cmd.is_empty() {
        return Err("缺少要执行的命令（用 -- 分隔）".into());
    }
    Ok(o)
}

/// 建一个以本进程 pid 命名的 cgroup。失败返回 None —— 降级为"无限额但有超时"模式，
/// 而不是直接失败：限额是加固手段，不该成为跑不起来的原因。
fn setup_cgroup(name: &str, o: &Opts) -> Option<PathBuf> {
    // 父层要显式启用控制器，否则子 cgroup 里那几个限额文件根本不会出现。
    let _ = fs::write(format!("{CGROUP_ROOT}/cgroup.subtree_control"), "+memory +pids +cpu");
    let dir = PathBuf::from(CGROUP_ROOT).join(name);
    fs::create_dir_all(&dir).ok()?;

    if let Some(m) = o.mem {
        fs::write(dir.join("memory.max"), m.to_string()).ok()?;
        // 关掉 swap 记账差异：只关心内存，不希望被 swap 掩盖
        let _ = fs::write(dir.join("memory.swap.max"), "0");
    }
    if let Some((q, p)) = o.cpu {
        fs::write(dir.join("cpu.max"), format!("{q} {p}")).ok()?;
    }
    if let Some(n) = o.pids {
        fs::write(dir.join("pids.max"), n.to_string()).ok()?;
    }
    Some(dir)
}

/// 枚举 cgroup 里的所有 pid。这是"杀干净"的基础——不靠名字，靠内核记账。
fn cgroup_pids(dir: &Path) -> Vec<i32> {
    fs::read_to_string(dir.join("cgroup.procs"))
        .map(|s| s.lines().filter_map(|l| l.trim().parse().ok()).collect())
        .unwrap_or_default()
}

fn log_size(p: &Option<PathBuf>) -> u64 {
    p.as_ref()
        .and_then(|f| fs::metadata(f).ok())
        .map(|m| m.len())
        .unwrap_or(0)
}

fn read_u64(p: &Path) -> Option<u64> {
    fs::read_to_string(p).ok()?.trim().parse().ok()
}

fn main() {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("nai-run: {e}");
            eprintln!("用法: nai-run [--mem 1G] [--cpu 2] [--pids 256] [--timeout 900] [--cwd DIR] [--log FILE] -- CMD ...");
            exit(2)
        }
    };

    // 进程树必须归组：报告只包含"本次运行"的进程，不能把之前跑过的算进来。
    let cg_name = format!("nai-run-{}-{}", std::process::id(), Instant::now().elapsed().as_nanos());
    let cg = setup_cgroup(&cg_name, &opts);
    let limited = cg.is_some();

    let started = Instant::now();

    // 日志文件：先打开，再 fork，避免子进程重复打开
    let log_file = opts.log.as_ref().and_then(|p| {
        fs::File::create(p).ok()
    });
    let devnull = fs::File::open("/dev/null").ok();

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        eprintln!("nai-run: fork 失败");
        exit(3);
    }

    if pid == 0 {
        // ---- 子进程 ----
        unsafe {
            // 独立会话：这样它有自己的进程组，信号不会误伤别人
            libc::setsid();
        }
        if let Some(d) = &opts.cwd {
            let _ = std::env::set_current_dir(d);
        }
        // stdin 接 /dev/null；stdout/stderr 都进日志
        if let Some(dn) = &devnull {
            unsafe { libc::dup2(dn.as_raw_fd(), 0) };
        }
        if let Some(lf) = &log_file {
            unsafe {
                libc::dup2(lf.as_raw_fd(), 1);
                libc::dup2(lf.as_raw_fd(), 2);
            }
        }
        // 进 cgroup。必须在 exec 之前写——exec 之后进程可能就不受控了。
        if let Some(dir) = &cg {
            if let Ok(mut f) = fs::OpenOptions::new().append(true).open(dir.join("cgroup.procs")) {
                let _ = writeln!(f, "{}", unsafe { libc::getpid() });
            }
        }
        // exec
        let prog = CString::new(opts.cmd[0].clone()).unwrap();
        let args: Vec<CString> = opts.cmd.iter().map(|a| CString::new(a.as_str()).unwrap()).collect();
        let mut argv: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
        argv.push(std::ptr::null());
        unsafe { libc::execvp(prog.as_ptr(), argv.as_ptr()) };
        // exec 失败
        unsafe { libc::_exit(127) };
    }

    // ---- 父进程：等待 ----
    // 用 pidfd 而不是 waitpid：pidfd 是稳定的句柄，不会因为 pid 复用而误判。
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;

    // 两个判据并存：总时长管"跑太久"，无输出管"卡死"。
    // 只用一个不够——一轮扎实的逆向可能 15 分钟都在跑（不该被 idle 杀），
    // 而一个卡住的 ssh 连接 15 分钟一个字都不吐（该杀）。
    let mut timed_out = false;
    let mut kill_reason = "";
    let status: i32;
    if pidfd >= 0 {
        let mut pfd = libc::pollfd { fd: pidfd, events: libc::POLLIN, revents: 0 };
        let hard_deadline = Instant::now() + opts.timeout;
        let mut last_size = log_size(&opts.log);
        let mut last_change = Instant::now();
        loop {
            let slice = Duration::from_millis(500);
            let r = unsafe { libc::poll(&mut pfd, 1, slice.as_millis() as i32) };
            if r != 0 {
                break; // 子进程退出（或 poll 出错，交由后续 waitpid 收尾）
            }
            let now = Instant::now();
            if now >= hard_deadline {
                kill_reason = "total_wall";
                timed_out = true;
                break;
            }
            if !opts.idle.is_zero() {
                let sz = log_size(&opts.log);
                if sz != last_size {
                    last_size = sz;
                    last_change = now;
                } else if now.duration_since(last_change) >= opts.idle {
                    kill_reason = "idle";
                    timed_out = true;
                    break;
                }
            }
        }
        if timed_out {
            // 先礼后兵：SIGTERM 给机会收尾（把 ROUND.md / 日志写完）
            let pgid = unsafe { libc::getpgid(pid) };
            if pgid > 0 {
                unsafe { libc::kill(-pgid, libc::SIGTERM) };
            }
            // 等宽限期
            let mut gp = libc::pollfd { fd: pidfd, events: libc::POLLIN, revents: 0 };
            let gr = unsafe {
                libc::poll(&mut gp, 1, opts.grace.as_millis().min(i32::MAX as u128) as i32)
            };
            if gr == 0 {
                unsafe { libc::kill(-pgid, libc::SIGKILL) };
            }
        }
        // 收尸
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        status = st;
        unsafe { libc::close(pidfd) };
    } else {
        // 内核不支持 pidfd 时退回 waitpid
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        status = st;
    }

    // ---- 清理整棵进程树 ----
    // 这一步才是关键：无论正常结束还是超时，cgroup 里剩下的都必须杀干净。
    // 今天踩过的坑就是主进程死了、孙进程还在吃 1.3GB。
    let mut killed = 0;
    if let Some(dir) = &cg {
        for _ in 0..3 {
            let pids = cgroup_pids(dir);
            if pids.is_empty() {
                break;
            }
            for p in &pids {
                unsafe { libc::kill(*p, libc::SIGKILL) };
                killed += 1;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    let elapsed_ms = started.elapsed().as_millis();
    let peak_kb = cg.as_ref()
        .and_then(|d| read_u64(&d.join("memory.peak")))
        .map(|b| b / 1024)
        .unwrap_or(0);

    // 读限额是否被触发（OOM 归因的关键证据）
    // memory.events 是多行 "key value" 文本，不是单个数字——
    // 早先用 read_u64 解析它，必然失败并静默返回 0，OOM 归因就丢了。
    let oom_kills = cg.as_ref()
        .and_then(|d| fs::read_to_string(d.join("memory.events")).ok())
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("oom_kill"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|n| n.parse::<u64>().ok()))
        })
        .unwrap_or(0);

    // 清理 cgroup 目录
    if let Some(dir) = &cg {
        let _ = fs::remove_dir(dir);
    }

    let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { -1 };
    let sig = if libc::WIFSIGNALED(status) { libc::WTERMSIG(status) } else { 0 };

    println!(
        "{{\"exit\":{},\"signal\":{},\"elapsed_ms\":{},\"peak_mem_kb\":{},\"timed_out\":{},\"kill_reason\":\"{}\",\"killed\":{},\"oom_kill\":{},\"limited\":{}}}",
        code, sig, elapsed_ms, peak_kb,
        if timed_out { "true" } else { "false" },
        kill_reason, killed, oom_kills,
        if limited { "true" } else { "false" }
    );

    // 退出码语义：被信号杀死时返回 128+sig，与 shell 惯例一致
    exit(if timed_out { 124 } else if sig != 0 { 128 + sig } else { code });
}
