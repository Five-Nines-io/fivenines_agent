// RSS of a loop shaped like one agent tick: MODE=threads spawns one worker
// thread per "collector" (call_bounded); MODE=inline runs them on the caller.
use std::sync::mpsc;
fn rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status").unwrap().lines()
        .find_map(|l| l.strip_prefix("VmRSS:")?.split_whitespace().next()?.parse().ok()).unwrap()
}
fn collector() -> usize {
    // a /proc read and a few KB of JSON-ish strings, like a real collector
    let s = std::fs::read_to_string("/proc/self/stat").unwrap();
    let v: Vec<String> = (0..200).map(|i| format!("{s}{i}")).collect();
    v.iter().map(String::len).sum()
}
fn main() {
    let threads = std::env::var("MODE").as_deref() != Ok("inline");
    for tick in 0..=600 {
        for _ in 0..12 {
            if threads {
                let (tx, rx) = mpsc::sync_channel(1);
                std::thread::spawn(move || { let _ = tx.send(collector()); });
                rx.recv().unwrap();
            } else {
                std::hint::black_box(collector());
            }
        }
        if tick % 150 == 0 { print!("tick {tick:3}: {:5.1} MB   ", rss_kb() as f64 / 1024.0); }
    }
    println!();
}
