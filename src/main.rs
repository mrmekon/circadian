extern crate regex;
use regex::Regex;

use std::error::Error;
use std::process::Stdio;
use std::process::Command;

pub struct CircadianError(String);
impl std::fmt::Debug for CircadianError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl From<std::io::Error> for CircadianError {
    fn from(error: std::io::Error) -> Self {
        CircadianError(error.description().to_owned())
    }
}
impl From<regex::Error> for CircadianError {
    fn from(error: regex::Error) -> Self {
        CircadianError(error.description().to_owned())
    }
}
impl From<std::num::ParseIntError> for CircadianError {
    fn from(error: std::num::ParseIntError) -> Self {
        CircadianError(error.description().to_owned())
    }
}

type IdleResult = Result<u32, CircadianError>;
type ThreshResult = Result<bool, CircadianError>;
type ExistResult = Result<bool, CircadianError>;

#[allow(dead_code)]
enum NetConnection {
    SSH,
    SMB
}

#[allow(dead_code)]
enum CpuHistory {
    Min1,
    Min5,
    Min15
}

/// Parse idle time strings from 'w' command into seconds
fn parse_w_time(time_str: &str) -> Result<u32, CircadianError> {
    let mut secs: u32 = 0;
    let mut mins: u32 = 0;
    let mut hours:u32 = 0;
    let re_sec = Regex::new(r"^\d+.\d+s$")?;
    let re_min = Regex::new(r"^\d+:\d+$")?;
    let re_hour = Regex::new(r"^\d+:\d+m$")?;
    if re_sec.is_match(time_str) {
        let time_str: &str = time_str.trim_matches('s');
        let parts: Vec<u32> = time_str.split(".")
            .map(|s| str::parse::<u32>(s).unwrap_or(0))
            .collect();
        secs = *parts.get(0).unwrap_or(&0);
    }
    else if re_min.is_match(time_str) {
        let parts: Vec<u32> = time_str.split(":")
            .map(|s| str::parse::<u32>(s).unwrap_or(0))
            .collect();
        mins = *parts.get(0).unwrap_or(&0);
        secs = *parts.get(1).unwrap_or(&0);
    }
    else if re_hour.is_match(time_str) {
        let time_str: &str = time_str.trim_matches('m');
        let parts: Vec<u32> = time_str.split(":")
            .map(|s| str::parse::<u32>(s).unwrap_or(0))
            .collect();
        hours = *parts.get(0).unwrap_or(&0);
        mins = *parts.get(1).unwrap_or(&0);
    }
    else {
        return Err(CircadianError("Invalid idle format".to_string()));
    }
    Ok((hours*60*60) + (mins*60) + secs)
}

// Call 'w' command and return minimum idle time
fn idle_w() -> IdleResult {
    let w_output = Command::new("w")
        .arg("-hus")
        .stdout(Stdio::piped()).spawn()?;
    let w_stdout = w_output.stdout
        .ok_or(CircadianError("w command has no output".to_string()))?;
    let awk_output = Command::new("awk")
        .arg("{print $4}")
        .stdin(w_stdout)
        .output()?;
    let idle_times: Vec<u32> = String::from_utf8(awk_output.stdout)
        .unwrap_or(String::new())
        .split("\n")
        .filter(|t| t.len() > 0)
        .map(|t| parse_w_time(t))
        .filter_map(|t| t.ok())
        .collect();
    Ok(idle_times.iter().cloned().fold(std::u32::MAX, std::cmp::min))
}

// Call 'xssstate' command and return idle time
fn idle_xssstate() -> IdleResult {
    let output = Command::new("xssstate")
        .env("DISPLAY", ":0.0")
        .arg("-i")
        .output()?;
    let mut idle_str = String::from_utf8(output.stdout)
        .unwrap_or(String::new());
    idle_str.pop();
    Ok(idle_str.parse::<u32>().unwrap_or(0)/1000)
}

// Call 'xprintidle' command and return idle time
fn idle_xprintidle() -> IdleResult {
    let output = Command::new("xprintidle")
        .env("DISPLAY", ":0.0")
        .output()?;
    let mut idle_str = String::from_utf8(output.stdout)
        .unwrap_or(String::new());
    idle_str.pop();
    Ok(idle_str.parse::<u32>().unwrap_or(0)/1000)
}

// Compare whether 'uptime' 5-min CPU usage compares
// to the given thresh with the given cmp function.
//
// ex: thresh_cpu(CpuHistory::Min1, 0.1, std::cmp::PartialOrd::lt) returns true
//     if the 5-min CPU usage is less than 0.1 for the past minute
//
fn thresh_cpu<C>(history: CpuHistory, thresh: f64, cmp: C) -> ThreshResult
    where C: Fn(&f64, &f64) -> bool {
    let output = Command::new("uptime")
        .output()?;
    let uptime_str = String::from_utf8(output.stdout)
        .unwrap_or(String::new());
    let columns: Vec<&str> = uptime_str.split(" ").collect();
    let cpu_usages: Vec<f64> = columns.iter()
        .rev().take(3).map(|x| *x).collect::<Vec<&str>>().iter()
        .rev()
        .map(|x| *x)
        .filter(|x| x.len() > 0)
        .map(|x| str::parse::<f64>(&x[0..x.len()-1]).unwrap_or(std::f64::MAX))
        .collect::<Vec<f64>>();
    let idle: Vec<bool> = cpu_usages.iter()
        .map(|x| cmp(x, &thresh))
        .collect();
    // idle is bools of [1min, 5min, 15min] CPU usage
    let idx = match history {
        CpuHistory::Min1 => 0,
        CpuHistory::Min5 => 1,
        CpuHistory::Min15 => 2,
    };
    Ok(*idle.get(idx).unwrap_or(&false))
}

fn exist_process(prc: &str) -> ExistResult {
    let output = Command::new("pgrep")
        .arg("-c")
        .arg(prc)
        .output()?;
    let output = &output.stdout[0..output.stdout.len()-1];
    let count: u32 = String::from_utf8(output.to_vec())
        .unwrap_or(String::new()).parse::<u32>()?;
    Ok(count > 0)
}

fn exist_net_connection(conn: NetConnection) -> ExistResult {
    let output = Command::new("netstat")
        .arg("-tnpa")
        .stderr(Stdio::null())
        .stdout(Stdio::piped()).spawn()?;
    let stdout = output.stdout
        .ok_or(CircadianError("netstat command has no output".to_string()))?;
    let output = Command::new("grep")
        .arg("ESTABLISHED")
        .stdin(stdout)
        .stdout(Stdio::piped()).spawn()?;
    let stdout = output.stdout
        .ok_or(CircadianError("netstat command has no connections".to_string()))?;
    let pattern = match conn {
        NetConnection::SSH => "[0-9]+/ssh[d]*",
        NetConnection::SMB => "[0-9]+/smb[d]*",
    };
    let output = Command::new("grep")
        .arg("-E")
        .arg(pattern)
        .stdin(stdout)
        .output()?;
    let output = String::from_utf8(output.stdout)
        .unwrap_or(String::new());
    let connections: Vec<&str> = output
        .split("\n")
        .filter(|l| l.len() > 0)
        .collect();
    Ok(connections.len() > 0)
}

fn main() {
    println!("Hello, world!");
    println!("Sec: {:?}", parse_w_time("10.45s"));
    println!("Sec: {:?}", parse_w_time("1:11"));
    println!("Sec: {:?}", parse_w_time("0:10m"));
    loop {
        println!("w min: {:?}", idle_w());
        println!("xssstate min: {:?}", idle_xssstate());
        println!("xprintidle min: {:?}", idle_xprintidle());
        println!("cpu: {:?}", thresh_cpu(CpuHistory::Min5, 0.3, std::cmp::PartialOrd::lt));
        println!("ssh: {:?}", exist_net_connection(NetConnection::SSH));
        println!("smb: {:?}", exist_net_connection(NetConnection::SMB));
        println!("iotop: {:?}", exist_process("^iotop$"));
        std::thread::sleep(std::time::Duration::from_millis(2000));
    }
}
