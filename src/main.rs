/*
 * Copyright 2017 Trevor Bentley
 *
 * Author: Trevor Bentley
 * Contact: trevor@trevorbentley.com
 * Source: https://github.com/mrmekon/circadian
 *
 * This file is part of Circadian.
 *
 * Circadian is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Circadian is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Circadian.  If not, see <http://www.gnu.org/licenses/>.
 */
extern crate regex;
use regex::Regex;

extern crate glob;
use glob::glob;

extern crate clap;

extern crate ini;
use ini::Ini;

use std::error::Error;
use std::process::Stdio;
use std::process::Command;

pub struct CircadianError(String);
impl std::fmt::Display for CircadianError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::fmt::Debug for CircadianError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for CircadianError {
    fn description(&self) -> &str {
        self.0.as_str()
    }

    fn cause(&self) -> Option<&std::error::Error> {
        None
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
impl From<std::string::FromUtf8Error> for CircadianError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        CircadianError(error.description().to_owned())
    }
}
impl From<glob::PatternError> for CircadianError {
    fn from(error: glob::PatternError) -> Self {
        CircadianError(error.description().to_owned())
    }
}
impl From<ini::ini::Error> for CircadianError {
    fn from(error: ini::ini::Error) -> Self {
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

/// Call 'w' command and return minimum idle time
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

/// Call 'xssstate' command and return idle time
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

/// Call 'xprintidle' command and return idle time
fn idle_xprintidle() -> IdleResult {
    let output = Command::new("xprintidle")
        .env("DISPLAY", ":0.0")
        .output()?;
    let mut idle_str = String::from_utf8(output.stdout)
        .unwrap_or(String::new());
    idle_str.pop();
    Ok(idle_str.parse::<u32>().unwrap_or(0)/1000)
}

/// Compare whether 'uptime' 5-min CPU usage compares
/// to the given thresh with the given cmp function.
///
/// ex: thresh_cpu(CpuHistory::Min1, 0.1, std::cmp::PartialOrd::lt) returns true
///     if the 5-min CPU usage is less than 0.1 for the past minute
///
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

/// Determine whether a process (by name regex) is running.
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

/// Determine whether the given type of network connection is established.
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

/// Determine whether audio is actively playing on any ALSA interface.
fn exist_audio() -> ExistResult {
    let mut count = 0;
    for device in glob("/proc/asound/card*/pcm*/sub*/status")? {
        if let Ok(path) = device {
            let output = Command::new("cat")
                .arg(path)
                .stderr(Stdio::null())
                .stdout(Stdio::piped()).spawn()?;
            let stdout = output.stdout
                .ok_or(CircadianError("pacmd failed".to_string()))?;
            let output = Command::new("grep")
                .arg("state:")
                .stdin(stdout)
                .output()?;
            let output_str = String::from_utf8(output.stdout)?;
            let lines: Vec<&str> = output_str.split("\n")
                .filter(|l| l.len() > 0)
                .collect();
            count += lines.len();
        }
    }
    Ok(count > 0)
}

struct CircadianLaunchOptions {
    config_file: String,
    //script_dir: String,
}

#[derive(Default,Debug)]
struct CircadianConfig {
    idle_time: u64,
    auto_wake: Option<String>,
    on_idle: Option<String>,
    on_wake: Option<String>,
    tty_input: bool,
    x11_input: bool,
    ssh_block: bool,
    smb_block: bool,
    audio_block: bool,
    max_cpu_load: Option<f64>,
    process_block: Vec<String>,
}

fn read_config(file_path: &str) -> Result<CircadianConfig, CircadianError> {
    println!("Reading config from file: {}", file_path);
    let i = Ini::load_from_file(file_path)?;
    let mut config: CircadianConfig = Default::default();
    if let Some(section) = i.section(Some("actions".to_owned())) {
        config.idle_time = section.get("idle_time")
            .map_or(0, |x| if x.len() > 0 {
                let (body,suffix) = x.split_at(x.len()-1);
                let num: u64 = match suffix {
                    "m" => body.parse::<u64>().unwrap_or(0) * 60,
                    "h" => body.parse::<u64>().unwrap_or(0) * 60 * 60,
                    _ => x.parse::<u64>().unwrap_or(0),
                };
                num
            } else {0});
        config.auto_wake = section.get("auto_wake")
            .and_then(|x| if x.len() > 0 {Some(x.to_owned())} else {None});
        config.on_idle = section.get("on_idle")
            .and_then(|x| if x.len() > 0 {Some(x.to_owned())} else {None});
        config.on_wake = section.get("on_wake")
            .and_then(|x| if x.len() > 0 {Some(x.to_owned())} else {None});
    }
    fn read_bool(s: &std::collections::HashMap<String,String>,
                 key: &str) -> bool {
        match s.get(key).unwrap_or(&"no".to_string()).to_lowercase().as_str() {
            "yes" | "true" | "1" => true,
            _ => false,
        }
    }
    if let Some(section) = i.section(Some("heuristics".to_owned())) {
        config.tty_input = read_bool(section, "tty_input");
        config.x11_input = read_bool(section, "x11_input");
        config.ssh_block = read_bool(section, "ssh_block");
        config.smb_block = read_bool(section, "smb_block");
        config.audio_block = read_bool(section, "audio_block");
        config.max_cpu_load = section.get("max_cpu_load")
            .and_then(|x| if x.len() > 0
                      {Some(x.parse::<f64>().unwrap_or(999.0))} else {None});
        if let Some(proc_str) = section.get("process_block") {
            let proc_list = proc_str.split(",");
            config.process_block = proc_list
                .map(|x| x.trim().to_owned()).collect();
        }
    }
    Ok(config)
}

fn read_cmdline() -> CircadianLaunchOptions {
    let matches = clap::App::new("circadian")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .args_from_usage(
            "-f, --config=[FILE] ''
             -d, --script-dir=[DIR] ''")
        .get_matches();
    let config = matches.value_of("config").unwrap_or("/etc/circadian.conf");
    //let script_dir = matches.value_of("script-dir").unwrap_or("");
    //println!("Script dir: {}", script_dir);
    CircadianLaunchOptions {
        config_file: config.to_owned(),
        //script_dir: script_dir.to_owned(),
    }
}

fn main() {
    let launch_opts = read_cmdline();
    let config = read_config(&launch_opts.config_file);
    println!("{:?}", config);
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
        println!("audio: {:?}", exist_audio());
        std::thread::sleep(std::time::Duration::from_millis(2000));
    }
}
