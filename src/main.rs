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

use std::collections::HashSet;
use std::io::BufRead;
use std::os::linux::fs::MetadataExt;
use regex::Regex;

extern crate glob;
use glob::glob;

extern crate clap;
use clap::Parser;

extern crate ini;
use ini::Ini;

extern crate nix;
use nix::sys::signal;

extern crate time;
use time::macros::*;

extern crate users;
use users::get_user_by_name;

use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use std::os::unix::process::CommandExt;

pub static VERBOSITY: AtomicUsize = AtomicUsize::new(0);
pub const MAX_VERBOSITY: usize = 4;
#[allow(unused_macros)]
macro_rules! println_vb1 {
    () => { if VERBOSITY.load(Ordering::SeqCst) > 0 { println!() } };
    ($($arg:tt)*) => {{ if VERBOSITY.load(Ordering::SeqCst) > 0 { println!($($arg)*); } }};
}
#[allow(unused_macros)]
macro_rules! println_vb2 {
    () => { if VERBOSITY.load(Ordering::SeqCst) > 1 { println!() } };
    ($($arg:tt)*) => {{ if VERBOSITY.load(Ordering::SeqCst) > 1 { println!($($arg)*); } }};
}
#[allow(unused_macros)]
macro_rules! println_vb3 {
    () => { if VERBOSITY.load(Ordering::SeqCst) > 2 { println!() } };
    ($($arg:tt)*) => {{ if VERBOSITY.load(Ordering::SeqCst) > 2 { println!($($arg)*); } }};
}
#[allow(unused_macros)]
macro_rules! println_vb4 {
    () => { if VERBOSITY.load(Ordering::SeqCst) > 3 { println!() } };
    ($($arg:tt)*) => {{ if VERBOSITY.load(Ordering::SeqCst) > 3 { println!($($arg)*); } }};
}

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

    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }
}
impl <'a> From<&'a str> for CircadianError {
    fn from(error: &str) -> Self {
        CircadianError(error.to_owned())
    }
}
impl From<std::io::Error> for CircadianError {
    fn from(error: std::io::Error) -> Self {
        CircadianError(error.to_string().to_owned())
    }
}
impl From<regex::Error> for CircadianError {
    fn from(error: regex::Error) -> Self {
        CircadianError(error.to_string().to_owned())
    }
}
impl From<std::num::ParseIntError> for CircadianError {
    fn from(error: std::num::ParseIntError) -> Self {
        CircadianError(error.to_string().to_owned())
    }
}
impl From<std::string::FromUtf8Error> for CircadianError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        CircadianError(error.to_string().to_owned())
    }
}
impl From<glob::PatternError> for CircadianError {
    fn from(error: glob::PatternError) -> Self {
        CircadianError(error.to_string().to_owned())
    }
}
impl From<ini::Error> for CircadianError {
    fn from(error: ini::Error) -> Self {
        CircadianError(error.to_string().to_owned())
    }
}
impl From<nix::Error> for CircadianError {
    fn from(error: nix::Error) -> Self {
        CircadianError(error.to_string().to_owned())
    }
}
impl From<time::error::Parse> for CircadianError {
    fn from(error: time::error::Parse) -> Self {
        CircadianError(error.to_string().to_owned())
    }
}
impl From<time::error::ComponentRange> for CircadianError {
    fn from(error: time::error::ComponentRange) -> Self {
        CircadianError(error.to_string().to_owned())
    }
}

type IdleResult = Result<u32, CircadianError>;
type ThreshResult = Result<bool, CircadianError>;
type ExistResult = Result<bool, CircadianError>;

#[allow(dead_code)]
enum NetConnection {
    SSH,
    SMB,
    NFS,
}

#[allow(dead_code)]
enum CpuHistory {
    Min1,
    Min5,
    Min15
}

#[derive(Clone)]
struct AutoWakeEpoch {
    epoch: i64,
    is_utc: bool,
}

#[derive(Debug)]
struct IdleResponse {
    w_idle: IdleResult,
    w_enabled: bool,
    xssstate_idle: IdleResult,
    xssstate_enabled: bool,
    xprintidle_idle: IdleResult,
    xprintidle_enabled: bool,
    wake_remain: u32,
    tty_idle: u32,
    tty_enabled: bool,
    x11_idle: u32,
    x11_enabled: bool,
    min_idle: u32,
    idle_target: u64,
    idle_remain: u64,
    is_idle: bool,
}
impl std::fmt::Display for IdleResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let result_map = vec![
            (self.w_idle.as_ref(), self.w_enabled, "w"),
            (self.xssstate_idle.as_ref(), self.xssstate_enabled, "xssstate"),
            (self.xprintidle_idle.as_ref(), self.xprintidle_enabled, "xprintidle"),
        ];
        for (var,enabled,name) in result_map {
            let s = match var {
                Ok(x)  => x.to_string(),
                Err(e) => e.to_string(),
            };
            let enabled = match enabled {
                true => "*",
                _ => "",
            };
            let name = format!("{}{}", name, enabled);
            let _ = write!(f, "{:<16}: {}\n", name, s);
        }
        let _ = write!(f, "{:<16}: {}\n", "Wake block", self.wake_remain);
        let int_map = vec![
            (self.tty_idle, self.tty_enabled, "TTY (combined)"),
            (self.x11_idle, self.x11_enabled, "X11 (combined)"),
        ];
        for (var,enabled,name) in int_map {
            let enabled = match enabled {
                true => "*",
                _ => "",
            };
            let name = format!("{}{}", name, enabled);
            let _ = write!(f, "{:<16}: {}\n", name, var);
        }
        let _ = write!(f, "{:<16}: {}\n", "Idle (min)", self.min_idle);
        let _ = write!(f, "{:<16}: {}\n", "Idle target", self.idle_target);
        let _ = write!(f, "{:<16}: {}\n", "Until idle", self.idle_remain);
        let _ = write!(f, "{:<16}: {}\n", "IDLE?", self.is_idle);
        Ok(())
    }
}

#[derive(Debug)]
struct NonIdleResponse {
    cpu_load: ThreshResult,
    cpu_load_enabled: bool,
    ssh: ExistResult,
    ssh_enabled: bool,
    smb: ExistResult,
    smb_enabled: bool,
    nfs: ExistResult,
    nfs_enabled: bool,
    audio: ExistResult,
    audio_enabled: bool,
    procs: ExistResult,
    procs_enabled: bool,
    is_blocked: bool,
}
impl std::fmt::Display for NonIdleResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let result_map = vec![
            (self.cpu_load.as_ref(), self.cpu_load_enabled, "CPU load"),
            (self.ssh.as_ref(), self.ssh_enabled, "SSH"),
            (self.smb.as_ref(), self.smb_enabled, "SMB"),
            (self.nfs.as_ref(), self.nfs_enabled, "NFS"),
            (self.audio.as_ref(), self.audio_enabled, "Audio"),
            (self.procs.as_ref(), self.procs_enabled, "Processes"),
        ];
        for (var,enabled,name) in result_map {
            let s = match var {
                Ok(x)  => x.to_string(),
                Err(e) => e.to_string(),
            };
            let enabled = match enabled {
                true => "*",
                _ => "",
            };
            let name = format!("{}{}", name, enabled);
            let _ = write!(f, "{:<16}: {}\n", name, s);
        }
        let _ = write!(f, "{:<16}: {}\n", "BLOCKED?", self.is_blocked);
        Ok(())
    }
}

static SIGUSR_SIGNALED: AtomicBool = AtomicBool::new(false);

/// Set global flag when SIGUSR1 signal is received
extern fn sigusr1_handler(_: i32) {
    SIGUSR_SIGNALED.store(true, Ordering::SeqCst);
}

/// Register SIGUSR1 signal handler
fn register_sigusr1() -> Result<signal::SigAction, CircadianError> {
    let sig_handler = signal::SigHandler::Handler(sigusr1_handler);
    let sig_action = signal::SigAction::new(sig_handler,
                                            signal::SaFlags::empty(),
                                            signal::SigSet::empty());
    unsafe {
        Ok(signal::sigaction(signal::SIGUSR1, &sig_action)?)
    }
}

fn command_exists(cmd: &str) -> bool {
    match Command::new(cmd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status() {
            Ok(_) => true,
            Err(_) => false,
        }
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

// count number of fields in 'w' output
//
// This is a stupid requirement because some linux distros build w
// with the 'FROM' field enabled by default and others with it
// disabled.  'w' has a command-line option to *toggle* the field, but
// no to forcibly enable/disable it.
fn count_w_fields() -> Result<usize, CircadianError> {
    let w_stdout = Stdio::piped();
    let s_stdout = Stdio::piped();
    let mut w_output = Command::new("w")
        .arg("-us")
        .stdout(w_stdout).spawn()?;
    let _ = w_output.wait()?;
    let w_stdout = w_output.stdout
        .ok_or(CircadianError("w command has no output".into()))?;
    // print just the second row, the header
    let mut sed_output = Command::new("sed")
        .arg("-n")
        .arg("2p")
        .stdin(w_stdout)
        .stdout(s_stdout)
        .spawn()?;
    let _ = sed_output.wait()?;
    let s_stdout = sed_output.stdout
        .ok_or(CircadianError("w/sed command has no output".into()))?;
    let awk_output = Command::new("awk")
        .arg("{print NF}")
        .stdin(s_stdout)
        .output()?;
    let num_fields: usize = String::from_utf8(awk_output.stdout)
        .unwrap_or(String::new())
        .trim()
        .parse::<usize>()?;
    Ok(num_fields)
}

// Returns tuple containing argument string to provide to `w` to have
// the FROM field included, and the 0-indexed offset of the field.
fn w_from_args() -> Result<(String, usize), CircadianError> {
    // Ask for a fake user to get just the header and check if the
    // FROM field is enabled.
    let w_output = Command::new("w")
        .arg("-us")
        .arg("CIRCADIAN_FAKEUSER")
        .output()?;
    let w_fields: Vec<String> = w_output.stdout
        .lines()
        .nth(1) // second line is the header
        .ok_or(CircadianError("w command has no output".into()))??
        .split_whitespace().map(|x| x.to_owned()).collect();
    let from_header = String::from("FROM");
    let (hargs, args) = match w_fields.contains(&from_header) {
        true => ("-hus".to_string(), "-us".to_string()),
        false => ("-husf".to_string(), "-usf".to_string()),
    };

    // Do it again with FROM field on and find its index.
    let w_output = Command::new("w")
        .arg(&args)
        .arg("CIRCADIAN_FAKEUSER")
        .output()?;
    let w_fields: Vec<String> = w_output.stdout
        .lines()
        .nth(1)
        .ok_or(CircadianError("w command has no output".into()))??
        .split_whitespace().map(|x| x.to_owned()).collect();
    let idx = w_fields.iter()
        .position(|x| x == &from_header)
        .ok_or(CircadianError("w command arguments invalid".into()))?;
    Ok((hargs, idx))
}

fn xauthority_from_cmdline(display: &str) -> Result<String, CircadianError> {
    // Look for PIDs of processes with a variety of X11-related names.
    let pgrep_out = Command::new("pgrep")
        .arg("(X11|Xorg|xinit|Xwayland|Xephyr)")
        .output()?;
    let pids: Vec<String> = String::from_utf8(pgrep_out.stdout)
        .unwrap_or(String::new())
        .split("\n")
        .map(|s| s.trim().to_owned())
        .filter(|s| s.len() > 0)
        .collect();
    let display = display.to_owned();

    // Read the command-line arguments out of procfs for all of the
    // matching PIDs.
    for pid in &pids {
        let cmdline_path = PathBuf::from(format!("/proc/{}/cmdline", pid));
        if !cmdline_path.exists() {
            continue;
        }
        let raw_args: String = String::from_utf8(std::fs::read(&cmdline_path)?)?;
        let split_args: Vec<String> = raw_args.split("\0").map(|s| s.to_owned()).collect();

        // Look for processes that have the display name (":0") as an
        // argument, and also have a "-auth" argument.  The parameter
        // after "-auth" should be an xauth file.
        let auth_arg = String::from("-auth");
        if split_args.contains(&auth_arg) && split_args.contains(&display) {
            // Grab the next argument after "-auth"
            let split_args: Vec<String> = split_args.iter().rev().take_while(|s| *s != "-auth").map(|s| s.to_owned()).collect();
            let auth_arg: &str = split_args.iter().map(|x| x.as_str()).rev().next().unwrap_or("");
            let auth_path = PathBuf::from(auth_arg);
            // Ensure the file actually exists
            if auth_path.exists() {
                // return the first match
                println_vb4!("    - xauth from cmdline: {}", auth_arg);
                return Ok(auth_arg.to_string());
            }
        }
    }

    Err(CircadianError("No auth file specified on command line.".into()))
}

fn xauthority_for_uid(uid: u32, display: &str) -> String {
    // Default to whatever is currently in the XAUTHORITY environment
    // variable, if anything.
    let default = std::env::var("XAUTHORITY").unwrap_or("".into());

    // If root user, try to read the xauth file out of the
    // command-line arguments.  This one takes highest priority, if it
    // exists.
    if uid == 0 {
        if let Ok(xauth) = xauthority_from_cmdline(display) {
            return xauth;
        }
    }

    // getent displays the row from /etc/passwd for a specific user
    let getent_stdout = Stdio::piped();
    let mut getent_output = match Command::new("getent")
        .arg("passwd")
        .arg(uid.to_string())
        .stdout(getent_stdout).spawn() {
            Ok(w) => w,
            _ => return default,
        };
    let _ = match getent_output.wait() {
        Ok(_) => {},
        _ => return default,
    };
    let getent_stdout = match getent_output.stdout {
        Some(w) => w,
        _ => return default,
    };

    // the 6th colon-separated field is the user's home directory
    let cut_output = match Command::new("cut")
        .arg("-d:")
        .arg("-f6")
        .stdin(getent_stdout)
        .output() {
            Ok(o) => o,
            _ => return default,
        };

    // look for ~/.Xauthority for the specified user
    let homedir = String::from_utf8(cut_output.stdout)
        .unwrap_or(default.clone())
        .trim().to_owned();
    let mut homedir = PathBuf::from(homedir);
    homedir.push(".Xauthority");

    // return the path if it exists, otherwise just use whatever the
    // current XAUTHORITY environment variable is set to.
    match homedir.exists() {
        true => homedir.to_str().unwrap_or(&default).to_owned(),
        _ => default,
    }
}

/// Call 'w' command and return minimum idle time
fn idle_w() -> IdleResult {
    let num_fields = count_w_fields()?;
    let w_stdout = Stdio::piped();
    let mut w_output = Command::new("w")
        .arg("-hus")
        .stdout(w_stdout).spawn()?;
    let _ = w_output.wait()?;
    let w_stdout = w_output.stdout
        .ok_or(CircadianError("w command has no output".into()))?;
    // idle field is the second to last
    let awk_output = Command::new("awk")
        .arg(format!("{{print ${}}}", num_fields - 1))
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

/// Call idle command for each X display
///
/// 'cmd' should be a unix command that, given args 'args', prints the idle
/// time in milliseconds.  It will be run with the DISPLAY env variable set
/// and with the uid of the user that owns the DISPLAY, for every running
/// X display.  The minimum of all found idle times is returned.
fn idle_fn(cmd: &str, args: Vec<&str>) -> IdleResult {
    let mut display_mins: Vec<u32> = Vec::<u32>::new();
    let (w_args, from_idx) = w_from_args()?;
    println_vb4!("cmd: {} / w args: '{}' / w field: {}", cmd, w_args, from_idx);
    for device in glob("/tmp/.X11-unix/X*")? {
        println_vb4!("  - socket: {:?}", device);
        let device: String = match device {
            Ok(p) => p.to_str().unwrap_or("0").to_owned(),
            _ => "0".to_owned(),
        };
        let display = format!(":{}", device.chars().rev().next().unwrap_or('0'));
        println_vb4!("    - display: {}", display);
        let mut output = Command::new("w")
            .arg(&w_args)
            .stdout(Stdio::piped()).spawn()?;
        let _ = output.wait()?;
        let w_stdout = output.stdout
            .ok_or(CircadianError("w command has no output".into()))?;
        let awk_arg = format!("{{if (${} ~ /^{}/) print $1}}", from_idx + 1, display);
        let output = Command::new("awk")
            .arg(awk_arg)
            .stdin(w_stdout)
            .output()?;
        let user_str = String::from_utf8(output.stdout)
            .unwrap_or(String::new());
        println_vb4!("    - awk users ({}): {}", user_str.len(), user_str.replace("\n", " / "));

        // Get a list of all system users with open sessions to this
        // X11 display, and de-duplicate by storing in a set.  There
        // should be one per logged in user if a session manager is in
        // use, plus one for each terminal the user has open.
        let user_list: HashSet<&str> = user_str.split("\n")
            .map(|x| x.trim())
            .filter(|x| x.len() > 0)
            .collect();
        // Convert all of the user names to UIDs.
        let mut user_list: HashSet<u32> = user_list.iter()
            .filter_map(|x| match x.trim() {
                user if user.len() > 0 => {
                    match Command::new("id").arg("-u").arg(user).output() {
                        Ok(output) => {
                            let mut uid = String::from_utf8(output.stdout)
                                .unwrap_or(String::new());
                            uid.pop();
                            let uid = uid.parse::<u32>().unwrap_or(0);
                            Some(uid)
                        },
                        Err(_) => {
                            None
                        }
                    }
                },
                _ => {
                    None
                }
            })
            .collect();
        // Insert the UID of the socket owner, too.  This covers X
        // servers spawned without session managers, i.e. those
        // spawned with 'startx' or Xephyr.
        let owner_uid = std::fs::metadata(&device)?.st_uid();
        user_list.insert(owner_uid);
        // Always give it a try as root, too, since root can read
        // xauth files from anywhere.
        user_list.insert(0);
        println_vb4!("    - socket owner: {}", owner_uid);
        for uid in user_list {
            println_vb4!("    - UID: {}", uid);
            let xauth = xauthority_for_uid(uid, &display);
            println_vb4!("    - xauthority: {}", xauth);
            // allow this command to fail, in case there are several X
            // servers running.
            match Command::new(cmd)
                .args(&args)
                .uid(uid)
                .env("DISPLAY", &display)
                .env("XAUTHORITY", &xauth)
                .output() {
                    Ok(output) => {
                        let mut idle_str = String::from_utf8(output.stdout)
                            .unwrap_or(String::new());
                        idle_str.pop();
                        let idle = idle_str.parse::<u32>().unwrap_or(std::u32::MAX)/1000;
                        println_vb4!("      - idle: {}", idle);
                        display_mins.push(idle);
                    },
                    Err(e) => {
                        println!("WARNING: {} failed for socket {} with error: {}", cmd, device, e);
                    },
                }
        }
    }
    match display_mins.len() {
        0 => Err(CircadianError("No displays found.".to_string())),
        _ => Ok(display_mins.iter().fold(std::u32::MAX, |acc, x| std::cmp::min(acc,*x)))
    }
}

/// Call 'xprintidle' command and return idle time
fn idle_xprintidle() -> IdleResult {
    idle_fn("xprintidle", vec![])
}

/// Call 'xssstate' command and return idle time
fn idle_xssstate() -> IdleResult {
    idle_fn("xssstate", vec!["-i"])
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
        .map(|x| str::parse::<f64>(&x[0..x.len()-1].replace(",",".")).unwrap_or(0.0))
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
    // false == below threshold, true == above
    Ok(!*idle.get(idx).unwrap_or(&false))
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
    let mut output = Command::new("netstat")
        .arg("-tnpa")
        .stderr(Stdio::null())
        .stdout(Stdio::piped()).spawn()?;
    let _ = output.wait()?;
    let stdout = output.stdout
        .ok_or(CircadianError("netstat command has no output".to_string()))?;
    let mut output = Command::new("grep")
        .arg("ESTABLISHED")
        .stdin(stdout)
        .stdout(Stdio::piped()).spawn()?;
    let _ = output.wait()?;
    let stdout = output.stdout
        .ok_or(CircadianError("netstat command has no connections".to_string()))?;
    let pattern = match conn {
        NetConnection::SSH => "[0-9]+/ssh[d]*",
        NetConnection::SMB => "[0-9]+/smb[d]*",
        NetConnection::NFS => "[0-9]+:2049\\s",
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
fn exist_audio_alsa() -> ExistResult {
    let mut count = 0;
    for device in glob("/proc/asound/card*/pcm*/sub*/status")? {
        if let Ok(path) = device {
            let mut cat_output = Command::new("cat")
                .arg(path)
                .stderr(Stdio::null())
                .stdout(Stdio::piped()).spawn()?;
            let _ = cat_output.wait()?;
            let stdout = cat_output.stdout
                .ok_or(CircadianError("cat /proc/asound/* failed".to_string()))?;
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

/// Determine whether audio is actively playing on any Pulseaudio interface.
fn exist_audio_pulseaudio() -> ExistResult {
    let users_output = Command::new("users")
        .stderr(Stdio::null())
        .output();
    let users_stdout = users_output
        .map_err(| _ | CircadianError("users failed".to_string()));
    let users_output_str = String::from_utf8(users_stdout?.stdout)?;
    let active_users: HashSet<&str> = users_output_str.split(" ")
        .filter(|l| l.len() > 0)
        .collect();

    let mut count = 0;
    for active_user in active_users {
        match get_user_by_name(&active_user.trim()) {
            Some(x) => {
                let active_user_id = x.uid();
                let mut pactl_output = Command::new("pactl").uid(active_user_id)
                    .env("XDG_RUNTIME_DIR", format!("/run/user/{}", active_user_id))
                    .args(["list", "sinks", "short"])
                    .stderr(Stdio::null())
                    .stdout(Stdio::piped()).spawn()?;
                let _ = pactl_output.wait()?;
                let stdout = pactl_output.stdout
                    .ok_or(CircadianError("pactl failed".to_string()))?;
                let output = Command::new("grep")
                    .arg("RUNNING") // Does not includes IDLE == Paused audio
                    .stdin(stdout)
                    .output()?;
                let output_str = String::from_utf8(output.stdout)?;
                let lines: Vec<&str> = output_str.split("\n")
                    .filter(|l| l.len() > 0)
                    .collect();
                count += lines.len();
            },
            None    => continue,
        }

    }
    Ok(count > 0)
}

fn exist_audio() -> ExistResult {
    let audio_alsa = exist_audio_alsa();
    let audio_pulseaudio = exist_audio_pulseaudio();
    Ok(*audio_alsa.as_ref().unwrap_or(&false) || *audio_pulseaudio.as_ref().unwrap_or(&false))
}

#[derive(Parser)]
#[command(author, version, about, long_about)]
#[command(help_template = "\
{name} v{version}, {author-with-newline}
{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}
")]
struct CircadianLaunchOptions {
    #[arg(short = 'f', long = "config", value_name = "FILE", default_value_t = String::from("/etc/circadian.conf"))]
    config_file: String,
    #[arg(short, long)]
    test: bool,
    #[arg(short, long = "verbose", action = clap::ArgAction::Count)]
    verbosity: u8,
}

#[derive(Default,Debug)]
struct CircadianConfig {
    verbosity: usize,
    idle_time: u64,
    auto_wake: Option<String>,
    on_idle: Option<String>,
    on_wake: Option<String>,
    tty_input: bool,
    x11_input: bool,
    ssh_block: bool,
    smb_block: bool,
    nfs_block: bool,
    audio_block: bool,
    max_cpu_load: Option<f64>,
    process_block: Vec<String>,
}

fn read_config(file_path: &str) -> Result<CircadianConfig, CircadianError> {
    println!("Reading config from file: {}", file_path);
    let i = Ini::load_from_file(file_path)?;
    let mut config: CircadianConfig = Default::default();
    if let Some(section) = i.section(Some("settings".to_owned())) {
        let verbosity: usize = section.get("verbosity")
            .and_then(|x| match x {
                x if x.len() > 0 => { x.parse::<usize>().ok() },
                _ => None,
            })
            .unwrap_or(0);
        let verbosity = std::cmp::min(verbosity, MAX_VERBOSITY);
        VERBOSITY.store(verbosity, Ordering::SeqCst);
        config.verbosity = verbosity;
    }
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
    fn read_bool(s: &ini::Properties,
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
        config.nfs_block = read_bool(section, "nfs_block");
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

fn test_idle(config: &CircadianConfig, start: i64) -> IdleResponse {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let tty = idle_w();
    let xssstate = idle_xssstate();
    let xprintidle = idle_xprintidle();
    let tty_idle = *tty.as_ref().unwrap_or(&std::u32::MAX);
    let x11_idle = std::cmp::min(*xssstate.as_ref().unwrap_or(&std::u32::MAX),
                                 *xprintidle.as_ref().unwrap_or(&std::u32::MAX));
    let wake_remain = std::cmp::max(0, start + (config.idle_time as i64) - now) as u32;
    let min_idle: u32 = match (config.tty_input, config.x11_input) {
        (true,true) => std::cmp::min(tty_idle, x11_idle) as u32,
        (true,false) => tty_idle as u32,
        (false,_) => x11_idle as u32,
    };
    let idle_remain: u64 =
            std::cmp::max(config.idle_time as i64 - min_idle as i64, 0) as u64;
    IdleResponse {
        w_idle: tty,
        w_enabled: config.tty_input,
        xssstate_idle: xssstate,
        xssstate_enabled: config.x11_input,
        xprintidle_idle: xprintidle,
        xprintidle_enabled: config.x11_input,
        wake_remain: wake_remain,
        tty_idle: tty_idle,
        tty_enabled: config.tty_input,
        x11_idle: x11_idle,
        x11_enabled: config.x11_input,
        min_idle: min_idle,
        idle_target: config.idle_time,
        idle_remain: idle_remain,
        is_idle: idle_remain == 0 && wake_remain == 0,
    }
}
fn test_nonidle(config: &CircadianConfig) -> NonIdleResponse {
    let cpu_load = thresh_cpu(CpuHistory::Min1,
                              config.max_cpu_load.unwrap_or(999.0),
                              std::cmp::PartialOrd::lt);
    let cpu_load_enabled = config.max_cpu_load.is_some() &&
        config.max_cpu_load.unwrap() < 999.0;
    let ssh = exist_net_connection(NetConnection::SSH);
    let ssh_enabled = config.ssh_block;
    let smb = exist_net_connection(NetConnection::SMB);
    let smb_enabled = config.smb_block;
    let nfs = exist_net_connection(NetConnection::NFS);
    let nfs_enabled = config.nfs_block;
    let audio = exist_audio();
    let audio_enabled = config.audio_block;
    let procs = config.process_block.iter()
    // Run 'exist_process' on each process string
        .map(|p| exist_process(p))
    // Flatten into a single result with a Vec of bools
        .collect::<Result<Vec<bool>, CircadianError>>()
    // Flatten Vec of bools into a single bool
        .map(|x| x.iter().fold(false, |acc,p| acc || *p));
    let procs_enabled = config.process_block.len() > 0;

    let blocked = (cpu_load_enabled && *cpu_load.as_ref().unwrap_or(&true)) ||
        (ssh_enabled && *ssh.as_ref().unwrap_or(&true)) ||
        (smb_enabled && *smb.as_ref().unwrap_or(&true)) ||
        (nfs_enabled && *nfs.as_ref().unwrap_or(&true)) ||
        (audio_enabled && *audio.as_ref().unwrap_or(&true)) ||
        (procs_enabled && *procs.as_ref().unwrap_or(&true));
    NonIdleResponse {
        cpu_load: cpu_load,
        cpu_load_enabled: cpu_load_enabled,
        ssh: ssh,
        ssh_enabled: ssh_enabled,
        smb: smb,
        smb_enabled: smb_enabled,
        nfs: nfs,
        nfs_enabled: nfs_enabled,
        audio: audio,
        audio_enabled: audio_enabled,
        procs: procs,
        procs_enabled: procs_enabled,
        is_blocked: blocked,
    }
}

fn is_rtc_utc() -> Result<bool, CircadianError> {
    fn get_rtc_time() -> Result<String, CircadianError> {
        let output = Command::new("cat")
            .arg("/sys/class/rtc/rtc0/time")
            .output()?;
        let t = String::from_utf8(output.stdout)?;
        Ok(t.split(":").take(2).collect::<Vec<&str>>().join(":"))
    }
    let utc_tm = time::OffsetDateTime::now_utc().time();
    let utc_time = format!("{:02}:{:02}", utc_tm.hour(), utc_tm.minute());
    let rtc_time = get_rtc_time()?;
    let is_utc = utc_time == rtc_time;
    let is_synced = utc_time.split(":").nth(1) == rtc_time.split(":").nth(1);
    match is_synced {
        true => Ok(is_utc),
        _ => Err("RTC clock does not match OS clock. Auto-wake disabled.".into()),
    }
}

fn auto_wake_to_epoch(auto_wake: &str) -> Result<AutoWakeEpoch, CircadianError> {
    let _ = is_rtc_utc()?; // just to detect RTC sync errors
    let format = format_description!("[hour]:[minute]");
    let auto_wake_tm = time::Time::parse(auto_wake, &format)?;
    let now_local = match time::OffsetDateTime::now_local() {
        Ok(l) => l,
        _ => time::OffsetDateTime::now_utc(),
    };
    let target_time_local = now_local.clone();
    let target_time_local = target_time_local.replace_hour(auto_wake_tm.hour())?;
    let target_time_local = target_time_local.replace_minute(auto_wake_tm.minute())?;
    let target_time_local = target_time_local.replace_second(0)?;
    let target_time_local = match target_time_local < now_local {
        true => target_time_local + time::Duration::days(1),
        false => target_time_local,
    };

    // UNIX timestamps are defined as being in UTC, and Linux's RTC is
    // defined as taking UTC timestamps.
    Ok(AutoWakeEpoch {
        epoch: target_time_local.unix_timestamp(),
        is_utc: true
    })
}
fn set_rtc_wakealarm(timestamp: i64) -> Result<(), CircadianError> {
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open("/sys/class/rtc/rtc0/wakealarm")?;
        f.write_all("0\n".as_bytes())?;
    }
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open("/sys/class/rtc/rtc0/wakealarm")?;
        f.write_all(format!("{}\n", timestamp).as_bytes())?;
    }
    Ok(())
}

fn set_auto_wake(auto_wake: Option<&String>) -> Result<AutoWakeEpoch, CircadianError> {
    if auto_wake.is_none() {
        return Err("Auto-wake not enabled.".into());
    }
    let time = auto_wake.unwrap();
    let epoch = auto_wake_to_epoch(time)?;
    let _ = set_rtc_wakealarm(epoch.epoch)?;
    println!("Auto-wake scheduled for {} ({})", time, epoch.epoch);
    Ok(epoch)
}

fn reschedule_auto_wake(auto_wake: Option<&String>, current_epoch: Option<AutoWakeEpoch>) -> Option<AutoWakeEpoch> {
    let mut new_rtc: Option<AutoWakeEpoch> = current_epoch.clone();
    if auto_wake.is_none() || current_epoch.is_none() {
        return None;
    }
    let epoch = current_epoch.unwrap();
    let now = match epoch.is_utc {
        true => time::OffsetDateTime::now_utc().unix_timestamp(),
        false => match time::OffsetDateTime::now_local() {
            Ok(l) => l.unix_timestamp(),
            _ => time::OffsetDateTime::now_utc().unix_timestamp(),
        }
    };
    if now >= epoch.epoch {
        new_rtc = match set_auto_wake(auto_wake) {
            Ok(epoch) => Some(epoch),
            Err(e) => {println!("Error recheduling auto-wake timer: {}.  Disabled.", e); None},
        };
    }
    new_rtc
}

#[allow(dead_code)]
fn test() {
    println!("Sec: {:?}", parse_w_time("10.45s"));
    println!("Sec: {:?}", parse_w_time("1:11"));
    println!("Sec: {:?}", parse_w_time("0:10m"));
    println!("w min: {:?}", idle_w());
    println!("xssstate min: {:?}", idle_xssstate());
    println!("xprintidle min: {:?}", idle_xprintidle());
    println!("cpu: {:?}", thresh_cpu(CpuHistory::Min5, 0.3, std::cmp::PartialOrd::lt));
    println!("ssh: {:?}", exist_net_connection(NetConnection::SSH));
    println!("smb: {:?}", exist_net_connection(NetConnection::SMB));
    println!("nfs: {:?}", exist_net_connection(NetConnection::NFS));
    println!("iotop: {:?}", exist_process("^iotop$"));
    println!("audio: {:?}", exist_audio());
}

fn main() {
    let launch_opts = CircadianLaunchOptions::parse();
    let config = read_config(&launch_opts.config_file)
        .unwrap_or_else(|x| {
            println!("{}", x);
            println!("Could not open config file.  Exiting.");
            std::process::exit(1);
        });
    println!("Circadian launching.");
    println!("{:?}", config);

    // override config verbosity from command-line
    if launch_opts.verbosity as usize > config.verbosity {
        VERBOSITY.store(launch_opts.verbosity as usize, Ordering::SeqCst);
    }

    // override user locale to make all command outputs uniform (e.g. when parsing column headers or dates/times)
    std::env::set_var("LC_ALL", "C");

    if launch_opts.test {
        println!("Got --test: running idle test and exiting.");
        let start = time::OffsetDateTime::now_utc().unix_timestamp();
        let idle = test_idle(&config, start);
        let tests = test_nonidle(&config);
        println!("Idle Detection Summary:\n{}{}", idle, tests);
        std::process::exit(0);
    }

    if !config.tty_input && !config.x11_input {
        println!("tty_input or x11_input must be enabled.  Exiting.");
        std::process::exit(1);
    }
    if config.tty_input && !command_exists("w") {
        println!("'w' command required by tty_input failed.  Exiting.");
        std::process::exit(1);
    }
    if config.x11_input &&
        !command_exists("xssstate") &&
        !command_exists("xprintidle") {
            println!("Both 'xssstate' and 'xprintidle' commands required by x11_input failed.  Exiting.");
            std::process::exit(1);
        }
    if config.max_cpu_load.is_some() &&
        thresh_cpu(CpuHistory::Min1, 0.0, std::cmp::PartialOrd::lt).is_err() {
            println!("'uptime' command required by max_cpu_load failed.  Exiting.");
            std::process::exit(1);
        }
    if (config.ssh_block || config.smb_block || config.nfs_block) &&
        exist_net_connection(NetConnection::SSH).is_err() {
        println!("'netstat' command required by ssh/smb/nfs_block failed.  Exiting.");
        std::process::exit(1);
        }
    if config.audio_block && (exist_audio_alsa().is_err() && exist_audio_pulseaudio().is_err())  {
        println!("'/proc/asound/' and pactl required by audio_block is unreadable. Exiting.");
        std::process::exit(1);
    }
    if config.process_block.len() > 0 && exist_process("").is_err() {
        println!("'pgrep' required by process_block failed.  Exiting.");
        std::process::exit(1);
    }
    if config.idle_time == 0 {
        println!("Idle time disabled.  Nothing to do.  Exiting.");
        std::process::exit(1);
    }
    let mut current_rtc: Option<AutoWakeEpoch> = match set_auto_wake(config.auto_wake.as_ref()) {
        Ok(epoch) => Some(epoch),
        Err(e) => {println!("Error setting auto-wake timer: {}", e); None},
    };
    let _ = register_sigusr1().unwrap_or_else(|x| {
        println!("{}", x);
        println!("WARNING: Could not register SIGUSR1 handler.");
        std::process::exit(1);
    });
    println!("Configuration valid.  Idle detection starting.");

    let mut idle_triggered = false;
    let mut start = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut watchdog = time::OffsetDateTime::now_utc().unix_timestamp();
    loop {
        let idle = test_idle(&config, start);
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        // Look for clock jumps that indicate the system slept. In this case dont run idle
        // trigger.
        // Otherwise if it's idle, the idle command hasn't already run, and it has been
        // at least |idle_time| since the service started: enter idle state.
        if watchdog + 30 > now && idle.is_idle && !idle_triggered {
            let tests = test_nonidle(&config);
            if !tests.is_blocked {
                println!("Idle state active:\n{}{}", idle, tests);
                if let Some(ref idle_cmd) = config.on_idle {
                    println!("System suspending.");
                    let status = Command::new("sh")
                        .arg("-c")
                        .arg(idle_cmd)
                        .status();
                    match status {
                        Ok(_) => { println!("Idle command succeeded."); },
                        Err(e) => { println!("Idle command failed: {}", e); },
                    }
                }
                idle_triggered = true;
            }
        }
        else {
            idle_triggered = false;
        }

        let sleep_time = std::cmp::max(idle.idle_remain, 5000);
        let sleep_chunk = 500;
        // Sleep for the minimum time needed before the system can possibly
        // be idle, but do it in small chunks so we can periodically check
        // for signals and clock jumps.
        for _ in 0 .. sleep_time / sleep_chunk {
            // Print stats when SIGUSR1 signal received
            let signaled = SIGUSR_SIGNALED.swap(false, Ordering::SeqCst);
            if signaled {
                let idle = test_idle(&config, start);
                let tests = test_nonidle(&config);
                println!("Idle Detection Summary:\n{}{}", idle, tests);
            }

            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            // Look for clock jumps that indicate the system slept
            if watchdog + 30 < now {
                println!("Watchdog missed.  Wake from sleep!");
                start = time::OffsetDateTime::now_utc().unix_timestamp();
                let idle = test_idle(&config, start);
                let tests = test_nonidle(&config);
                println!("Idle state on wake:\n{}{}", idle, tests);
                if let Some(ref wake_cmd) = config.on_wake {
                    println!("System waking.");
                    let status = Command::new("sh")
                        .arg("-c")
                        .arg(wake_cmd)
                        .status();
                    match status {
                        Ok(_) => { println!("Wake command succeeded."); },
                        Err(e) => { println!("Wake command failed: {}", e); },
                    }
                }
            }
            // Kick watchdog timer frequently, and possibly reschedule auto-wake timer
            if watchdog + 10 < now {
                current_rtc = reschedule_auto_wake(config.auto_wake.as_ref(), current_rtc);
                watchdog = time::OffsetDateTime::now_utc().unix_timestamp();
            }
            std::thread::sleep(std::time::Duration::from_millis(sleep_chunk));
        }
    }
}
