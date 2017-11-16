# Circadian

##
### Suspend-On-Idle Daemon for GNU/Linux Power Management
##

Circadian is a background daemon/service for triggering suspend/sleep/hibernate automatically when a computer is idle.

Circadian uses a suite of 'idle heuristics' to determine when a system is idle.  These include:
 * User activity in X11 (keyboard, mouse, full-screen playback)
 * User activity in terminals (typing in PTY/SSH session)
 * Open SSH connections
 * Open SMB/Samba connections
 * Active audio playback
 * CPU usage below specified threshold
 * Blacklisted processes

When all of its heuristics determine that your system has been idle for long enough, Circadian will execute a command.  This is typically a simple power suspend, but it can be configured to any desired action.

It can execute another command when it detects that the system woke back up.

Circadian exists because modern Linux distros already support suspend-on-idle, but it is apparently a very buggy and unreliable domain.  After you've followed your distro's advice of poking a handful of conf files, tweaking a few XML hierarchies, writing a few scripts, wafting the smoke of burning sage across your keyboard, suspending gem stones from your machine, and whatever else may be recommended... perhaps try Circadian.

## Status

"Works for me".  You try.  You give feedback on GitHub, or to <trevor@trevorbentley.com>.

## Installing

### Debian x86-64

* Download [Circadian 0.3.0](https://github.com/mrmekon/circadian/releases/download/0.3.0/circadian_0.3.0-1_amd64.deb)

```
$ sudo dpkg -i circadian_0.3.0-1_amd64.deb
```

Edit /etc/circadian.conf to configure.  The default is to suspend with systemd after 2 hours of idle.

When you are happy with the config, continue:

```
$ sudo systemctl enable circadian
$ sudo systemctl start circadian
```


### Any other system with systemd

Install manually.  It's easy.

```
$ git clone https://github.com/mrmekon/circadian.git
$ cd circadian
$ cargo build --release
$ sudo cp target/release/circadian /usr/local/bin/
$ sudo cp resources/circadian.conf.in /etc/circadian.conf
$ sudo cp resources/circadian.service /usr/lib/systemd/system/
$ sudo systemctl enable circadian
$ sudo systemctl start circadian
```

### Non-systemd systems

Follow systemd instructions, and port circadian.service to whatever format you want.

## Dependencies

* Might need to install
    * xssstate
    * xprintidle
    * netstat
    * rustc + cargo (if building locally)
* Should already have
    * grep
    * awk
    * w
    * id
    * uptime
    * pgrep
    * cat
    * sh

## Usage

* Should run as root, ideally from systemd.
* Config is in: /etc/circadian.conf (it is documented)
* `pkill -SIGUSR1 circadian` will dump info to syslog.  Use that to see if it's working, or find out why it isn't sleeping.
