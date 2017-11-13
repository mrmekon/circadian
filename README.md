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

Circadian exists because modern Linux distros already support suspend-on-idle, but it is apparently a very buggy and unreliable domain.  After you've followed your distro's advice of poking a handful of conf files, tweaking a few XML hierarchies, writing a few scripts, wafting the smoke of burning sage across your keyboard, suspending gem stones from your machine, and whatever else may be recommended... perhaps try Circadian.

## Status

Completely unfinished.  Perhaps don't try it *now*.
