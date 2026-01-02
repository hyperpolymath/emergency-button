// SPDX-License-Identifier: AGPL-3.0-or-later
// Safe diagnostic capture modules
// Best-effort, non-destructive data collection

module main

import os
import time

struct CaptureResult {
	name       string
	success    bool
	output     string
	error_msg  string
	duration   i64
}

fn capture_diagnostics(mut incident Incident, config Config) {
	// List of safe capture modules to run
	modules := [
		CaptureModule{'os_version', 'OS Version', get_os_version_commands()},
		CaptureModule{'uptime', 'System Uptime', get_uptime_commands()},
		CaptureModule{'disk_free', 'Disk Space', get_disk_commands()},
		CaptureModule{'memory', 'Memory Status', get_memory_commands()},
		CaptureModule{'network_summary', 'Network Summary', get_network_commands()},
		CaptureModule{'process_summary', 'Process Summary', get_process_commands()},
	]

	for mod in modules {
		result := run_capture_module(mod, incident, config)
		if result.success {
			println('  ${c_green}✓${c_reset} ${mod.display_name}')
		} else {
			println('  ${c_yellow}○${c_reset} ${mod.display_name} (skipped)')
		}

		// Log command execution
		incident.commands << CommandLog{
			name: mod.name
			command: mod.commands.join(' | ')
			started_at: time.now().format_rfc3339()
			ended_at: time.now().format_rfc3339()
			exit_code: if result.success { 0 } else { 1 }
			output_len: result.output.len
		}
	}

	// Update incident.json with command logs
	update_incident_json(incident, config)
}

struct CaptureModule {
	name         string
	display_name string
	commands     []string
}

fn run_capture_module(mod CaptureModule, incident Incident, config Config) CaptureResult {
	start := time.now()
	mut outputs := []string{}
	mut success := false

	for cmd in mod.commands {
		if config.dry_run {
			outputs << '[DRY-RUN] Would execute: ${cmd}'
			success = true
			continue
		}

		result := os.execute(cmd)
		if result.exit_code == 0 {
			outputs << '=== ${cmd} ==='
			outputs << result.output
			outputs << ''
			success = true
		}
	}

	output := outputs.join('\n')
	duration := time.now() - start

	// Write to log file
	if !config.dry_run && output.len > 0 {
		log_file := os.join_path(incident.logs_path, '${mod.name}.log')
		os.write_file(log_file, output) or {
			return CaptureResult{
				name: mod.name
				success: false
				error_msg: 'Failed to write log: ${err}'
				duration: duration.milliseconds()
			}
		}
	}

	return CaptureResult{
		name: mod.name
		success: success
		output: output
		duration: duration.milliseconds()
	}
}

// Platform-specific command lists

fn get_os_version_commands() []string {
	$if linux {
		return [
			'cat /etc/os-release',
			'uname -a',
			'hostnamectl 2>/dev/null || true',
		]
	} $else $if macos {
		return [
			'sw_vers',
			'uname -a',
		]
	} $else $if windows {
		return [
			'systeminfo | findstr /B /C:"OS"',
			'ver',
		]
	} $else {
		return ['uname -a']
	}
}

fn get_uptime_commands() []string {
	$if linux {
		return [
			'uptime',
			'cat /proc/uptime',
		]
	} $else $if macos {
		return [
			'uptime',
		]
	} $else $if windows {
		return [
			'net statistics workstation | find "Statistics"',
		]
	} $else {
		return ['uptime']
	}
}

fn get_disk_commands() []string {
	$if linux {
		return [
			'df -h',
			'df -i',
			'lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT 2>/dev/null || true',
		]
	} $else $if macos {
		return [
			'df -h',
			'diskutil list',
		]
	} $else $if windows {
		return [
			'wmic logicaldisk get size,freespace,caption',
		]
	} $else {
		return ['df -h']
	}
}

fn get_memory_commands() []string {
	$if linux {
		return [
			'free -h',
			'cat /proc/meminfo | head -20',
		]
	} $else $if macos {
		return [
			'vm_stat',
			'top -l 1 | head -10',
		]
	} $else $if windows {
		return [
			'systeminfo | findstr Memory',
		]
	} $else {
		return []
	}
}

fn get_network_commands() []string {
	$if linux {
		return [
			'ip addr show 2>/dev/null || ifconfig',
			'ip route show 2>/dev/null || route -n',
			'ss -tuln 2>/dev/null || netstat -tuln',
		]
	} $else $if macos {
		return [
			'ifconfig',
			'netstat -rn',
			'netstat -an | head -50',
		]
	} $else $if windows {
		return [
			'ipconfig /all',
			'netstat -an | findstr LISTENING',
		]
	} $else {
		return []
	}
}

fn get_process_commands() []string {
	$if linux {
		return [
			'ps aux --sort=-%mem | head -20',
			'ps aux --sort=-%cpu | head -20',
		]
	} $else $if macos {
		return [
			'ps aux | head -20',
			'top -l 1 -o mem | head -20',
		]
	} $else $if windows {
		return [
			'tasklist /V | findstr /V "N/A"',
		]
	} $else {
		return ['ps aux | head -20']
	}
}
