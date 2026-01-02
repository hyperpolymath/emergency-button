// SPDX-License-Identifier: AGPL-3.0-or-later
// Handoff logic to specialized tools (psa, big-up)

module main

import os

struct HandoffTarget {
	name        string
	command     string
	args        []string
	description string
}

fn handoff(incident Incident, config Config) {
	// Try to find specialized tools in order of preference
	targets := [
		HandoffTarget{
			name: 'psa'
			command: 'psa'
			args: ['crisis', '--incident', incident.path]
			description: 'Personal Sysadmin crisis mode'
		},
		HandoffTarget{
			name: 'big-up'
			command: 'big-up'
			args: ['scan', '--incident', incident.path]
			description: 'Advanced diagnostics (non-mutating)'
		},
	]

	mut found_target := ?HandoffTarget(none)

	for target in targets {
		if tool_exists(target.command) {
			found_target = target
			break
		}
	}

	if target := found_target {
		println('${c_blue}[HANDOFF]${c_reset} Found ${target.name}: ${target.description}')
		println('')

		full_command := '${target.command} ${target.args.join(' ')}'

		if config.dry_run {
			println('${c_cyan}[DRY-RUN]${c_reset} Would execute: ${full_command}')
			return
		}

		println('${c_blue}[INFO]${c_reset} Launching: ${full_command}')
		println('')

		// Log the handoff
		log_handoff(incident, target, config)

		// Execute the handoff (spawn, don't wait)
		spawn_tool(target)
	} else {
		println('${c_yellow}[INFO]${c_reset} No specialized tools found (psa, big-up)')
		println('${c_blue}[INFO]${c_reset} Incident bundle is ready for manual review')
		println('')
		println('${c_cyan}Suggested next steps:${c_reset}')
		println('  1. Review logs in: ${incident.logs_path}')
		println('  2. Install psa or big-up for enhanced diagnostics')
		println('  3. Share the incident bundle for analysis')
	}
}

fn tool_exists(name string) bool {
	// Check if tool is in PATH
	$if windows {
		result := os.execute('where ${name} 2>nul')
		return result.exit_code == 0
	} $else {
		result := os.execute('command -v ${name} 2>/dev/null')
		return result.exit_code == 0
	}
}

fn spawn_tool(target HandoffTarget) {
	// Build the command
	mut cmd_args := [target.command]
	cmd_args << target.args

	// Use os.execute for now (synchronous)
	// In a more advanced version, we'd spawn and detach
	full_cmd := cmd_args.join(' ')

	$if windows {
		os.execute('start "" ${full_cmd}')
	} $else {
		// Run in foreground for now - user can Ctrl+C
		result := os.execute(full_cmd)
		if result.exit_code != 0 {
			eprintln('${c_yellow}[WARN]${c_reset} ${target.name} exited with code ${result.exit_code}')
		}
	}
}

fn log_handoff(incident Incident, target HandoffTarget, config Config) {
	if config.dry_run {
		return
	}

	handoff_log := os.join_path(incident.logs_path, 'handoff.log')
	content := 'Handoff to: ${target.name}
Command: ${target.command} ${target.args.join(' ')}
Description: ${target.description}
'

	os.write_file(handoff_log, content) or {
		eprintln('${c_yellow}[WARN]${c_reset} Could not write handoff log: ${err}')
	}
}
