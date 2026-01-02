// SPDX-License-Identifier: AGPL-3.0-or-later
// Incident bundle creation and management

module main

import os
import time
import json

struct Incident {
	id         string
	path       string
	logs_path  string
	created_at time.Time
mut:
	commands   []CommandLog
}

struct CommandLog {
	name       string
	command    string
	started_at string
	ended_at   string
	exit_code  int
	output_len int
}

struct IncidentEnvelope {
	schema_version string        @[json: 'schema_version']
	id             string
	created_at     string        @[json: 'created_at']
	hostname       string
	username       string
	working_dir    string        @[json: 'working_dir']
	platform       PlatformInfo
	trigger        TriggerInfo
	commands       []CommandLog
}

struct PlatformInfo {
	os      string
	arch    string
	kernel  string
}

struct TriggerInfo {
	version    string
	dry_run    bool   @[json: 'dry_run']
	args       string
}

fn create_incident_bundle(config Config) !Incident {
	now := time.now()
	timestamp := now.custom_format('YYYYMMDD-HHmmss')
	incident_id := 'incident-${timestamp}'

	// Determine base directory (current working directory)
	base_dir := os.getwd()
	incident_path := os.join_path(base_dir, incident_id)
	logs_path := os.join_path(incident_path, 'logs')

	if config.dry_run {
		println('${c_cyan}[DRY-RUN]${c_reset} Would create: ${incident_path}')
		println('${c_cyan}[DRY-RUN]${c_reset} Would create: ${logs_path}')
		return Incident{
			id: incident_id
			path: incident_path
			logs_path: logs_path
			created_at: now
			commands: []
		}
	}

	// Check if directory already exists (idempotency)
	if os.exists(incident_path) {
		// Find existing incident with same prefix
		return error('Incident directory already exists: ${incident_path}')
	}

	// Create directories
	os.mkdir_all(logs_path) or {
		return error('Failed to create logs directory: ${err}')
	}

	incident := Incident{
		id: incident_id
		path: incident_path
		logs_path: logs_path
		created_at: now
		commands: []
	}

	// Write initial incident.json
	write_incident_json(incident, config) or {
		return error('Failed to write incident.json: ${err}')
	}

	return incident
}

fn write_incident_json(incident Incident, config Config) ! {
	envelope := IncidentEnvelope{
		schema_version: '1.0'
		id: incident.id
		created_at: incident.created_at.format_rfc3339()
		hostname: os.hostname()
		username: os.getenv('USER')
		working_dir: os.getwd()
		platform: PlatformInfo{
			os: get_os_name()
			arch: get_arch()
			kernel: get_kernel_version()
		}
		trigger: TriggerInfo{
			version: version
			dry_run: config.dry_run
			args: os.args.join(' ')
		}
		commands: incident.commands
	}

	json_content := json.encode_pretty(envelope)

	if config.dry_run {
		println('${c_cyan}[DRY-RUN]${c_reset} Would write incident.json')
		return
	}

	json_path := os.join_path(incident.path, 'incident.json')
	os.write_file(json_path, json_content) or {
		return error('Failed to write incident.json: ${err}')
	}
}

fn update_incident_json(incident Incident, config Config) {
	if config.dry_run {
		return
	}
	write_incident_json(incident, config) or {
		eprintln('${c_yellow}[WARN]${c_reset} Could not update incident.json: ${err}')
	}
}

fn write_receipt(incident Incident, config Config) ! {
	receipt_path := os.join_path(incident.path, 'receipt.adoc')

	mut content := []string{}
	content << '= Incident Receipt'
	content << ':icons: font'
	content << ':toc:'
	content << ''
	content << '== Summary'
	content << ''
	content << '|==='
	content << '|Field |Value'
	content << ''
	content << '|Incident ID'
	content << '|`${incident.id}`'
	content << ''
	content << '|Created'
	content << '|${incident.created_at.format_rfc3339()}'
	content << ''
	content << '|Hostname'
	content << '|${os.hostname()}'
	content << ''
	content << '|Platform'
	content << '|${get_os_name()} (${get_arch()})'
	content << ''
	content << '|Dry Run'
	content << '|${config.dry_run}'
	content << '|==='
	content << ''
	content << '== Commands Executed'
	content << ''

	if incident.commands.len == 0 {
		content << '_No commands logged._'
	} else {
		content << '|==='
		content << '|Command |Exit Code |Output Size'
		content << ''
		for cmd in incident.commands {
			content << '|${cmd.name}'
			content << '|${cmd.exit_code}'
			content << '|${cmd.output_len} bytes'
			content << ''
		}
		content << '|==='
	}

	content << ''
	content << '== Log Files'
	content << ''

	if config.dry_run {
		content << '_Dry run - no log files created._'
	} else {
		log_files := os.ls(incident.logs_path) or { [] }
		if log_files.len == 0 {
			content << '_No log files._'
		} else {
			for f in log_files {
				content << '* `logs/${f}`'
			}
		}
	}

	content << ''
	content << '== Next Steps'
	content << ''
	content << '1. Review the captured diagnostics in the `logs/` directory'
	content << '2. If issues persist, run specialized tools:'
	content << '   - `psa crisis --incident ${incident.path}`'
	content << '   - `big-up scan --incident ${incident.path}`'
	content << '3. Report findings via feedback-o-tron'
	content << ''
	content << '== License'
	content << ''
	content << 'AGPL-3.0-or-later'
	content << ''

	if config.dry_run {
		println('${c_cyan}[DRY-RUN]${c_reset} Would write receipt.adoc')
		return
	}

	os.write_file(receipt_path, content.join('\n')) or {
		return error('Failed to write receipt: ${err}')
	}

	println('${c_green}[OK]${c_reset} Written receipt.adoc')
}

fn get_os_name() string {
	$if linux {
		return 'Linux'
	} $else $if macos {
		return 'macOS'
	} $else $if windows {
		return 'Windows'
	} $else {
		return 'Unknown'
	}
}

fn get_arch() string {
	$if amd64 {
		return 'x86_64'
	} $else $if arm64 {
		return 'arm64'
	} $else $if i386 {
		return 'i386'
	} $else {
		return 'unknown'
	}
}

fn get_kernel_version() string {
	$if linux {
		result := os.execute('uname -r')
		if result.exit_code == 0 {
			return result.output.trim_space()
		}
	} $else $if macos {
		result := os.execute('uname -r')
		if result.exit_code == 0 {
			return result.output.trim_space()
		}
	} $else $if windows {
		result := os.execute('ver')
		if result.exit_code == 0 {
			return result.output.trim_space()
		}
	}
	return 'unknown'
}
