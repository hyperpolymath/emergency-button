// SPDX-License-Identifier: AGPL-3.0-or-later
// Quick backup functionality with preview mode

module main

import os
import time

struct BackupPlan {
	source_dirs []string
	dest_path   string
	total_files int
	total_size  i64
	items       []BackupItem
}

struct BackupItem {
	path        string
	size        i64
	is_dir      bool
	will_backup bool
	reason      string
}

fn run_quick_backup(incident Incident, config Config) {
	dest := config.quick_backup_dest

	// Validate destination
	if !os.exists(dest) {
		eprintln('${c_red}[ERROR]${c_reset} Backup destination does not exist: ${dest}')
		eprintln('${c_blue}[INFO]${c_reset} Please create the directory first or mount the drive.')
		return
	}

	if !os.is_dir(dest) {
		eprintln('${c_red}[ERROR]${c_reset} Backup destination is not a directory: ${dest}')
		return
	}

	// Default source directories for quick backup
	home := os.home_dir()
	source_dirs := [
		os.join_path(home, 'Documents'),
		os.join_path(home, 'Desktop'),
		os.join_path(home, '.ssh'),
		os.join_path(home, '.gnupg'),
		os.join_path(home, '.config'),
	]

	println('')
	println('${c_blue}━━━ Quick Backup Preview ━━━${c_reset}')
	println('')

	// Create backup plan
	plan := create_backup_plan(source_dirs, dest)

	println('Source directories:')
	for dir in source_dirs {
		if os.exists(dir) {
			println('  ${c_green}✓${c_reset} ${dir}')
		} else {
			println('  ${c_yellow}○${c_reset} ${dir} (not found)')
		}
	}
	println('')
	println('Destination: ${dest}')
	println('')
	println('Summary:')
	println('  Files to backup: ${plan.total_files}')
	println('  Estimated size:  ${format_size(plan.total_size)}')
	println('')

	// Log the backup plan
	log_backup_plan(incident, plan, config)

	if config.dry_run {
		println('${c_cyan}[DRY-RUN]${c_reset} Would perform backup of ${plan.total_files} files')
		println('${c_cyan}[DRY-RUN]${c_reset} Backup log written to incident bundle')
		return
	}

	// Actually perform backup
	println('${c_blue}[INFO]${c_reset} Starting backup...')
	perform_backup(plan, incident, config)
}

fn create_backup_plan(source_dirs []string, dest string) BackupPlan {
	mut plan := BackupPlan{
		source_dirs: source_dirs
		dest_path: dest
		items: []
	}

	for dir in source_dirs {
		if !os.exists(dir) {
			continue
		}

		// Walk directory and count files
		scan_directory(dir, mut plan)
	}

	return plan
}

fn scan_directory(path string, mut plan BackupPlan) {
	entries := os.ls(path) or { return }

	for entry in entries {
		full_path := os.join_path(path, entry)

		// Skip hidden git directories to save space
		if entry == '.git' {
			continue
		}

		if os.is_dir(full_path) {
			// Recurse into subdirectories (with depth limit)
			depth := full_path.count(os.path_separator)
			if depth < 10 {
				scan_directory(full_path, mut plan)
			}
		} else {
			size := os.file_size(full_path)
			plan.total_files++
			plan.total_size += size

			plan.items << BackupItem{
				path: full_path
				size: size
				is_dir: false
				will_backup: true
			}
		}
	}
}

fn perform_backup(plan BackupPlan, incident Incident, config Config) {
	timestamp := time.now().custom_format('YYYYMMDD-HHmmss')
	backup_dir := os.join_path(plan.dest_path, 'emergency-backup-${timestamp}')

	os.mkdir_all(backup_dir) or {
		eprintln('${c_red}[ERROR]${c_reset} Failed to create backup directory: ${err}')
		return
	}

	mut copied := 0
	mut failed := 0

	for dir in plan.source_dirs {
		if !os.exists(dir) {
			continue
		}

		dir_name := os.base(dir)
		dest_dir := os.join_path(backup_dir, dir_name)

		// Use system copy for efficiency
		$if windows {
			result := os.execute('xcopy /E /I /H /Y "${dir}" "${dest_dir}"')
			if result.exit_code == 0 {
				copied++
				println('  ${c_green}✓${c_reset} ${dir_name}')
			} else {
				failed++
				println('  ${c_red}✗${c_reset} ${dir_name}')
			}
		} $else {
			result := os.execute('cp -r "${dir}" "${dest_dir}" 2>/dev/null')
			if result.exit_code == 0 {
				copied++
				println('  ${c_green}✓${c_reset} ${dir_name}')
			} else {
				failed++
				println('  ${c_red}✗${c_reset} ${dir_name}')
			}
		}
	}

	println('')
	if failed == 0 {
		println('${c_green}[OK]${c_reset} Backup complete: ${backup_dir}')
	} else {
		println('${c_yellow}[WARN]${c_reset} Backup completed with ${failed} errors')
	}

	// Log backup result
	log_backup_result(incident, backup_dir, copied, failed)
}

fn log_backup_plan(incident Incident, plan BackupPlan, config Config) {
	log_path := os.join_path(incident.logs_path, 'backup_plan.log')

	mut lines := []string{}
	lines << 'Quick Backup Plan'
	lines << '================='
	lines << ''
	lines << 'Destination: ${plan.dest_path}'
	lines << 'Total files: ${plan.total_files}'
	lines << 'Total size:  ${format_size(plan.total_size)}'
	lines << ''
	lines << 'Source directories:'
	for dir in plan.source_dirs {
		exists := if os.exists(dir) { 'exists' } else { 'not found' }
		lines << '  - ${dir} (${exists})'
	}
	lines << ''
	lines << 'Dry run: ${config.dry_run}'

	if config.dry_run {
		println('${c_cyan}[DRY-RUN]${c_reset} Would write backup plan to logs')
		return
	}

	os.write_file(log_path, lines.join('\n')) or {
		eprintln('${c_yellow}[WARN]${c_reset} Could not write backup plan: ${err}')
	}
}

fn log_backup_result(incident Incident, backup_dir string, copied int, failed int) {
	log_path := os.join_path(incident.logs_path, 'backup_result.log')

	content := 'Backup Result
=============

Backup directory: ${backup_dir}
Directories copied: ${copied}
Directories failed: ${failed}
Status: ${if failed == 0 { 'SUCCESS' } else { 'PARTIAL' }}
'

	os.write_file(log_path, content) or {
		eprintln('${c_yellow}[WARN]${c_reset} Could not write backup result: ${err}')
	}
}

fn format_size(bytes i64) string {
	if bytes >= 1073741824 {
		return '${f64(bytes) / 1073741824.0:.1}G'
	} else if bytes >= 1048576 {
		return '${f64(bytes) / 1048576.0:.1}M'
	} else if bytes >= 1024 {
		return '${f64(bytes) / 1024.0:.1}K'
	}
	return '${bytes}B'
}
