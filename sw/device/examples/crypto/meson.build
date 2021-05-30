foreach device_name, device_lib : sw_lib_arch_core_devices
  crypto_elf = executable(
    'crypto_' + device_name,
    sources: [
      hw_ip_kmac_reg_h,
      'crypto.c',
      'crypto.h',
      'key.h',
    ],
    name_suffix: 'elf',
    dependencies: [
      sw_lib_dif_uart,
      sw_lib_dif_aes,
      sw_lib_dif_hmac,
      sw_lib_mem,
      riscv_crt,
      sw_lib_irq_handlers,
      device_lib,
      sw_lib_testing_test_status,
    ],
  )

  crypto_embedded = custom_target(
    'crypto_' + device_name,
    command: make_embedded_target_command,
    depend_files: [make_embedded_target_depend_files,],
    input: crypto_elf,
    output: make_embedded_target_outputs,
    build_by_default: true,
  )

  custom_target(
    'crypto_export_' + device_name,
    command: export_target_command,
    depend_files: [export_target_depend_files,],
    input: [crypto_elf, crypto_embedded],
    output: 'crypto_export_' + device_name,
    build_always_stale: true,
    build_by_default: true,
  )
endforeach
