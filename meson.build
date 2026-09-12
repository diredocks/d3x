project('zzz', 'c',
  version : '0.1.1',
  default_options : [
    'buildtype=release',
    'c_std=gnu23'
  ]
)

if get_option('buildtype') == 'debug'
  add_project_arguments('-Db_sanitize=address', language : 'c')
endif

pcap_dep = dependency('libpcap', required : true)
event_dep = dependency('libevent', required : true)

inc = include_directories('include', 'src')

src_files = files(
  'src/auth.c',
  'src/state-machine.c',
  'src/crypto/aes.c',
  'src/crypto/aes-md5.c',
  'src/crypto/base64.c',
  'src/crypto/const.c',
  'src/crypto/crypto.c',
  'src/crypto/md5.c',
  'src/main.c',
  'src/packet/packet.c',
  'src/packet/send.c',
  'src/utils/config.c',
  'src/utils/device.c',
  'src/utils/ini.c',
  'src/utils/log.c'
)

executable('zzz',
  src_files,
  include_directories : inc,
  dependencies : [
    pcap_dep,
    event_dep
  ],
  install : true
)
