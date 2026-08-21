// Per-service UI hints for the generic TomlEditor, keyed by service name.
// The editor renders whatever hints an entry declares without knowing any
// service by name — service-specific knowledge belongs here, not in the
// editor. Services without an entry render unchanged.
//
// Supported hints:
//   callouts: [{ text, cta, url, beforeField? }]
//     Link callout rendered at the top of the form, or above the named
//     top-level field when beforeField is set. The TOML parser drops
//     comments, so guidance like this can't come from the config file
//     itself.
//   visibleWhen: { fieldName: { otherField: ['value', ...] } }
//     Hide a top-level field unless every listed sibling matches.
//   fieldHelp: { fieldName: 'text' }
//     Description shown under the field label.

export default {
  pointperfect: {
    callouts: [
      {
        text: 'PointPerfect corrections require a u-blox Thingstream account.',
        cta: 'Create an account',
        url: 'https://portal.thingstream.io/register?token=eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJjdG9rOmYzNGRkMTg2LWNjYWUtNDZhMS1hNWRmLWRiM2UxYjMwZWI5MCIsImF1ZCI6IlRoaW5nc3RyZWFtIiwiY21wIjoicmVkZW1wdGlvbi1jYW1wYWlnbjphZmViMmY4OS05MDMzLTQ1YjAtOGE4NC0wZjBhZGVjMzA3MWUifQ.Y0gn8ai-0eJ7LVs8k1uthvj7LM0WSXhefR70p3l6w6XWBD9mrO99NYdal1NS7wfi1DGyM21TMExaXUnFoxVYSA'
      }
    ]
  },
  'dds-agent': {
    // Show serial vs Ethernet fields based on transport.
    visibleWhen: {
      device: { transport: ['serial'] },
      baudrate: { transport: ['serial'] },
      port: { transport: ['ethernet', 'udp', 'tcp'] },
      address: { transport: ['ethernet', 'udp', 'tcp'] },
    },
    fieldHelp: {
      transport: 'Serial is Telem2 UART. Ethernet is UDP. TCP is rarely needed.',
      device: 'UART device, e.g. /dev/ttyTHS1 (Jetson) or /dev/ttyAMA4 (Pi).',
      baudrate: 'UART baud rate. PX4 Telem2 is typically 3000000.',
      address: 'Companion IP the flight controller should use (PX4 UXRCE_DDS_AG_IP). The agent listens on all interfaces.',
      port: 'Listen port. Match PX4 UXRCE_DDS_PRT (default 8888).',
    },
  },
};
