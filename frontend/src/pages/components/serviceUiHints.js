// Per-service UI hints for the generic TomlEditor, keyed by service name.
// The editor renders whatever hints an entry declares without knowing any
// service by name — service-specific knowledge belongs here, not in the
// editor. Services without an entry render unchanged.
//
// Supported hints:
//   callouts: [{ beforeField, text, cta, url }]
//     Link callout rendered above the named top-level field, so a prompt can
//     sit next to the fields it belongs to (e.g. credentials). The TOML
//     parser drops comments, so guidance like this can't come from the
//     config file itself.

export default {
  pointperfect: {
    callouts: [
      {
        beforeField: 'ntrip_username',
        text: 'PointPerfect corrections require a u-blox Thingstream account.',
        cta: 'Create an account',
        url: 'https://portal.thingstream.io/register?token=eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJjdG9rOmYzNGRkMTg2LWNjYWUtNDZhMS1hNWRmLWRiM2UxYjMwZWI5MCIsImF1ZCI6IlRoaW5nc3RyZWFtIiwiY21wIjoicmVkZW1wdGlvbi1jYW1wYWlnbjphZmViMmY4OS05MDMzLTQ1YjAtOGE4NC0wZjBhZGVjMzA3MWUifQ.Y0gn8ai-0eJ7LVs8k1uthvj7LM0WSXhefR70p3l6w6XWBD9mrO99NYdal1NS7wfi1DGyM21TMExaXUnFoxVYSA'
      }
    ]
  }
};
