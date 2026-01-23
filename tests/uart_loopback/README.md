# UART Loopback Test

Loopback test for Just a Jetson to test UART0 (`/dev/ttyTHS3`) and UART1 (`/dev/ttyTHS1`) wired together without flow control.

## Wiring

```
UART0 (ttyTHS3)          UART1 (ttyTHS1)
    TX  ─────────────────────  RX
    RX  ─────────────────────  TX
    GND ─────────────────────  GND
```

## Building

```bash
make        # Build
make clean  # Remove build directory
```

## Usage

```
Usage: ./build/uart_loopback_test [OPTIONS]

Options:
  -0 DEVICE    UART0 device (default: /dev/ttyTHS3)
  -1 DEVICE    UART1 device (default: /dev/ttyTHS1)
  -b BAUD      Test only this baud rate (57600, 115200, 921600)
  -d SECONDS   Test duration per baud rate (default: 10)
  -h           Show this help
```

Examples:
```bash
sudo ./build/uart_loopback_test              # Run full test suite
sudo ./build/uart_loopback_test -b 921600    # Test only 921600 baud
sudo ./build/uart_loopback_test -d 30        # 30 second test per baud rate
```

## How It Works

This test simulates a bidirectional MAVLink link by running four threads simultaneously:

1. **UART0 TX** - sends packets to UART1
2. **UART1 RX** - receives and validates packets from UART0
3. **UART1 TX** - sends packets to UART0
4. **UART0 RX** - receives and validates packets from UART1

This mirrors real-world usage where the flight controller sends telemetry while the companion computer sends setpoint commands.

### Bandwidth

Each direction targets 80% of the theoretical maximum throughput:

| Baud Rate | Max (8N1) | Target (80%) |
|-----------|-----------|--------------|
| 57600     | 5,760 B/s | 4,608 B/s    |
| 115200    | 11,520 B/s | 9,216 B/s   |
| 921600    | 92,160 B/s | 73,728 B/s  |

### Packet Structure

Each packet uses a structure similar to MAVLink:

```
[SEQ: 2 bytes][LEN: 2 bytes][PAYLOAD: 8-280 bytes][CRC16: 2 bytes]
```

- **SEQ** - 16-bit sequence number for detecting drops, duplicates, and reordering
- **LEN** - payload length
- **PAYLOAD** - random data (size varies to simulate real traffic)
- **CRC16** - CCITT checksum (same algorithm as MAVLink)

### Packet Size Distribution

Payload sizes are randomized to match typical MAVLink message distribution:

- **60%**: 8-50 bytes (heartbeat, attitude, GPS, etc.)
- **30%**: 50-150 bytes (param values, statustext, etc.)
- **10%**: 150-280 bytes (file transfer, logging, etc.)

MAVLink v2 maximum message size is 280 bytes, which this test covers.

### Error Detection

The test detects and reports:

- **CRC errors** - data corruption (computed CRC doesn't match received)
- **Sequence gaps** - dropped packets (missing sequence numbers)
- **Sequence duplicates** - repeated packets
- **Framing errors** - signal integrity issues (from kernel driver)
- **Overrun errors** - buffer overflow (from kernel driver)
- **Parity errors** - bit errors (from kernel driver)

### Kernel Error Monitoring

The test polls `/sys/class/tty/ttyTHS*/icount` during execution to capture hardware-level errors reported by the `tegra_hsuart` driver. These are the same errors that appear in `dmesg` during normal operation.
