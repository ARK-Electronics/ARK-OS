/**
 * UART Loopback Test
 *
 * Tests bidirectional UART communication between ttyTHS3 (UART0) and ttyTHS1 (UART1)
 * to diagnose data loss issues at high throughput.
 *
 * Wiring required: TX0<->RX1, TX1<->RX0, GND<->GND
 */

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <random>
#include <signal.h>
#include <sstream>
#include <string>
#include <termios.h>
#include <thread>
#include <unistd.h>
#include <vector>

// Packet structure:
// [SEQ_NUM: 2 bytes][LENGTH: 2 bytes][PAYLOAD: N bytes][CRC16: 2 bytes]
// Minimum packet size: 6 bytes (empty payload)
// Maximum packet size: 286 bytes (280 byte payload, like max MAVLink)

constexpr size_t PACKET_HEADER_SIZE = 4;  // seq + len
constexpr size_t PACKET_CRC_SIZE = 2;
constexpr size_t PACKET_OVERHEAD = PACKET_HEADER_SIZE + PACKET_CRC_SIZE;
constexpr size_t MIN_PAYLOAD_SIZE = 8;
constexpr size_t MAX_PAYLOAD_SIZE = 280;
constexpr size_t MAX_PACKET_SIZE = MAX_PAYLOAD_SIZE + PACKET_OVERHEAD;

// Test duration per baud rate
constexpr int TEST_DURATION_SECONDS = 10;

// Target bandwidth utilization
constexpr double TARGET_BANDWIDTH_PERCENT = 0.80;

std::atomic<bool> g_running{true};

void signal_handler(int) {
    g_running = false;
}

// CRC-16-CCITT (used by MAVLink)
uint16_t crc16_ccitt(const uint8_t* data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        uint8_t byte = data[i];
        byte ^= (crc & 0xFF);
        byte ^= (byte << 4);
        crc = (crc >> 8) ^ (static_cast<uint16_t>(byte) << 8) ^
              (static_cast<uint16_t>(byte) << 3) ^
              (static_cast<uint16_t>(byte) >> 4);
    }
    return crc;
}

struct PacketStats {
    std::atomic<uint64_t> packets_sent{0};
    std::atomic<uint64_t> packets_received{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> crc_errors{0};
    std::atomic<uint64_t> sequence_gaps{0};
    std::atomic<uint64_t> sequence_duplicates{0};
    std::atomic<uint64_t> parse_errors{0};     // Software packet parsing errors
    std::atomic<uint64_t> framing_errors{0};   // Hardware framing errors from kernel
    std::atomic<uint64_t> overrun_errors{0};   // Hardware overrun errors from kernel
    std::atomic<uint64_t> parity_errors{0};    // Hardware parity errors from kernel

    uint16_t last_seq_sent{0};
    uint16_t last_seq_received{0};
    uint16_t first_seq_received{0};
    bool first_packet{true};
    std::mutex seq_mutex;
    std::vector<uint16_t> missing_sequences;
};

struct KernelSerialStats {
    uint64_t frame{0};
    uint64_t overrun{0};
    uint64_t parity{0};
};

// Read kernel serial error statistics from sysfs
KernelSerialStats read_kernel_stats(const std::string& device) {
    KernelSerialStats stats;

    size_t pos = device.rfind('/');
    std::string tty_name = (pos != std::string::npos) ? device.substr(pos + 1) : device;

    std::string sysfs_path = "/sys/class/tty/" + tty_name + "/icount";
    std::ifstream sysfs(sysfs_path);
    if (sysfs.is_open()) {
        std::string line;
        while (std::getline(sysfs, line)) {
            std::istringstream iss(line);
            std::string key;
            uint64_t value;
            if (iss >> key >> value) {
                if (key == "frame:") stats.frame = value;
                else if (key == "overrun:") stats.overrun = value;
                else if (key == "parity:") stats.parity = value;
            }
        }
    }

    return stats;
}

class UartPort {
public:
    UartPort(const std::string& device, speed_t baud)
        : device_(device), baud_(baud), fd_(-1) {}

    ~UartPort() {
        close_port();
    }

    bool open_port() {
        fd_ = open(device_.c_str(), O_RDWR | O_NOCTTY);
        if (fd_ < 0) {
            std::cerr << "Failed to open " << device_ << ": " << strerror(errno) << std::endl;
            return false;
        }

        struct termios tty;
        memset(&tty, 0, sizeof(tty));

        if (tcgetattr(fd_, &tty) != 0) {
            std::cerr << "tcgetattr failed: " << strerror(errno) << std::endl;
            close_port();
            return false;
        }

        // Set baud rate
        cfsetospeed(&tty, baud_);
        cfsetispeed(&tty, baud_);

        // 8N1, no flow control
        tty.c_cflag &= ~PARENB;        // No parity
        tty.c_cflag &= ~CSTOPB;        // 1 stop bit
        tty.c_cflag &= ~CSIZE;
        tty.c_cflag |= CS8;            // 8 data bits
        tty.c_cflag &= ~CRTSCTS;       // No hardware flow control
        tty.c_cflag |= CREAD | CLOCAL; // Enable receiver, ignore modem controls

        // Raw input
        tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
        tty.c_iflag &= ~(IXON | IXOFF | IXANY); // No software flow control
        tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL);

        // Raw output
        tty.c_oflag &= ~OPOST;

        // Read settings: return immediately with whatever is available
        tty.c_cc[VMIN] = 0;
        tty.c_cc[VTIME] = 1; // 100ms timeout

        if (tcsetattr(fd_, TCSANOW, &tty) != 0) {
            std::cerr << "tcsetattr failed: " << strerror(errno) << std::endl;
            close_port();
            return false;
        }

        // Flush buffers
        tcflush(fd_, TCIOFLUSH);

        return true;
    }

    void close_port() {
        if (fd_ >= 0) {
            close(fd_);
            fd_ = -1;
        }
    }

    ssize_t write_bytes(const uint8_t* data, size_t len) {
        return write(fd_, data, len);
    }

    ssize_t read_bytes(uint8_t* buffer, size_t max_len) {
        return read(fd_, buffer, max_len);
    }

    const std::string& device() const { return device_; }

private:
    std::string device_;
    speed_t baud_;
    int fd_;
};

class PacketBuilder {
public:
    PacketBuilder() : seq_(0) {
        // Initialize random number generator
        std::random_device rd;
        rng_.seed(rd());

        // Pre-generate random payload data
        random_data_.resize(MAX_PAYLOAD_SIZE * 1024);
        for (auto& byte : random_data_) {
            byte = static_cast<uint8_t>(dist_(rng_));
        }
    }

    // Returns packet size and sets seq_out to the sequence number used
    size_t build_packet(uint8_t* buffer, size_t payload_size, uint16_t& seq_out) {
        if (payload_size > MAX_PAYLOAD_SIZE) {
            payload_size = MAX_PAYLOAD_SIZE;
        }

        uint16_t seq = seq_++;
        seq_out = seq;
        uint16_t len = static_cast<uint16_t>(payload_size);

        // Header
        buffer[0] = seq & 0xFF;
        buffer[1] = (seq >> 8) & 0xFF;
        buffer[2] = len & 0xFF;
        buffer[3] = (len >> 8) & 0xFF;

        // Payload (from pre-generated random data)
        size_t offset = (seq * 37) % (random_data_.size() - payload_size);
        memcpy(buffer + PACKET_HEADER_SIZE, random_data_.data() + offset, payload_size);

        // CRC (over header + payload)
        size_t data_len = PACKET_HEADER_SIZE + payload_size;
        uint16_t crc = crc16_ccitt(buffer, data_len);
        buffer[data_len] = crc & 0xFF;
        buffer[data_len + 1] = (crc >> 8) & 0xFF;

        return data_len + PACKET_CRC_SIZE;
    }

    size_t random_payload_size() {
        // Generate sizes similar to MAVLink message distribution
        // Most messages are 20-50 bytes, occasional larger ones
        int r = dist_(rng_) % 100;
        if (r < 60) {
            return MIN_PAYLOAD_SIZE + (dist_(rng_) % 42);  // 8-50 bytes
        } else if (r < 90) {
            return 50 + (dist_(rng_) % 100);  // 50-150 bytes
        } else {
            return 150 + (dist_(rng_) % 130); // 150-280 bytes
        }
    }

private:
    std::atomic<uint16_t> seq_;
    std::mt19937 rng_;
    std::uniform_int_distribution<int> dist_{0, 255};
    std::vector<uint8_t> random_data_;
};

class PacketParser {
public:
    PacketParser(PacketStats& stats) : stats_(stats), state_(State::HEADER), buffer_pos_(0), payload_len_(0) {}

    void process_bytes(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; i++) {
            process_byte(data[i]);
        }
    }

private:
    enum class State {
        HEADER,
        PAYLOAD,
        CRC
    };

    void process_byte(uint8_t byte) {
        buffer_[buffer_pos_++] = byte;

        switch (state_) {
            case State::HEADER:
                if (buffer_pos_ >= PACKET_HEADER_SIZE) {
                    payload_len_ = buffer_[2] | (buffer_[3] << 8);
                    if (payload_len_ > MAX_PAYLOAD_SIZE) {
                        // Invalid length, shift buffer and try to resync
                        memmove(buffer_, buffer_ + 1, buffer_pos_ - 1);
                        buffer_pos_--;
                        stats_.parse_errors++;
                    } else if (payload_len_ == 0) {
                        state_ = State::CRC;
                    } else {
                        state_ = State::PAYLOAD;
                    }
                }
                break;

            case State::PAYLOAD:
                if (buffer_pos_ >= PACKET_HEADER_SIZE + payload_len_) {
                    state_ = State::CRC;
                }
                break;

            case State::CRC:
                if (buffer_pos_ >= PACKET_HEADER_SIZE + payload_len_ + PACKET_CRC_SIZE) {
                    validate_packet();
                    buffer_pos_ = 0;
                    state_ = State::HEADER;
                }
                break;
        }
    }

    void validate_packet() {
        size_t data_len = PACKET_HEADER_SIZE + payload_len_;
        uint16_t received_crc = buffer_[data_len] | (buffer_[data_len + 1] << 8);
        uint16_t computed_crc = crc16_ccitt(buffer_, data_len);

        if (received_crc != computed_crc) {
            stats_.crc_errors++;
            return;
        }

        uint16_t seq = buffer_[0] | (buffer_[1] << 8);

        std::lock_guard<std::mutex> lock(stats_.seq_mutex);
        if (stats_.first_packet) {
            stats_.first_packet = false;
            stats_.first_seq_received = seq;
            stats_.last_seq_received = seq;
        } else {
            uint16_t expected = stats_.last_seq_received + 1;
            if (seq != expected) {
                if (seq == stats_.last_seq_received) {
                    stats_.sequence_duplicates++;
                } else {
                    // Calculate gap (handling wraparound)
                    uint16_t gap = seq - expected;
                    if (gap > 32768) {
                        // Likely a duplicate of an old packet
                        stats_.sequence_duplicates++;
                    } else {
                        stats_.sequence_gaps += gap;
                        // Record the missing sequence numbers (limit to first 100)
                        if (stats_.missing_sequences.size() < 100) {
                            for (uint16_t s = expected; s != seq; s++) {
                                stats_.missing_sequences.push_back(s);
                                if (stats_.missing_sequences.size() >= 100) break;
                            }
                        }
                    }
                }
            }
            stats_.last_seq_received = seq;
        }

        stats_.packets_received++;
        stats_.bytes_received += buffer_pos_;
    }

    PacketStats& stats_;
    State state_;
    uint8_t buffer_[MAX_PACKET_SIZE];
    size_t buffer_pos_;
    uint16_t payload_len_;
};

void sender_thread(UartPort& port, PacketStats& stats, int baud_rate, std::atomic<bool>& running) {
    PacketBuilder builder;
    uint8_t packet_buffer[MAX_PACKET_SIZE];

    // Calculate target bytes per second (80% of theoretical max)
    double bytes_per_sec = (baud_rate / 10.0) * TARGET_BANDWIDTH_PERCENT;
    auto start_time = std::chrono::steady_clock::now();
    uint64_t target_bytes_sent = 0;

    while (running && g_running) {
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - start_time).count();
        target_bytes_sent = static_cast<uint64_t>(elapsed * bytes_per_sec);

        // Send packets until we've sent enough
        while (stats.bytes_sent < target_bytes_sent && running && g_running) {
            size_t payload_size = builder.random_payload_size();
            uint16_t seq;
            size_t packet_len = builder.build_packet(packet_buffer, payload_size, seq);

            ssize_t written = port.write_bytes(packet_buffer, packet_len);
            if (written > 0) {
                stats.packets_sent++;
                stats.bytes_sent += written;
                stats.last_seq_sent = seq;
            } else if (written < 0 && errno != EAGAIN) {
                std::cerr << "Write error on " << port.device() << ": " << strerror(errno) << std::endl;
            }
        }

        // Small sleep to prevent busy-waiting
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
}

void receiver_thread(UartPort& port, PacketStats& stats, std::atomic<bool>& running) {
    PacketParser parser(stats);
    uint8_t read_buffer[1024];

    while (running && g_running) {
        ssize_t bytes_read = port.read_bytes(read_buffer, sizeof(read_buffer));
        if (bytes_read > 0) {
            parser.process_bytes(read_buffer, bytes_read);
        } else if (bytes_read < 0 && errno != EAGAIN) {
            std::cerr << "Read error on " << port.device() << ": " << strerror(errno) << std::endl;
        }
    }
}

void stats_monitor_thread(const std::string& dev0, const std::string& dev1,
                          PacketStats& stats0, PacketStats& stats1,
                          std::atomic<bool>& running) {
    KernelSerialStats prev0, prev1;

    while (running && g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        KernelSerialStats curr0 = read_kernel_stats(dev0);
        KernelSerialStats curr1 = read_kernel_stats(dev1);

        // Update error counts (delta from previous reading)
        stats0.framing_errors += (curr0.frame - prev0.frame);
        stats0.overrun_errors += (curr0.overrun - prev0.overrun);
        stats0.parity_errors += (curr0.parity - prev0.parity);

        stats1.framing_errors += (curr1.frame - prev1.frame);
        stats1.overrun_errors += (curr1.overrun - prev1.overrun);
        stats1.parity_errors += (curr1.parity - prev1.parity);

        prev0 = curr0;
        prev1 = curr1;
    }
}

int baud_to_int(speed_t baud) {
    switch (baud) {
        case B57600: return 57600;
        case B115200: return 115200;
        case B921600: return 921600;
        default: return 0;
    }
}

void print_stats(const std::string& name, const PacketStats& stats, double elapsed_sec) {
    double tx_rate = stats.bytes_sent / elapsed_sec;
    double rx_rate = stats.bytes_received / elapsed_sec;

    std::cout << "\n  " << name << ":" << std::endl;
    std::cout << "    Packets: sent=" << stats.packets_sent
              << ", received=" << stats.packets_received << std::endl;
    std::cout << "    Bytes: sent=" << stats.bytes_sent
              << ", received=" << stats.bytes_received << std::endl;
    std::cout << "    Rates: TX=" << std::fixed << std::setprecision(1)
              << tx_rate << " B/s, RX=" << rx_rate << " B/s" << std::endl;
    std::cout << "    Errors: CRC=" << stats.crc_errors
              << ", parse=" << stats.parse_errors
              << ", framing=" << stats.framing_errors
              << ", overrun=" << stats.overrun_errors
              << ", parity=" << stats.parity_errors << std::endl;
    std::cout << "    Sequence: first_rx=" << stats.first_seq_received
              << ", last_tx=" << stats.last_seq_sent
              << ", last_rx=" << stats.last_seq_received << std::endl;
    std::cout << "    Sequence: gaps=" << stats.sequence_gaps
              << ", duplicates=" << stats.sequence_duplicates << std::endl;

    // Check for missing packets at the tail (sent but never received)
    if (stats.packets_sent > 0 && stats.last_seq_sent != stats.last_seq_received) {
        uint16_t tail_missing = stats.last_seq_sent - stats.last_seq_received;
        if (tail_missing > 0 && tail_missing < 1000) {  // Sanity check
            std::cout << "    Tail loss: " << tail_missing << " packet(s) sent but not received (seq "
                      << (stats.last_seq_received + 1) << "-" << stats.last_seq_sent << ")" << std::endl;
        }
    }

    // Show missing sequences from mid-stream gaps
    if (!stats.missing_sequences.empty()) {
        std::cout << "    Missing seq: ";
        size_t show_count = std::min(stats.missing_sequences.size(), size_t(20));
        for (size_t i = 0; i < show_count; i++) {
            if (i > 0) std::cout << ", ";
            std::cout << stats.missing_sequences[i];
        }
        if (stats.missing_sequences.size() > 20) {
            std::cout << " ... (" << (stats.missing_sequences.size() - 20) << " more)";
        }
        std::cout << std::endl;
    }
}

bool run_test(const std::string& dev0, const std::string& dev1, speed_t baud, int duration_sec) {
    int baud_rate = baud_to_int(baud);
    std::cout << "\n========================================" << std::endl;
    std::cout << "Testing at " << baud_rate << " baud" << std::endl;
    std::cout << "========================================" << std::endl;

    UartPort port0(dev0, baud);
    UartPort port1(dev1, baud);

    if (!port0.open_port() || !port1.open_port()) {
        return false;
    }

    // Flush any stale data
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    uint8_t flush_buf[1024];
    while (port0.read_bytes(flush_buf, sizeof(flush_buf)) > 0) {}
    while (port1.read_bytes(flush_buf, sizeof(flush_buf)) > 0) {}

    // Stats tracked by direction:
    // stats_0to1: UART0 sends -> UART1 receives
    // stats_1to0: UART1 sends -> UART0 receives
    PacketStats stats_0to1, stats_1to0;
    std::atomic<bool> tx_running{true};
    std::atomic<bool> rx_running{true};

    // Get baseline kernel stats
    KernelSerialStats baseline0 = read_kernel_stats(dev0);
    KernelSerialStats baseline1 = read_kernel_stats(dev1);

    auto start_time = std::chrono::steady_clock::now();

    // Start threads - all 4 run simultaneously for bidirectional traffic
    std::thread tx0(sender_thread, std::ref(port0), std::ref(stats_0to1), baud_rate, std::ref(tx_running));
    std::thread rx1(receiver_thread, std::ref(port1), std::ref(stats_0to1), std::ref(rx_running));  // UART1 receives what UART0 sent
    std::thread tx1(sender_thread, std::ref(port1), std::ref(stats_1to0), baud_rate, std::ref(tx_running));
    std::thread rx0(receiver_thread, std::ref(port0), std::ref(stats_1to0), std::ref(rx_running));  // UART0 receives what UART1 sent
    std::thread monitor(stats_monitor_thread, dev0, dev1, std::ref(stats_0to1), std::ref(stats_1to0), std::ref(rx_running));

    std::cout << "Running for " << duration_sec << " seconds..." << std::endl;
    std::cout << "(Both directions running simultaneously)" << std::endl;

    // Progress display
    for (int i = 0; i < duration_sec && g_running; i++) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "  " << (i + 1) << "s: UART0->UART1 tx=" << stats_0to1.bytes_sent
                  << " rx=" << stats_0to1.bytes_received
                  << " | UART1->UART0 tx=" << stats_1to0.bytes_sent
                  << " rx=" << stats_1to0.bytes_received << std::endl;
    }

    // Stop senders first
    tx_running = false;
    tx0.join();
    tx1.join();

    // Wait for in-flight data to be received (worst case: full buffer at lowest baud)
    // At 57600 baud, 1024 bytes takes ~180ms. Add margin for processing.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Now stop receivers
    rx_running = false;
    rx0.join();
    rx1.join();
    monitor.join();

    auto end_time = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(end_time - start_time).count();

    // Get final kernel stats
    KernelSerialStats final0 = read_kernel_stats(dev0);
    KernelSerialStats final1 = read_kernel_stats(dev1);

    std::cout << "\n--- Results ---" << std::endl;
    print_stats("UART0 -> UART1", stats_0to1, elapsed);
    print_stats("UART1 -> UART0", stats_1to0, elapsed);

    // Kernel-level stats
    std::cout << "\n  Kernel error counters (delta):" << std::endl;
    std::cout << "    " << dev0 << ": frame=" << (final0.frame - baseline0.frame)
              << ", overrun=" << (final0.overrun - baseline0.overrun)
              << ", parity=" << (final0.parity - baseline0.parity) << std::endl;
    std::cout << "    " << dev1 << ": frame=" << (final1.frame - baseline1.frame)
              << ", overrun=" << (final1.overrun - baseline1.overrun)
              << ", parity=" << (final1.parity - baseline1.parity) << std::endl;

    // Summary
    uint64_t total_sent = stats_0to1.packets_sent + stats_1to0.packets_sent;
    uint64_t total_received = stats_0to1.packets_received + stats_1to0.packets_received;
    uint64_t total_errors = stats_0to1.crc_errors + stats_1to0.crc_errors +
                            stats_0to1.sequence_gaps + stats_1to0.sequence_gaps;

    double loss_rate = 0;
    if (total_sent > 0) {
        loss_rate = 100.0 * (total_sent - total_received) / total_sent;
    }

    std::cout << "\n  SUMMARY:" << std::endl;
    std::cout << "    Total packets: sent=" << total_sent << ", received=" << total_received << std::endl;
    std::cout << "    Packet loss: " << std::fixed << std::setprecision(2) << loss_rate << "%" << std::endl;
    std::cout << "    Total errors: " << total_errors << std::endl;

    bool passed = (total_errors == 0 && loss_rate < 1.0);
    std::cout << "    Status: " << (passed ? "PASS" : "FAIL") << std::endl;

    return passed;
}

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [OPTIONS]" << std::endl;
    std::cout << "\nOptions:" << std::endl;
    std::cout << "  -0 DEVICE    UART0 device (default: /dev/ttyTHS3)" << std::endl;
    std::cout << "  -1 DEVICE    UART1 device (default: /dev/ttyTHS1)" << std::endl;
    std::cout << "  -b BAUD      Test only this baud rate (57600, 115200, 921600)" << std::endl;
    std::cout << "  -d SECONDS   Test duration per baud rate (default: 10)" << std::endl;
    std::cout << "  -h           Show this help" << std::endl;
    std::cout << "\nWiring required:" << std::endl;
    std::cout << "  UART0 TX -> UART1 RX" << std::endl;
    std::cout << "  UART0 RX -> UART1 TX" << std::endl;
    std::cout << "  GND      -> GND" << std::endl;
}

int main(int argc, char* argv[]) {
    std::string dev0 = "/dev/ttyTHS3";
    std::string dev1 = "/dev/ttyTHS1";
    int single_baud = 0;
    int duration = TEST_DURATION_SECONDS;

    int opt;
    while ((opt = getopt(argc, argv, "0:1:b:d:h")) != -1) {
        switch (opt) {
            case '0':
                dev0 = optarg;
                break;
            case '1':
                dev1 = optarg;
                break;
            case 'b':
                single_baud = std::stoi(optarg);
                break;
            case 'd':
                duration = std::stoi(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    std::cout << "UART Loopback Test" << std::endl;
    std::cout << "==================" << std::endl;
    std::cout << "UART0: " << dev0 << std::endl;
    std::cout << "UART1: " << dev1 << std::endl;
    std::cout << "Target bandwidth: " << (TARGET_BANDWIDTH_PERCENT * 100) << "%" << std::endl;
    std::cout << "Test duration: " << duration << " seconds per baud rate" << std::endl;

    std::vector<speed_t> bauds;
    if (single_baud > 0) {
        switch (single_baud) {
            case 57600: bauds.push_back(B57600); break;
            case 115200: bauds.push_back(B115200); break;
            case 921600: bauds.push_back(B921600); break;
            default:
                std::cerr << "Invalid baud rate: " << single_baud << std::endl;
                return 1;
        }
    } else {
        bauds = {B57600, B115200, B921600};
    }

    int pass_count = 0;
    int total_tests = bauds.size();

    for (speed_t baud : bauds) {
        if (!g_running) break;
        if (run_test(dev0, dev1, baud, duration)) {
            pass_count++;
        }
        // Brief pause between tests
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    std::cout << "\n========================================" << std::endl;
    std::cout << "OVERALL: " << pass_count << "/" << total_tests << " tests passed" << std::endl;
    std::cout << "========================================" << std::endl;

    return (pass_count == total_tests) ? 0 : 1;
}
