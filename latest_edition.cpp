
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//
// This software includes the BIP-39 English word list (2048 words).
//
// copyright (c) 2013-2017
// Slush (Marek Palatinus)
// Pavol Rusnak
// and contributors
//
// Licensed under the MIT License.
//
// =================================================================================
//
// MIT License
//
// Copyright (c) 2026 oiko-nomikos
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// =================================================================================
//
// IMPORTANT SECURITY & LEGAL NOTICES
//
// This program contains independent, from-scratch re-implementations of the
// following cryptographic algorithms, based solely on their public specifications:
//
//   • AES (Advanced Encryption Standard) — NIST FIPS 197
//   • SHA-256                            — NIST FIPS 180-4
//   • HMAC                               — NIST FIPS 198
//   • PBKDF                              — NIST SP 800-132
//
// No third-party copyrighted code is included for these primitives.
// They are educational/reference implementations only.
//
// All other parts of this program — including:
//
//   • PBKDF-style key derivation (HKDF-like construction)
//   • Timing-based entropy collection & randomness pool
//   • HMAC wrapper logic
//   • File encryption/decryption wrapper
//   • Command-line interface & I/O
//
//   — are original work by oiko-nomikos.
//
// CRITICAL WARNING:
// ---------------------------------------------------------------------------------
// THIS IS NOT PRODUCTION-GRADE CRYPTOGRAPHY.
// These implementations have NOT been audited, formally verified, side-channel
// protected, or tested against real-world attacks.
// Using this code for anything security-sensitive (real passwords, real data,
// financial information, etc.) is extremely dangerous and strongly discouraged.
//
// Use only for learning, experimentation, or CTF-style challenges.
// For anything important, use well-audited libraries such as:
//   OpenSSL, libsodium, cryptography (Python), Bouncy Castle, etc.
//
// If you find a bug or weakness — please report it responsibly.
// ---------------------------------------------------------------------------------
//
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
// Standard Library Includes
//----------------------------------------------------------------------------------
// Core C++ Input / Output and String Handling
//----------------------------------------------------------------------------------
//#include <fstream>     // std::ifstream, std::ofstream — file I/O
//Houston, we have a problem!
#include <iomanip>     // std::setw, std::setprecision — formatted output
#include <iostream>    // std::cout, std::cin — console I/O
#include <sstream>     // std::stringstream — string formatting and parsing
#include <string>      // std::string — owning string type
#include <string_view> // std::string_view — non-owning string references (zero-copy)
//----------------------------------------------------------------------------------
// Containers and Data Structures
//----------------------------------------------------------------------------------
#include <algorithm>     // std::sort, std::find, std::min/max — container algorithms
#include <deque>         // std::deque — double-ended queue (entropy buffers, sliding windows)
#include <map>           // std::map — ordered key-value storage
#include <queue>         // std::queue — FIFO data structures
#include <set>           // std::set — ordered unique elements
#include <unordered_map> // std::unordered_map — hash-based key-value storage
#include <unordered_set> // std::unordered_set — hash-based unique values
#include <utility>       // std::pair, std::move — efficient value operations
#include <vector>        // std::vector — dynamic contiguous arrays
//----------------------------------------------------------------------------------
// Numeric and Math Utilities
//----------------------------------------------------------------------------------
#include <cmath>   // std::ceil, std::log2, std::abs — math functions
#include <cstdint> // uint8_t, uint32_t, etc. — fixed-width integer types
#include <cstdlib> // std::rand, std::srand, std::exit — general utilities
#include <ctime>   // std::time, time_t — time-based RNG seeding
#include <random>  // std::mt19937, std::random_device — modern RNG facilities
//----------------------------------------------------------------------------------
// Low-level Memory and Character Handling
//----------------------------------------------------------------------------------
#include <cctype>  // std::tolower, std::isdigit — character classification
#include <cstring> // std::memset, std::memcpy — raw memory operations
#include <locale>  // std::locale, std::toupper/lower — locale-aware text handling
//----------------------------------------------------------------------------------
// Multithreading and Synchronization
//----------------------------------------------------------------------------------
#include <atomic>             // std::atomic — lock-free thread-safe variables
#include <condition_variable> // std::condition_variable — thread signaling
#include <functional>         // std::function, lambdas — callable abstractions
#include <future>             // std::future, std::async, std::promise — async results
#include <mutex>              // std::mutex, std::lock_guard — mutual exclusion
#include <thread>             // std::thread, sleep utilities
//----------------------------------------------------------------------------------
// Timing and Delays
//----------------------------------------------------------------------------------
#include <chrono> // std::chrono::steady_clock, durations, time points
//----------------------------------------------------------------------------------
// Platform-Specific (Windows)
//----------------------------------------------------------------------------------
#include <windows.h> // WinAPI — console, sleep, system calls
#include <cstdio>    // std::snprintf — C-style formatted output
#include <conio.h>   // _kbhit(), _getch() — non-blocking keyboard input
//----------------------------------------------------------------------------------
// Networking, Crypto, and External Libraries
//----------------------------------------------------------------------------------
#include <curl/curl.h>       // libcurl — HTTP requests (APIs, exchanges)
#include <nlohmann/json.hpp> // JSON parsing and serialization
#include <openssl/hmac.h>    // HMAC (API authentication)
#include <openssl/sha.h>     // SHA-256 / SHA-512 hashing
#include <openssl/evp.h>     // High-level crypto + Base64 helpers
#include <openssl/buffer.h>  // OpenSSL buffer utilities
//----------------------------------------------------------------------------------
// Unix / POSIX Headers (Disabled)
//----------------------------------------------------------------------------------
// #include <termios.h>   // Terminal configuration (raw input mode)
// #include <unistd.h>    // POSIX API (read, sleep)
// #include <sys/ioctl.h> // Terminal window size and I/O control

//----------------------------------------------------------------------------------
// Type Aliases
//----------------------------------------------------------------------------------
using json = nlohmann::json; // Convenience alias for JSON objects

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

void enableANSI() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

#define APP_VERSION "0.1.0"

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

namespace fs = std::filesystem;

class FileSystem {
  public:
    // Base directories
    static inline const fs::path BASE_DIR = fs::path("C:/Users/rodom/OneDrive/Desktop/Projects/Trader");
    static inline const fs::path SUB_DIR = fs::path("C:/Users/rodom/OneDrive/Desktop/Projects");
    static inline const fs::path MISC_DIR = BASE_DIR / "misc_data";
    static inline const fs::path APP_DIR = BASE_DIR / "program_data";
    static inline const fs::path AUTHENTICATION_DIR = BASE_DIR / "authentication";
    static inline const fs::path SECRETS_DIR = SUB_DIR / "Secrets";

    // Asset paths
    static inline const fs::path path_1 = MISC_DIR / "cacert-2025-12-02.pem";
    static inline const fs::path path_2 = MISC_DIR / "GreenTile.png";
    static inline const fs::path path_3 = MISC_DIR / "RedTile.png";

    // App files (encrypted/decrypted)
    static inline const fs::path file_1 = APP_DIR / "btc_history.txt";
    static inline const fs::path file_2 = APP_DIR / "open_positions.txt";
    static inline const fs::path file_3 = APP_DIR / "calendar_pnl.txt";
    static inline const fs::path file_4 = APP_DIR / "twitter_config.txt"; // UNUSED
    static inline const fs::path file_5 = APP_DIR / "debug_file.log";
    static inline const fs::path file_6 = APP_DIR / "kraken_credentials.dat"; // UNUSED
    static inline const fs::path file_7 = APP_DIR / "qtable.csv";
    static inline const fs::path file_8 = APP_DIR / "trades.log";

    // Authentication files
    static inline const fs::path file_mnem = AUTHENTICATION_DIR / "mnemonic.dat";
    static inline const fs::path file_salt = AUTHENTICATION_DIR / "master.salt";

    // Secret files (never committed)
    static inline const fs::path file_kraken = SECRETS_DIR / "kraken_credentials.dat";
    static inline const fs::path file_twitter = SECRETS_DIR / "twitter_config.txt";

    // Initialize all directories and files
    static void initialize() {
        ensureDirectory(BASE_DIR);
        ensureDirectory(MISC_DIR);
        ensureDirectory(APP_DIR);
        ensureDirectory(AUTHENTICATION_DIR);
        ensureDirectory(SECRETS_DIR);

        ensureAppFiles();
    }

  private:
    // Ensure all app files exist
    static void ensureAppFiles() {
        ensureFileExists(file_1);
        ensureFileExists(file_2);
        ensureFileExists(file_3);
        ensureFileExists(file_4); // UNUSED
        ensureFileExists(file_5);
        ensureFileExists(file_6); // UNUSED
        ensureFileExists(file_7);
        ensureFileExists(file_8);
        // Note: file_mnem and file_salt are created automatically when needed
        // ...and used to Encrypt/Decrypt files 1 to 8
    }

    // Ensure a directory exists
    static void ensureDirectory(const fs::path &path) {
        if (!fs::exists(path)) {
            fs::create_directories(path);
        }
    }

    // Ensure a file exists
    static void ensureFileExists(const fs::path &path) {
        if (!fs::exists(path)) {
            std::ofstream file(path, std::ios::binary);
            if (!file) {
                throw std::runtime_error("Failed to create file: " + path.string());
            }
        }
    }
};

// Global Instance
FileSystem fileSystem;

// Directory Structure:
//
// C:/Users/rodom/OneDrive/Desktop/Projects/
// │
// ├── Trader/                                   (BASE_DIR)
// │   │
// │   ├── misc_data/                            (MISC_DIR)
// │   │   ├── cacert-2025-12-02.pem             (path_1)
// │   │   ├── GreenTile.png                     (path_2)
// │   │   └── RedTile.png                       (path_3)
// │   │
// │   ├── program_data/                         (APP_DIR)
// │   │   ├── btc_history.txt          (.enc)   (file_1) - Encrypted
// │   │   ├── open_positions.txt       (.enc)   (file_2) - Encrypted
// │   │   ├── calendar_pnl.txt         (.enc)   (file_3) - Encrypted
// │   │   ├── twitter_config.txt       (.enc)   (file_4) - Encrypted (UNUSED)
// │   │   ├── debug_file.log           (.enc)   (file_5) - Encrypted
// │   │   ├── kraken_credentials.dat   (.enc)   (file_6) - Encrypted (UNUSED)
// │   │   ├── qtable.csv               (.enc)   (file_7) - Encrypted
// │   │   └── trades.log               (.enc)   (file_8) - Encrypted
// │   │
// │   └── authentication/                       (AUTHENTICATION_DIR)
// │       ├── file_mnem.dat                     (file_mnem) - Mnemonic hash
// │       └── master.salt                       (file_salt) - Encryption salt
// │
// └── Secrets/                                  (SECRETS_DIR - NEVER COMMITTED)
//     ├── kraken_credentials.dat                (file_kraken) - Kraken API keys
//     └── twitter_config.txt                    (file_twitter) - Twitter API keys

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
// Trading related global variables
//----------------------------------------------------------------------------------

static constexpr uint64_t SATOSHIS = 100'000'000; // 1 coin = 100 million satoshis
static constexpr uint64_t CENTS = 100;            // 1 coin = 100 cents

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
// Blockchain related global variables
//----------------------------------------------------------------------------------

// Subsidy constants
const uint64_t INITIAL_SUBSIDY = 10 * SATOSHIS; // 10 coins in sats
const int HALVING_INTERVAL = 10;

// Constants
const uint64_t RECYCLE_COUNT = 5;
const uint64_t MAX_VALUE = UINT64_MAX;
const size_t MAX_BLOCK_SIZE = 1 * 1024 * 1024;
const size_t TRANSACTION_SIZE_ESTIMATE = 400;
const size_t MAX_TRANSACTIONS_PER_BLOCK = MAX_BLOCK_SIZE / TRANSACTION_SIZE_ESTIMATE;
const double TARGET_BLOCK_TIME = 60.0;
const int DIFFICULTY_ADJUSTMENT_INTERVAL = 10;
const uint64_t MAX_DIFFICULTY = 1000000000000000ULL;

uint64_t difficulty = 1'000'000; // global difficulty, 1 million

std::vector<double> blockTimes; // last 60 blocks times

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Logger {
  public:
    enum Level { LOG_INFO, LOG_WARNING, LOG_ERROR };

    Logger() = default;

    ~Logger() {
        if (logFile.is_open()) {
            logFile << getCurrentTime() << " [INFO]    === Logger shutdown ===\n";
            logFile.close();
        }
    }

    void setConsoleOutput(bool enabled) { printToConsole = enabled; }

    void runDebugger() {
        using clock = std::chrono::steady_clock;
        auto start = clock::now();

        bool runDebuggerFlag = false; // Default: skip debugger

        std::cout << "Do you want to run debugger? (y/n)";

        while (std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - start).count() < 3000) {
            if (_kbhit()) {            // Did the user press a key?
                char input = _getch(); // Read the keypress without waiting for Enter
                if (input == 'y' || input == 'Y') {
                    runDebuggerFlag = true; // Enable debugger
                }
                break; // Stop waiting after a keypress
            }
        }

        setConsoleOutput(runDebuggerFlag); // Enable or disable console logging
    }

    void log(const std::string &message, Level level = LOG_INFO) {
        std::lock_guard<std::mutex> lock(mutex_);

        ensureLogFileOpen();

        std::ostringstream ss;
        ss << getCurrentTime() << " ";

        switch (level) {
        case LOG_INFO:
            ss << "[INFO]    ";
            break;
        case LOG_WARNING:
            ss << "[WARNING] ";
            break;
        case LOG_ERROR:
            ss << "[ERROR]   ";
            break;
        }

        ss << message << "\n";
        std::string line = ss.str();

        logFile << line;
        logFile.flush();

        if (printToConsole) {
            std::cout << line;
        }
    }

    void info(const std::string &msg) { log(msg, LOG_INFO); }
    void warning(const std::string &msg) { log(msg, LOG_WARNING); }
    void error(const std::string &msg) { log(msg, LOG_ERROR); }

  private:
    void ensureLogFileOpen() {
        if (!logFile.is_open()) {
            logFile.open(fileSystem.file_5.string(), std::ios::out | std::ios::app);
            if (logFile.is_open()) {
                logFile << getCurrentTime() << " [INFO]    === Logger startup ===\n";
            } else {
                std::cerr << "FATAL: Could not open log file\n";
            }
        }
    }

    std::string getCurrentTime() const {
        auto now = std::chrono::system_clock::now();
        auto tt = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

        std::ostringstream ss;
        ss << std::put_time(std::localtime(&tt), "%Y-%m-%d %H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }

    std::ofstream logFile;
    std::mutex mutex_;
    bool printToConsole = true;
};

// Global Instance
inline Logger logger;

// Global Macros
#define LOG_INFO(msg) logger.info(msg)
#define LOG_WARNING(msg) logger.warning(msg)
#define LOG_ERROR(msg) logger.error(msg)

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

struct Parameters {
    enum class TradeType { BUY, SELL };
    enum class PriceFeedMode { ENTROPY, LIVE, API, REPLAY };
    enum class TradingPair { BTC_USD, BTC_GBP, BTC_EUR, BTC_CAD };
    enum class OrderType { LIMIT, MARKET };
    enum class Leverage { NONE, TWO_X, THREE_X, FIVE_X };
    enum class LadderOrderPurpose { OPEN, FILLED, CLOSE, BATCH, REBALANCE };

    struct TradingPairHash {
        size_t operator()(TradingPair p) const noexcept { return static_cast<size_t>(p); }
    };

    // ---- Constructors ----
    Parameters() = default;
    Parameters(TradingPair p) : pairSymbol(p) {}

    // ---- Trade-specific fields ----
    std::string uuid;
    std::vector<std::string> filledUuids;
    uint64_t openTime = 0; // timestamp when order was placed
    uint64_t filledTime = 0;
    uint64_t closedTime = 0;
    uint64_t price = 0;        // Cents
    uint64_t averagePrice = 0; // Cents
    int numOrders = 0;
    bool filled = false;
    bool closed = false;
    bool isLeverage = false;
    bool isLiquidated = false;
    bool isBatched = false;
    bool tweetOutput = false;
    uint64_t makerFeeRate = 25; // Basis points
    uint64_t takerFeeRate = 40; // Basis points
    LadderOrderPurpose purpose = LadderOrderPurpose::OPEN;
    uint64_t totalAmount = 0;      // cumulative BTC in satoshis for this batch
    uint64_t weightedPriceSum = 0; // sum(amount * price)
    uint64_t batchFloor = 0;
    uint64_t batchCeiling = 0;
    int ordersInBatch = 0; // count of individual orders added to this batch
    int BATCH_SIZE = 10;   // batch limit
    int buyIndex = 0;
    int sellIndex = 0;
    uint64_t fee = 0;      // fee paid in USD cents
    uint64_t deposit = 0;  // BTC received in satoshis (for buys)
    uint64_t withdraw = 0; // USD spent in cents (for buys)
    // ... other fields

    // ---- User defined variables ----
    double threshold = 0.5;       // Percentage
    double stopLossPercent = 1.5; // Percentage
    TradingPair pairSymbol = TradingPair::BTC_USD;
    TradeType type = TradeType::BUY;
    uint64_t amount = 10'000; // Satoshis
    uint64_t usdValue = 0;    // Cents
    OrderType orderType = OrderType::LIMIT;
    Leverage leverage = Leverage::NONE;
    uint64_t increment = 100'00; // Cents
    uint64_t period = 2;
    int delayHours = 8;
    int spotOrders = 10;
    int leveragedOrders = 20;
    PriceFeedMode priceFeedMode = PriceFeedMode::ENTROPY;
    int refreshRateMs = 30000;
    std::string currentExchange = "UNKNOWN";
    std::string currentPair = "UNKNOWN";

    // ---- Wallet balances ----
    uint64_t balanceBTC = 0;       // or 1,000,000 sats = 0.01 BTC
    uint64_t balanceUSD = 1000'00; // 1000.00 USD

    static std::unordered_map<TradingPair, Parameters, TradingPairHash> allConfigs;

    static Parameters &getConfig(TradingPair pair) { return allConfigs[pair]; }

    // ---- Initialize all pairs with identical defaults ----
    static void initializeDefaults() {
        Parameters defaultParams;
        defaultParams.threshold = 0.5;
        defaultParams.stopLossPercent = 1.5;
        defaultParams.type = TradeType::BUY;
        defaultParams.amount = 10'000;
        defaultParams.usdValue = 0;
        defaultParams.orderType = OrderType::LIMIT;
        defaultParams.leverage = Leverage::NONE;
        defaultParams.increment = 100'00;
        defaultParams.delayHours = 8;
        defaultParams.spotOrders = 20;
        defaultParams.makerFeeRate = 25;
        defaultParams.takerFeeRate = 40;
        defaultParams.priceFeedMode = PriceFeedMode::ENTROPY;
        defaultParams.refreshRateMs = 30000;

        // Copy defaults to all trading pairs
        allConfigs[TradingPair::BTC_USD] = defaultParams;
        allConfigs[TradingPair::BTC_USD].pairSymbol = TradingPair::BTC_USD;

        allConfigs[TradingPair::BTC_GBP] = defaultParams;
        allConfigs[TradingPair::BTC_GBP].pairSymbol = TradingPair::BTC_GBP;

        allConfigs[TradingPair::BTC_EUR] = defaultParams;
        allConfigs[TradingPair::BTC_EUR].pairSymbol = TradingPair::BTC_EUR;

        allConfigs[TradingPair::BTC_CAD] = defaultParams;
        allConfigs[TradingPair::BTC_CAD].pairSymbol = TradingPair::BTC_CAD;
    }

    // ---- JSON serialization ----
    std::string toJSON(const std::string &txid) const {
        std::ostringstream oss;
        oss << "{"
            << "\"txid\":\"" << txid << "\","
            << "\"pair_symbol\":\"" << tradingPairToString(pairSymbol) << "\","
            << "\"trade_type\":\"" << tradeTypeToString(type) << "\","
            << "\"amount\":" << amount << ","
            << "\"usdValue\":" << usdValue << ","
            << "\"order_type\":\"" << orderTypeToString(orderType) << "\","
            << "\"leverage\":\"" << leverageToString(leverage) << "\","
            << "\"increment\":" << increment << ","
            << "\"delay_hours\":" << delayHours << ","
            << "\"spot_orders\":" << spotOrders << ","
            << "\"threshold\":" << threshold << ","
            << "\"stop_loss_percent\":" << stopLossPercent << ","
            << "\"price_feed_mode\":\"" << priceFeedModeToString(priceFeedMode) << "\""
            << "}";
        return oss.str();
    }

    static double makerFeeToRate(double fee) {
        return fee; // already a decimal like 0.0025
    }

    static double takerFeeToRate(double fee) {
        return fee; // already a decimal like 0.0040
    }

    enum class KrakenInterval : uint64_t {
        M1 = 60,     // 1 minute
        M5 = 300,    // 5 minutes
        M15 = 900,   // 15 minutes
        M30 = 1800,  // 30 minutes
        H1 = 3600,   // 1 hour
        H4 = 14400,  // 4 hours
        D1 = 86400,  // 1 day
        W1 = 604800, // 1 week
        // add more if you need them
    };

    // Current selected interval for the chart
    KrakenInterval chartInterval = KrakenInterval::M1;

    uint64_t getPeriod() const {
        // refreshRateMs is how often you call addCandle() (in milliseconds)
        // Example: 1000 ms → one call per second
        uint64_t intervalSeconds = static_cast<uint64_t>(chartInterval);
        uint64_t ticksPerCandle = intervalSeconds * 1000 / refreshRateMs;

        // Safety: at least 1 tick per candle
        return (ticksPerCandle == 0) ? 1 : ticksPerCandle;
    }

    std::string getIntervalString() const {
        switch (chartInterval) {
        case KrakenInterval::M1:
            return "1m";
        case KrakenInterval::M5:
            return "5m";
        case KrakenInterval::M15:
            return "15m";
        case KrakenInterval::M30:
            return "30m";
        case KrakenInterval::H1:
            return "1h";
        case KrakenInterval::H4:
            return "4h";
        case KrakenInterval::D1:
            return "1d";
        case KrakenInterval::W1:
            return "1w";
        default:
            return "1m";
        }
    }

    static std::string orderTypeToString(OrderType type) {
        switch (type) {
        case OrderType::LIMIT:
            return "LIMIT";
        case OrderType::MARKET:
            return "MARKET";
        }
        return "UNKNOWN";
    }

    static std::string leverageToString(Leverage lev) {
        switch (lev) {
        case Leverage::NONE:
            return "1x";
        case Leverage::TWO_X:
            return "2x";
        case Leverage::THREE_X:
            return "3x";
        case Leverage::FIVE_X:
            return "5x";
        }
        return "UNKNOWN";
    }

    // ---- Utility conversion functions ----
    static std::string tradeTypeToString(TradeType type) {
        switch (type) {
        case TradeType::BUY:
            return "BUY";
        case TradeType::SELL:
            return "SELL";
        }
        return "UNKNOWN";
    }

    static std::string tradingPairToString(TradingPair pair) {
        switch (pair) {
        case TradingPair::BTC_USD:
            return "BTC-USD";
        case TradingPair::BTC_GBP:
            return "BTC-GBP";
        case TradingPair::BTC_EUR:
            return "BTC-EUR";
        case TradingPair::BTC_CAD:
            return "BTC-CAD";
        }
        return "UNKNOWN";
    }

    static std::string priceFeedModeToString(PriceFeedMode mode) {
        switch (mode) {
        case PriceFeedMode::ENTROPY:
            return "ENTROPY";
        case PriceFeedMode::LIVE:
            return "LIVE";
        case PriceFeedMode::API:
            return "API";
        case PriceFeedMode::REPLAY:
            return "REPLAY";
        }
        return "UNKNOWN";
    }

    static std::string ladderOrderPurposeToString(LadderOrderPurpose purpose) {
        switch (purpose) {
        case LadderOrderPurpose::OPEN:
            return "OPEN";
        case LadderOrderPurpose::CLOSE:
            return "CLOSE";
        case LadderOrderPurpose::BATCH:
            return "BATCH";
        case LadderOrderPurpose::REBALANCE:
            return "REBALANCE";
        }
        return "UNKNOWN";
    }

    static uint64_t updateFeesByVolume(Parameters &params, uint64_t volumeUSD, bool isMaker) {
        // volumeUSD is rolling 30-day USD volume
        // Fee rates are in basis points (bps) => 1 bps = 0.01%

        if (volumeUSD < 10'000) {             // <$10,000
            params.makerFeeRate = 25;         // 0.25%
            params.takerFeeRate = 40;         // 0.40%
        } else if (volumeUSD < 50'000) {      // $10,000 - $49,999.99
            params.makerFeeRate = 20;         // 0.20%
            params.takerFeeRate = 35;         // 0.35%
        } else if (volumeUSD < 100'000) {     // $50,000 - $99,999.99
            params.makerFeeRate = 14;         // 0.14%
            params.takerFeeRate = 24;         // 0.24%
        } else if (volumeUSD < 250'000) {     // $100,000 - $249,999.99
            params.makerFeeRate = 12;         // 0.12%
            params.takerFeeRate = 22;         // 0.22%
        } else if (volumeUSD < 500'000) {     // $250,000 - $499,999.99
            params.makerFeeRate = 10;         // 0.10%
            params.takerFeeRate = 20;         // 0.20%
        } else if (volumeUSD < 1'000'000) {   // $500,000 - $999,999.99
            params.makerFeeRate = 8;          // 0.08%
            params.takerFeeRate = 18;         // 0.18%
        } else if (volumeUSD < 2'500'000) {   // $1,000,000 - $2,499,999.99
            params.makerFeeRate = 6;          // 0.06%
            params.takerFeeRate = 16;         // 0.16%
        } else if (volumeUSD < 5'000'000) {   // $2,500,000 - $4,999,999.99
            params.makerFeeRate = 4;          // 0.04%
            params.takerFeeRate = 14;         // 0.14%
        } else if (volumeUSD < 10'000'000) {  // $5,000,000 - $9,999,999.99
            params.makerFeeRate = 2;          // 0.02%
            params.takerFeeRate = 12;         // 0.12%
        } else if (volumeUSD < 100'000'000) { // $10,000,000 - $99,999,999.99
            params.makerFeeRate = 0;          // 0.00%
            params.takerFeeRate = 10;         // 0.10%
        } else if (volumeUSD < 500'000'000) { // $100,000,000 - $499,999,999.99
            params.makerFeeRate = 0;          // 0.00%
            params.takerFeeRate = 8;          // 0.08%
        } else {                              // $500,000,000+
            params.makerFeeRate = 0;          // 0.00%
            params.takerFeeRate = 5;          // 0.05%
        }

        // Return the fee for this order type
        return isMaker ? params.makerFeeRate : params.takerFeeRate;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

std::unordered_map<Parameters::TradingPair, Parameters, Parameters::TradingPairHash> Parameters::allConfigs;

using TradeType = Parameters::TradeType;
using PriceFeedMode = Parameters::PriceFeedMode;
using TradingPair = Parameters::TradingPair;
using OrderType = Parameters::OrderType;
using Leverage = Parameters::Leverage;
using LadderOrderPurpose = Parameters::LadderOrderPurpose;

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

struct OpenPositions {
    std::vector<Parameters> buys;
    std::vector<Parameters> sells;

    OpenPositions() {
        buys.reserve(60);
        sells.reserve(60);
    }
};

struct FilledPositions {
    std::vector<Parameters> buys;
    std::vector<Parameters> sells;
    std::vector<Parameters> batchedBuys;
    std::vector<Parameters> batchedSells;

    FilledPositions() {
        buys.reserve(60);
        sells.reserve(60);
        batchedBuys.reserve(200);
        batchedSells.reserve(200);
    }
};

struct ClosedPositions {
    std::vector<Parameters> buys;
    std::vector<Parameters> sells;

    ClosedPositions() {
        buys.reserve(200);
        sells.reserve(200);
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class SaveTradeState {
  public:
    void saveOpenPositions(const std::string &filename, const FilledPositions &fp, const Parameters &params) {
        std::ofstream file(filename, std::ios::out | std::ios::trunc);
        if (!file.is_open())
            return;

        file << "# OPEN POSITIONS SNAPSHOT\n";
        file << "# version=2\n\n";

        // ---- GLOBAL ACCOUNT STATE ----
        file << "BEGIN_GLOBAL\n";
        file << "balance_btc=" << params.balanceBTC << "\n";
        file << "balance_usd=" << params.balanceUSD << "\n";
        file << "END_GLOBAL\n\n";

        auto writeOrder = [&](const Parameters &o, const std::string &tag) {
            file << "BEGIN " << tag << "\n";
            file << "uuid=" << o.uuid << "\n";
            file << "type=" << (o.type == Parameters::TradeType::BUY ? "BUY" : "SELL") << "\n";
            file << "purpose=" << static_cast<int>(o.purpose) << "\n";
            file << "price=" << o.price << "\n";
            file << "avg_price=" << o.averagePrice << "\n";
            file << "amount=" << o.amount << "\n";
            file << "usd_value=" << o.usdValue << "\n";
            file << "fee=" << o.fee << "\n";
            file << "deposit=" << o.deposit << "\n";
            file << "withdraw=" << o.withdraw << "\n";
            file << "open_time=" << o.openTime << "\n";
            file << "filled_time=" << o.filledTime << "\n";

            file << "filled_uuids=";
            for (size_t i = 0; i < o.filledUuids.size(); ++i) {
                if (i)
                    file << ",";
                file << o.filledUuids[i];
            }
            file << "\nEND\n\n";
        };

        for (const auto &o : fp.buys)
            writeOrder(o, "BUY");
        for (const auto &o : fp.sells)
            writeOrder(o, "SELL");
        for (const auto &o : fp.batchedBuys)
            writeOrder(o, "BATCH_BUY");
        for (const auto &o : fp.batchedSells)
            writeOrder(o, "BATCH_SELL");
    }

    void loadOpenPositions(const std::string &filename, FilledPositions &fp, Parameters &params) {
        std::ifstream file(filename);
        if (!file.is_open())
            return;

        fp = FilledPositions();

        Parameters current;
        std::string line, mode;

        bool inGlobal = false;

        while (std::getline(file, line)) {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();

            if (line == "BEGIN_GLOBAL") {
                inGlobal = true;
                continue;
            }

            if (line == "END_GLOBAL") {
                inGlobal = false;
                continue;
            }

            if (inGlobal) {
                auto pos = line.find('=');
                if (pos == std::string::npos)
                    continue;

                std::string key = line.substr(0, pos);
                std::string val = line.substr(pos + 1);

                if (key == "balance_btc")
                    params.balanceBTC = std::stoull(val);
                else if (key == "balance_usd")
                    params.balanceUSD = std::stoull(val);

                continue;
            }

            if (line.rfind("BEGIN", 0) == 0) {
                current = Parameters{};
                mode = line.substr(6);
                continue;
            }

            if (line == "END") {
                current.filled = true;
                current.closed = false;

                if (mode == "BUY")
                    fp.buys.push_back(current);
                else if (mode == "SELL")
                    fp.sells.push_back(current);
                else if (mode == "BATCH_BUY")
                    fp.batchedBuys.push_back(current);
                else if (mode == "BATCH_SELL")
                    fp.batchedSells.push_back(current);

                continue;
            }

            auto pos = line.find('=');
            if (pos == std::string::npos)
                continue;

            std::string key = line.substr(0, pos);
            std::string val = line.substr(pos + 1);

            if (key == "uuid")
                current.uuid = val;
            else if (key == "price")
                current.price = std::stoull(val);
            else if (key == "avg_price")
                current.averagePrice = std::stoull(val);
            else if (key == "amount")
                current.amount = std::stoull(val);
            else if (key == "usd_value")
                current.usdValue = std::stoull(val);
            else if (key == "fee")
                current.fee = std::stoull(val);
            else if (key == "deposit")
                current.deposit = std::stoull(val);
            else if (key == "withdraw")
                current.withdraw = std::stoull(val);
            else if (key == "open_time")
                current.openTime = std::stoull(val);
            else if (key == "filled_time")
                current.filledTime = std::stoull(val);
            else if (key == "filled_uuids") {
                std::stringstream ss(val);
                std::string id;
                while (std::getline(ss, id, ','))
                    current.filledUuids.push_back(id);
            }
        }
    }
};

// Global Instance
inline SaveTradeState saveTradeState;

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Render {
  public:
    enum class Align { LEFT, CENTER, RIGHT };

    struct Line {
        std::string text;
        Align alignment;
    };

    // NEW: buffer that stores lines in order
    void pushLine(const std::string &txt, Align a = Align::LEFT) { bufferedLines.push_back({txt, a}); }

    // NEW: move buffered lines into a column
    void flushToColumn(std::vector<Line> &column) {
        column.insert(column.end(), bufferedLines.begin(), bufferedLines.end());
        bufferedLines.clear();
    }

    std::string printColumns(const std::vector<std::vector<Line>> &columns, int colWidth = 0, int spacing = 0, int padding = 0) const {
        std::ostringstream oss;

        int consoleWidth = getConsoleWidth();
        int numCols = columns.size();

        int totalWidth = numCols * colWidth + (numCols - 1) * spacing + padding * 2;
        int leftMargin = std::max(0, (consoleWidth - totalWidth) / 2);
        std::string leftPad(leftMargin, ' ');

        // WRAPPING
        std::vector<std::vector<std::string>> wrappedText(columns.size());
        std::vector<std::vector<Align>> wrappedAlign(columns.size());

        for (size_t c = 0; c < columns.size(); ++c) {
            for (const auto &ln : columns[c]) {
                // Empty line
                if (ln.text.find_first_not_of(" \t\r\n") == std::string::npos) {
                    wrappedText[c].push_back("");
                    wrappedAlign[c].push_back(ln.alignment);
                    continue;
                }

                // Fits in one line
                if (ln.text.size() <= (size_t)colWidth) {
                    wrappedText[c].push_back(ln.text);
                    wrappedAlign[c].push_back(ln.alignment);
                    continue;
                }

                // Wrap long text
                std::istringstream iss(ln.text);
                std::string word, current;

                while (iss >> word) {
                    if (current.empty()) {
                        current = word;
                    } else if (current.size() + 1 + word.size() <= (size_t)colWidth) {
                        current += " " + word;
                    } else {
                        wrappedText[c].push_back(current);
                        wrappedAlign[c].push_back(ln.alignment);
                        current = word;
                    }
                }

                if (!current.empty()) {
                    wrappedText[c].push_back(current);
                    wrappedAlign[c].push_back(ln.alignment);
                }
            }
        }

        // Find max height
        size_t maxLines = 0;
        for (auto &col : wrappedText)
            maxLines = std::max(maxLines, col.size());

        // Print
        for (size_t i = 0; i < maxLines; i++) {
            oss << leftPad;
            for (size_t c = 0; c < wrappedText.size(); c++) {
                std::string text = "";
                Align a = Align::LEFT;
                if (i < wrappedText[c].size()) {
                    text = wrappedText[c][i];
                    a = wrappedAlign[c][i];
                }
                oss << alignFragment(text, a, colWidth);
                if (c < wrappedText.size() - 1)
                    oss << std::string(spacing, ' ');
            }
            oss << "\n";
        }

        return oss.str();
    }

    std::string printHeaderColumns(const std::vector<std::vector<Line>> &columns) const { return printColumns(columns, 82, 0, 0); }
    std::string printMenuColumns(const std::vector<std::vector<Line>> &columns) const { return printColumns(columns, 41, 0, 0); }
    std::string printBodyColumns(const std::vector<std::vector<Line>> &columns) const { return printColumns(columns, 80, 2, 0); }
    std::string printIndicatorColumns(const std::vector<std::vector<Line>> &columns) const { return printColumns(columns, 30, 2, 0); }
    std::string printFooterColumns(const std::vector<std::vector<Line>> &columns) const { return printColumns(columns, 82, 0, 0); }
    std::string printCalendar(const std::vector<std::vector<Line>> &columns) const { return printColumns(columns, 246, 0, 0); }

    void addEmptyLines(std::vector<Line> &col, int n) {
        for (int i = 0; i < n; ++i) {
            col.push_back({"", Align::CENTER});
        }
    }

  private:
    std::vector<Line> bufferedLines;

    // align one wrapped fragment to EXACT width
    std::string alignFragment(const std::string &txt, Align a, int width) const {
        int len = txt.size();
        if (len >= width)
            return txt.substr(0, width);

        int space = width - len;

        switch (a) {
        case Align::LEFT:
            return txt + std::string(space, ' ');
        case Align::RIGHT:
            return std::string(space, ' ') + txt;
        case Align::CENTER: {
            int left = space / 2;
            int right = space - left;
            return std::string(left, ' ') + txt + std::string(right, ' ');
        }
        }
        return txt; // fallback
    }

    int getConsoleWidth() const {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
        return csbi.srWindow.Right - csbi.srWindow.Left + 1;
    }
};

using Line = Render::Line;
using Align = Render::Align;

// Persistent shared columns — used by ALL classes
std::vector<Line> bodyCol1;
std::vector<Line> bodyCol2;
std::vector<Line> bodyCol3;

std::vector<Line> col1;
std::vector<Line> col2;
std::vector<Line> col3;

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Functions {
  public:
    void clearConsole() {
        system("cls"); // Windows-only
    }

    inline void clearScreen() { std::cout << "\033[2J\033[1;1H"; }

    int getConsoleWidth() const {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
        return csbi.srWindow.Right - csbi.srWindow.Left + 1;
    }

    inline int getTerminalWidth() {
        int width = 80; // fallback
        return width;
    }

    inline void separator() {
        int termWidth = getTerminalWidth();
        for (int i = 0; i < termWidth; ++i)
            std::cout << '-';
        std::cout << std::endl;
    }

    inline std::string separatorBuffer() {
        int termWidth = getTerminalWidth();
        return std::string(termWidth, '-');
    }

    inline void selectOption() {
        separator();
        std::cout << "Select an option: ";
    }

    // Use only for Unix (mobile), not on windows machine
    inline void printCentered(const std::string &text, int width = 80) {
        int padding = (width - text.length()) / 2;
        if (padding > 0) {
            std::cout << std::string(padding, ' ') << text << std::endl;
        } else {
            std::cout << text << std::endl;
        }
    }

    // Works for windows machine
    inline std::string getCenteredString(const std::string &text, int width = 80) {
        int padding = (width - static_cast<int>(text.length())) / 2;
        if (padding > 0)
            return std::string(padding, ' ') + text;
        return text;
    }

    inline void pause() {
        std::cout << "Press enter to continue...";
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get();
    }

    // Convert first 16 hex chars to uint64_t
    inline uint64_t hexToUint64(const std::string &hexStr) {
        uint64_t value = 0;
        std::stringstream ss;
        ss << std::hex << hexStr;
        ss >> value;
        return value;
    }

    inline uint64_t hashToUint60(const std::string &hexHash) {
        // Take the first 15 hex characters = 60 bits
        std::string truncated = hexHash.substr(0, 15);
        uint64_t value = 0;
        std::stringstream ss;
        ss << std::hex << truncated;
        ss >> value;
        return value;
    }

    inline uint64_t messageToUint60(const std::string &message) {
        uint64_t value = 0;
        for (char c : message) {
            value = (value << 4) | (c & 0xF); // take only 4 bits per char to fit 60-bit max
        }
        return value;
    }

    inline static uint64_t extractTimestamp(const std::string &txid) {
        std::string tsStr;
        for (size_t i = 0; i < 15 && i < txid.size(); ++i) {
            if (txid[i] != '-')
                tsStr += txid[i];
        }
        return std::stoull(tsStr);
    }

    inline std::string formatDouble(double value) const {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2) << value;

        std::string s = ss.str();
        // Optional: insert commas for integer part
        size_t dot_pos = s.find('.');
        if (dot_pos == std::string::npos)
            dot_pos = s.length();

        int pos = dot_pos - 3;
        while (pos > 0) {
            s.insert(pos, ",");
            pos -= 3;
        }

        return s;
    }

    inline std::string formatExchangeRateDouble(double value) const {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(5) << value;

        std::string s = ss.str();
        // Optional: insert commas for integer part
        size_t dot_pos = s.find('.');
        if (dot_pos == std::string::npos)
            dot_pos = s.length();

        int pos = dot_pos - 3;
        while (pos > 0) {
            s.insert(pos, ",");
            pos -= 3;
        }

        return s;
    }

    inline std::string formatExchangeRateInt(uint64_t value) const {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2) << (static_cast<double>(value) / CENTS);
        std::string s = ss.str();

        // Find the position of the decimal point
        size_t dot_pos = s.find('.');
        if (dot_pos == std::string::npos) {
            dot_pos = s.length();
        }

        // Insert commas every 3 digits in the integer part
        int pos = dot_pos - 3;
        while (pos > 0) {
            s.insert(pos, ",");
            pos -= 3;
        }

        return s;
    }

    inline std::string formatIntUSD(uint64_t value) const {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2) << (static_cast<double>(value) / CENTS);
        std::string s = ss.str();

        // Find the position of the decimal point
        size_t dot_pos = s.find('.');
        if (dot_pos == std::string::npos) {
            dot_pos = s.length();
        }

        // Insert commas every 3 digits in the integer part
        int pos = dot_pos - 3;
        while (pos > 0) {
            s.insert(pos, ",");
            pos -= 3;
        }

        return s;
    }

    inline std::string formatIntBTC(uint64_t value) const {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(8) << (static_cast<double>(value) / SATOSHIS);
        std::string s = ss.str();

        // Find the position of the decimal point
        size_t dot_pos = s.find('.');
        if (dot_pos == std::string::npos) {
            dot_pos = s.length();
        }

        // Insert commas every 3 digits in the integer part
        int pos = dot_pos - 3;
        while (pos > 0) {
            s.insert(pos, ",");
            pos -= 3;
        }

        return s;
    }

    // USD version for double (already in dollars)
    inline std::string formatDoubleUSD(double value) const {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2) << value;
        std::string s = ss.str();

        size_t dot_pos = s.find('.');
        if (dot_pos == std::string::npos)
            dot_pos = s.length();

        int pos = dot_pos - 3;
        while (pos > 0) {
            s.insert(pos, ",");
            pos -= 3;
        }

        return s;
    }

    // BTC version for double (already in BTC)
    inline std::string formatDoubleBTC(double value) const {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(8) << value;
        std::string s = ss.str();

        size_t dot_pos = s.find('.');
        if (dot_pos == std::string::npos)
            dot_pos = s.length();

        int pos = dot_pos - 3;
        while (pos > 0) {
            s.insert(pos, ",");
            pos -= 3;
        }

        return s;
    }

    // Format a price difference in USD (delta) without any sign
    inline std::string formatDelta(int64_t delta) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2) << std::abs(delta) / 100.0;
        return oss.str();
    }

    // Format a percentage without any sign
    inline std::string formatPercentage(double pct) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2) << std::abs(pct) << "%";
        return oss.str();
    }

    // Format leverage nicely
    inline std::string formatLeverage(double lev) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2) << lev << "×";
        return oss.str();
    }

    inline std::string formatFeeRate(double feeRate) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(4) << feeRate << "%";
        return oss.str();
    }

    inline std::string formatTimestamp(uint64_t ms) const {
        if (ms == 0)
            return "";

        std::chrono::milliseconds dur(ms);
        std::chrono::system_clock::time_point tp(dur);

        std::time_t tt = std::chrono::system_clock::to_time_t(tp);
        std::tm *tm = std::localtime(&tt);

        char buffer[20];
        // Original: "%d/%m/%Y %H:%M:%S"
        std::strftime(buffer, sizeof(buffer), " - %H:%M:%S", tm); // day/month/year removed

        // Milliseconds part
        int milli = ms % 1000;

        char finalBuf[30];
        std::snprintf(finalBuf, sizeof(finalBuf), "%s.%03d", buffer, milli);

        return std::string(finalBuf);
    }

    std::string formatWithCommas(long long value) {
        std::string num = std::to_string(value);
        int insertPosition = static_cast<int>(num.length()) - 3;
        while (insertPosition > 0) {
            num.insert(insertPosition, ",");
            insertPosition -= 3;
        }
        return num;
    }

    inline std::string getTodayDate() {
        std::time_t t = std::time(nullptr);
        std::tm *now = std::localtime(&t);
        char buffer[11];
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%d", now);
        return std::string(buffer);
    }

    inline std::string getTimeDate() {
        std::time_t t = std::time(nullptr);
        std::tm *now = std::localtime(&t);
        char buffer[20]; // 19 chars + 1 null terminator
        std::strftime(buffer, sizeof(buffer), "%d/%m/%Y %H:%M:%S", now);
        return std::string(buffer);
    }

    // At top of file or in a utils header
    static std::string timestampToReadable(uint64_t ts) {
        auto timePoint = std::chrono::time_point<std::chrono::system_clock>(std::chrono::seconds(ts));
        auto tt = std::chrono::system_clock::to_time_t(timePoint);

        std::ostringstream ss;
        ss << std::put_time(std::gmtime(&tt), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    // Progress bar (simple)
    void printProgressBar(int current, int total, int width = 50) const {
        double progress = static_cast<double>(current) / static_cast<double>(total);
        int filled = static_cast<int>(std::round(progress * width));

        std::cout << "\r[";
        for (int i = 0; i < filled; ++i)
            std::cout << "#";
        for (int i = filled; i < width; ++i)
            std::cout << " ";
        std::cout << "] " << std::setw(3) << static_cast<int>(progress * 100) << "%";
        std::cout.flush(); // Force immediate output
    }

    std::string makeProgressBar(int current, int total, int width = 50) const {
        double progress = static_cast<double>(current) / total;
        int filled = static_cast<int>(std::round(progress * width));

        std::ostringstream oss;
        oss << "[";
        for (int i = 0; i < filled; ++i)
            oss << "#";
        for (int i = filled; i < width; ++i)
            oss << " ";
        oss << "] " << std::setw(3) << int(progress * 100) << "%";

        return oss.str();
    }

    void updateProgress(int current, int total) {
        col2.clear(); // overwrite previous bar
        col2.push_back({makeProgressBar(current, total), Align::CENTER});
        print();
    }

    void clearBodyColumns() {
        bodyCol1.clear();
        bodyCol2.clear();
        bodyCol3.clear();
        clearConsole();
    }

    void clearColumns() {
        col1.clear();
        col2.clear();
        col3.clear();
        clearConsole();
    }

    void print() {
        Render render;
        std::vector<std::vector<Line>> columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4);
    }
};

// Global Instance
inline Functions functions;

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class SystemClock {
  public:
    inline long long getSeconds() {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    }

    inline long long getMilliseconds() {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    }

    inline long long getMicroseconds() {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    }

    inline long long getNanoseconds() {
        auto now = std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
    }
};

// Global Instance
inline SystemClock systemClock;

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class ColourCodes {
  public:
    void setOrange() const {
        std::cout << "\033[38;5;208m"; // Orange
    }

    void setGreen() const { std::cout << "\033[38;5;46m"; }
    void setRed() const {
        std::cout << "\033[38;5;196m"; // Bright red for SELL
    }

    void resetColor() const {
        std::cout << "\033[0m"; // Reset to default terminal colors
    }
};

const std::string GREEN = "\033[38;5;46m";
const std::string RED = "\033[38;5;196m";
const std::string ORANGE = "\033[38;5;208m";
const std::string RESET = "\033[0m";

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class WordListManager {
  public:
    WordListManager() = default;
    WordListManager(const std::vector<std::string> &wordList) : wordList_(wordList) {}

    std::vector<std::string> getWordList() const { return wordList_; }

  private:
    std::vector<std::string> wordList_ = {
        "abandon",  "ability",  "able",     "about",    "above",    "absent",   "absorb",   "abstract", "absurd",   "abuse",    "access",   "accident", "account",  "accuse",
        "achieve",  "acid",     "acoustic", "acquire",  "across",   "act",      "action",   "actor",    "actress",  "actual",   "adapt",    "add",      "addict",   "address",
        "adjust",   "admit",    "adult",    "advance",  "advice",   "aerobic",  "affair",   "afford",   "afraid",   "again",    "age",      "agent",    "agree",    "ahead",
        "aim",      "air",      "airport",  "aisle",    "alarm",    "album",    "alcohol",  "alert",    "alien",    "all",      "alley",    "allow",    "almost",   "alone",
        "alpha",    "already",  "also",     "alter",    "always",   "amateur",  "amazing",  "among",    "amount",   "amused",   "analyst",  "anchor",   "ancient",  "anger",
        "angle",    "angry",    "animal",   "ankle",    "announce", "annual",   "another",  "answer",   "antenna",  "antique",  "anxiety",  "any",      "apart",    "apology",
        "appear",   "apple",    "approve",  "april",    "arch",     "arctic",   "area",     "arena",    "argue",    "arm",      "armed",    "armor",    "army",     "around",
        "arrange",  "arrest",   "arrive",   "arrow",    "art",      "artefact", "artist",   "artwork",  "ask",      "aspect",   "assault",  "asset",    "assist",   "assume",
        "asthma",   "athlete",  "atom",     "attack",   "attend",   "attitude", "attract",  "auction",  "audit",    "august",   "aunt",     "author",   "auto",     "autumn",
        "average",  "avocado",  "avoid",    "awake",    "aware",    "away",     "awesome",  "awful",    "awkward",  "axis",     "baby",     "bachelor", "bacon",    "badge",
        "bag",      "balance",  "balcony",  "ball",     "bamboo",   "banana",   "banner",   "bar",      "barely",   "bargain",  "barrel",   "base",     "basic",    "basket",
        "battle",   "beach",    "bean",     "beauty",   "because",  "become",   "beef",     "before",   "begin",    "behave",   "behind",   "believe",  "below",    "belt",
        "bench",    "benefit",  "best",     "betray",   "better",   "between",  "beyond",   "bicycle",  "bid",      "bike",     "bind",     "biology",  "bird",     "birth",
        "bitter",   "black",    "blade",    "blame",    "blanket",  "blast",    "bleak",    "bless",    "blind",    "blood",    "blossom",  "blouse",   "blue",     "blur",
        "blush",    "board",    "boat",     "body",     "boil",     "bomb",     "bone",     "bonus",    "book",     "boost",    "border",   "boring",   "borrow",   "boss",
        "bottom",   "bounce",   "box",      "boy",      "bracket",  "brain",    "brand",    "brass",    "brave",    "bread",    "breeze",   "brick",    "bridge",   "brief",
        "bright",   "bring",    "brisk",    "broccoli", "broken",   "bronze",   "broom",    "brother",  "brown",    "brush",    "bubble",   "buddy",    "budget",   "buffalo",
        "build",    "bulb",     "bulk",     "bullet",   "bundle",   "bunker",   "burden",   "burger",   "burst",    "bus",      "business", "busy",     "butter",   "buyer",
        "buzz",     "cabbage",  "cabin",    "cable",    "cactus",   "cage",     "cake",     "call",     "calm",     "camera",   "camp",     "can",      "canal",    "cancel",
        "candy",    "cannon",   "canoe",    "canvas",   "canyon",   "capable",  "capital",  "captain",  "car",      "carbon",   "card",     "cargo",    "carpet",   "carry",
        "cart",     "case",     "cash",     "casino",   "castle",   "casual",   "cat",      "catalog",  "catch",    "category", "cattle",   "caught",   "cause",    "caution",
        "cave",     "ceiling",  "celery",   "cement",   "census",   "century",  "cereal",   "certain",  "chair",    "chalk",    "champion", "change",   "chaos",    "chapter",
        "charge",   "chase",    "chat",     "cheap",    "check",    "cheese",   "chef",     "cherry",   "chest",    "chicken",  "chief",    "child",    "chimney",  "choice",
        "choose",   "chronic",  "chuckle",  "chunk",    "churn",    "cigar",    "cinnamon", "circle",   "citizen",  "city",     "civil",    "claim",    "clap",     "clarify",
        "claw",     "clay",     "clean",    "clerk",    "clever",   "click",    "client",   "cliff",    "climb",    "clinic",   "clip",     "clock",    "clog",     "close",
        "cloth",    "cloud",    "clown",    "club",     "clump",    "cluster",  "clutch",   "coach",    "coast",    "coconut",  "code",     "coffee",   "coil",     "coin",
        "collect",  "color",    "column",   "combine",  "come",     "comfort",  "comic",    "common",   "company",  "concert",  "conduct",  "confirm",  "congress", "connect",
        "consider", "control",  "convince", "cook",     "cool",     "copper",   "copy",     "coral",    "core",     "corn",     "correct",  "cost",     "cotton",   "couch",
        "country",  "couple",   "course",   "cousin",   "cover",    "coyote",   "crack",    "cradle",   "craft",    "cram",     "crane",    "crash",    "crater",   "crawl",
        "crazy",    "cream",    "credit",   "creek",    "crew",     "cricket",  "crime",    "crisp",    "critic",   "crop",     "cross",    "crouch",   "crowd",    "crucial",
        "cruel",    "cruise",   "crumble",  "crunch",   "crush",    "cry",      "crystal",  "cube",     "culture",  "cup",      "cupboard", "curious",  "current",  "curtain",
        "curve",    "cushion",  "custom",   "cute",     "cycle",    "dad",      "damage",   "damp",     "dance",    "danger",   "daring",   "dash",     "daughter", "dawn",
        "day",      "deal",     "debate",   "debris",   "decade",   "december", "decide",   "decline",  "decorate", "decrease", "deer",     "defense",  "define",   "defy",
        "degree",   "delay",    "deliver",  "demand",   "demise",   "denial",   "dentist",  "deny",     "depart",   "depend",   "deposit",  "depth",    "deputy",   "derive",
        "describe", "desert",   "design",   "desk",     "despair",  "destroy",  "detail",   "detect",   "develop",  "device",   "devote",   "diagram",  "dial",     "diamond",
        "diary",    "dice",     "diesel",   "diet",     "differ",   "digital",  "dignity",  "dilemma",  "dinner",   "dinosaur", "direct",   "dirt",     "disagree", "discover",
        "disease",  "dish",     "dismiss",  "disorder", "display",  "distance", "divert",   "divide",   "divorce",  "dizzy",    "doctor",   "document", "dog",      "doll",
        "dolphin",  "domain",   "donate",   "donkey",   "donor",    "door",     "dose",     "double",   "dove",     "draft",    "dragon",   "drama",    "drastic",  "draw",
        "dream",    "dress",    "drift",    "drill",    "drink",    "drip",     "drive",    "drop",     "drum",     "dry",      "duck",     "dumb",     "dune",     "during",
        "dust",     "dutch",    "duty",     "dwarf",    "dynamic",  "eager",    "eagle",    "early",    "earn",     "earth",    "easily",   "east",     "easy",     "echo",
        "ecology",  "economy",  "edge",     "edit",     "educate",  "effort",   "egg",      "eight",    "either",   "elbow",    "elder",    "electric", "elegant",  "element",
        "elephant", "elevator", "elite",    "else",     "embark",   "embody",   "embrace",  "emerge",   "emotion",  "employ",   "empower",  "empty",    "enable",   "enact",
        "end",      "endless",  "endorse",  "enemy",    "energy",   "enforce",  "engage",   "engine",   "enhance",  "enjoy",    "enlist",   "enough",   "enrich",   "enroll",
        "ensure",   "enter",    "entire",   "entry",    "envelope", "episode",  "equal",    "equip",    "era",      "erase",    "erode",    "erosion",  "error",    "erupt",
        "escape",   "essay",    "essence",  "estate",   "eternal",  "ethics",   "evidence", "evil",     "evoke",    "evolve",   "exact",    "example",  "excess",   "exchange",
        "excite",   "exclude",  "excuse",   "execute",  "exercise", "exhaust",  "exhibit",  "exile",    "exist",    "exit",     "exotic",   "expand",   "expect",   "expire",
        "explain",  "expose",   "express",  "extend",   "extra",    "eye",      "eyebrow",  "fabric",   "face",     "faculty",  "fade",     "faint",    "faith",    "fall",
        "false",    "fame",     "family",   "famous",   "fan",      "fancy",    "fantasy",  "farm",     "fashion",  "fat",      "fatal",    "father",   "fatigue",  "fault",
        "favorite", "feature",  "february", "federal",  "fee",      "feed",     "feel",     "female",   "fence",    "festival", "fetch",    "fever",    "few",      "fiber",
        "fiction",  "field",    "figure",   "file",     "film",     "filter",   "final",    "find",     "fine",     "finger",   "finish",   "fire",     "firm",     "first",
        "fiscal",   "fish",     "fit",      "fitness",  "fix",      "flag",     "flame",    "flash",    "flat",     "flavor",   "flee",     "flight",   "flip",     "float",
        "flock",    "floor",    "flower",   "fluid",    "flush",    "fly",      "foam",     "focus",    "fog",      "foil",     "fold",     "follow",   "food",     "foot",
        "force",    "forest",   "forget",   "fork",     "fortune",  "forum",    "forward",  "fossil",   "foster",   "found",    "fox",      "fragile",  "frame",    "frequent",
        "fresh",    "friend",   "fringe",   "frog",     "front",    "frost",    "frown",    "frozen",   "fruit",    "fuel",     "fun",      "funny",    "furnace",  "fury",
        "future",   "gadget",   "gain",     "galaxy",   "gallery",  "game",     "gap",      "garage",   "garbage",  "garden",   "garlic",   "garment",  "gas",      "gasp",
        "gate",     "gather",   "gauge",    "gaze",     "general",  "genius",   "genre",    "gentle",   "genuine",  "gesture",  "ghost",    "giant",    "gift",     "giggle",
        "ginger",   "giraffe",  "girl",     "give",     "glad",     "glance",   "glare",    "glass",    "glide",    "glimpse",  "globe",    "gloom",    "glory",    "glove",
        "glow",     "glue",     "goat",     "goddess",  "gold",     "good",     "goose",    "gorilla",  "gospel",   "gossip",   "govern",   "gown",     "grab",     "grace",
        "grain",    "grant",    "grape",    "grass",    "gravity",  "great",    "green",    "grid",     "grief",    "grit",     "grocery",  "group",    "grow",     "grunt",
        "guard",    "guess",    "guide",    "guilt",    "guitar",   "gun",      "gym",      "habit",    "hair",     "half",     "hammer",   "hamster",  "hand",     "happy",
        "harbor",   "hard",     "harsh",    "harvest",  "hat",      "have",     "hawk",     "hazard",   "head",     "health",   "heart",    "heavy",    "hedgehog", "height",
        "hello",    "helmet",   "help",     "hen",      "hero",     "hidden",   "high",     "hill",     "hint",     "hip",      "hire",     "history",  "hobby",    "hockey",
        "hold",     "hole",     "holiday",  "hollow",   "home",     "honey",    "hood",     "hope",     "horn",     "horror",   "horse",    "hospital", "host",     "hotel",
        "hour",     "hover",    "hub",      "huge",     "human",    "humble",   "humor",    "hundred",  "hungry",   "hunt",     "hurdle",   "hurry",    "hurt",     "husband",
        "hybrid",   "ice",      "icon",     "idea",     "identify", "idle",     "ignore",   "ill",      "illegal",  "illness",  "image",    "imitate",  "immense",  "immune",
        "impact",   "impose",   "improve",  "impulse",  "inch",     "include",  "income",   "increase", "index",    "indicate", "indoor",   "industry", "infant",   "inflict",
        "inform",   "inhale",   "inherit",  "initial",  "inject",   "injury",   "inmate",   "inner",    "innocent", "input",    "inquiry",  "insane",   "insect",   "inside",
        "inspire",  "install",  "intact",   "interest", "into",     "invest",   "invite",   "involve",  "iron",     "island",   "isolate",  "issue",    "item",     "ivory",
        "jacket",   "jaguar",   "jar",      "jazz",     "jealous",  "jeans",    "jelly",    "jewel",    "job",      "join",     "joke",     "journey",  "joy",      "judge",
        "juice",    "jump",     "jungle",   "junior",   "junk",     "just",     "kangaroo", "keen",     "keep",     "ketchup",  "key",      "kick",     "kid",      "kidney",
        "kind",     "kingdom",  "kiss",     "kit",      "kitchen",  "kite",     "kitten",   "kiwi",     "knee",     "knife",    "knock",    "know",     "lab",      "label",
        "labor",    "ladder",   "lady",     "lake",     "lamp",     "language", "laptop",   "large",    "later",    "latin",    "laugh",    "laundry",  "lava",     "law",
        "lawn",     "lawsuit",  "layer",    "lazy",     "leader",   "leaf",     "learn",    "leave",    "lecture",  "left",     "leg",      "legal",    "legend",   "leisure",
        "lemon",    "lend",     "length",   "lens",     "leopard",  "lesson",   "letter",   "level",    "liar",     "liberty",  "library",  "license",  "life",     "lift",
        "light",    "like",     "limb",     "limit",    "link",     "lion",     "liquid",   "list",     "little",   "live",     "lizard",   "load",     "loan",     "lobster",
        "local",    "lock",     "logic",    "lonely",   "long",     "loop",     "lottery",  "loud",     "lounge",   "love",     "loyal",    "lucky",    "luggage",  "lumber",
        "lunar",    "lunch",    "luxury",   "lyrics",   "machine",  "mad",      "magic",    "magnet",   "maid",     "mail",     "main",     "major",    "make",     "mammal",
        "man",      "manage",   "mandate",  "mango",    "mansion",  "manual",   "maple",    "marble",   "march",    "margin",   "marine",   "market",   "marriage", "mask",
        "mass",     "master",   "match",    "material", "math",     "matrix",   "matter",   "maximum",  "maze",     "meadow",   "mean",     "measure",  "meat",     "mechanic",
        "medal",    "media",    "melody",   "melt",     "member",   "memory",   "mention",  "menu",     "mercy",    "merge",    "merit",    "merry",    "mesh",     "message",
        "metal",    "method",   "middle",   "midnight", "milk",     "million",  "mimic",    "mind",     "minimum",  "minor",    "minute",   "miracle",  "mirror",   "misery",
        "miss",     "mistake",  "mix",      "mixed",    "mixture",  "mobile",   "model",    "modify",   "mom",      "moment",   "monitor",  "monkey",   "monster",  "month",
        "moon",     "moral",    "more",     "morning",  "mosquito", "mother",   "motion",   "motor",    "mountain", "mouse",    "move",     "movie",    "much",     "muffin",
        "mule",     "multiply", "muscle",   "museum",   "mushroom", "music",    "must",     "mutual",   "myself",   "mystery",  "myth",     "naive",    "name",     "napkin",
        "narrow",   "nasty",    "nation",   "nature",   "near",     "neck",     "need",     "negative", "neglect",  "neither",  "nephew",   "nerve",    "nest",     "net",
        "network",  "neutral",  "never",    "news",     "next",     "nice",     "night",    "noble",    "noise",    "nominee",  "noodle",   "normal",   "north",    "nose",
        "notable",  "note",     "nothing",  "notice",   "novel",    "now",      "nuclear",  "number",   "nurse",    "nut",      "oak",      "obey",     "object",   "oblige",
        "obscure",  "observe",  "obtain",   "obvious",  "occur",    "ocean",    "october",  "odor",     "off",      "offer",    "office",   "often",    "oil",      "okay",
        "old",      "olive",    "olympic",  "omit",     "once",     "one",      "onion",    "online",   "only",     "open",     "opera",    "opinion",  "oppose",   "option",
        "orange",   "orbit",    "orchard",  "order",    "ordinary", "organ",    "orient",   "original", "orphan",   "ostrich",  "other",    "outdoor",  "outer",    "output",
        "outside",  "oval",     "oven",     "over",     "own",      "owner",    "oxygen",   "oyster",   "ozone",    "pact",     "paddle",   "page",     "pair",     "palace",
        "palm",     "panda",    "panel",    "panic",    "panther",  "paper",    "parade",   "parent",   "park",     "parrot",   "party",    "pass",     "patch",    "path",
        "patient",  "patrol",   "pattern",  "pause",    "pave",     "payment",  "peace",    "peanut",   "pear",     "peasant",  "pelican",  "pen",      "penalty",  "pencil",
        "people",   "pepper",   "perfect",  "permit",   "person",   "pet",      "phone",    "photo",    "phrase",   "physical", "piano",    "picnic",   "picture",  "piece",
        "pig",      "pigeon",   "pill",     "pilot",    "pink",     "pioneer",  "pipe",     "pistol",   "pitch",    "pizza",    "place",    "planet",   "plastic",  "plate",
        "play",     "please",   "pledge",   "pluck",    "plug",     "plunge",   "poem",     "poet",     "point",    "polar",    "pole",     "police",   "pond",     "pony",
        "pool",     "popular",  "portion",  "position", "possible", "post",     "potato",   "pottery",  "poverty",  "powder",   "power",    "practice", "praise",   "predict",
        "prefer",   "prepare",  "present",  "pretty",   "prevent",  "price",    "pride",    "primary",  "print",    "priority", "prison",   "private",  "prize",    "problem",
        "process",  "produce",  "profit",   "program",  "project",  "promote",  "proof",    "property", "prosper",  "protect",  "proud",    "provide",  "public",   "pudding",
        "pull",     "pulp",     "pulse",    "pumpkin",  "punch",    "pupil",    "puppy",    "purchase", "purity",   "purpose",  "purse",    "push",     "put",      "puzzle",
        "pyramid",  "quality",  "quantum",  "quarter",  "question", "quick",    "quit",     "quiz",     "quote",    "rabbit",   "raccoon",  "race",     "rack",     "radar",
        "radio",    "rail",     "rain",     "raise",    "rally",    "ramp",     "ranch",    "random",   "range",    "rapid",    "rare",     "rate",     "rather",   "raven",
        "raw",      "razor",    "ready",    "real",     "reason",   "rebel",    "rebuild",  "recall",   "receive",  "recipe",   "record",   "recycle",  "reduce",   "reflect",
        "reform",   "refuse",   "region",   "regret",   "regular",  "reject",   "relax",    "release",  "relief",   "rely",     "remain",   "remember", "remind",   "remove",
        "render",   "renew",    "rent",     "reopen",   "repair",   "repeat",   "replace",  "report",   "require",  "rescue",   "resemble", "resist",   "resource", "response",
        "result",   "retire",   "retreat",  "return",   "reunion",  "reveal",   "review",   "reward",   "rhythm",   "rib",      "ribbon",   "rice",     "rich",     "ride",
        "ridge",    "rifle",    "right",    "rigid",    "ring",     "riot",     "ripple",   "risk",     "ritual",   "rival",    "river",    "road",     "roast",    "robot",
        "robust",   "rocket",   "romance",  "roof",     "rookie",   "room",     "rose",     "rotate",   "rough",    "round",    "route",    "royal",    "rubber",   "rude",
        "rug",      "rule",     "run",      "runway",   "rural",    "sad",      "saddle",   "sadness",  "safe",     "sail",     "salad",    "salmon",   "salon",    "salt",
        "salute",   "same",     "sample",   "sand",     "satisfy",  "satoshi",  "sauce",    "sausage",  "save",     "say",      "scale",    "scan",     "scare",    "scatter",
        "scene",    "scheme",   "school",   "science",  "scissors", "scorpion", "scout",    "scrap",    "screen",   "script",   "scrub",    "sea",      "search",   "season",
        "seat",     "second",   "secret",   "section",  "security", "seed",     "seek",     "segment",  "select",   "sell",     "seminar",  "senior",   "sense",    "sentence",
        "series",   "service",  "session",  "settle",   "setup",    "seven",    "shadow",   "shaft",    "shallow",  "share",    "shed",     "shell",    "sheriff",  "shield",
        "shift",    "shine",    "ship",     "shiver",   "shock",    "shoe",     "shoot",    "shop",     "short",    "shoulder", "shove",    "shrimp",   "shrug",    "shuffle",
        "shy",      "sibling",  "sick",     "side",     "siege",    "sight",    "sign",     "silent",   "silk",     "silly",    "silver",   "similar",  "simple",   "since",
        "sing",     "siren",    "sister",   "situate",  "six",      "size",     "skate",    "sketch",   "ski",      "skill",    "skin",     "skirt",    "skull",    "slab",
        "slam",     "sleep",    "slender",  "slice",    "slide",    "slight",   "slim",     "slogan",   "slot",     "slow",     "slush",    "small",    "smart",    "smile",
        "smoke",    "smooth",   "snack",    "snake",    "snap",     "sniff",    "snow",     "soap",     "soccer",   "social",   "sock",     "soda",     "soft",     "solar",
        "soldier",  "solid",    "solution", "solve",    "someone",  "song",     "soon",     "sorry",    "sort",     "soul",     "sound",    "soup",     "source",   "south",
        "space",    "spare",    "spatial",  "spawn",    "speak",    "special",  "speed",    "spell",    "spend",    "sphere",   "spice",    "spider",   "spike",    "spin",
        "spirit",   "split",    "spoil",    "sponsor",  "spoon",    "sport",    "spot",     "spray",    "spread",   "spring",   "spy",      "square",   "squeeze",  "squirrel",
        "stable",   "stadium",  "staff",    "stage",    "stairs",   "stamp",    "stand",    "start",    "state",    "stay",     "steak",    "steel",    "stem",     "step",
        "stereo",   "stick",    "still",    "sting",    "stock",    "stomach",  "stone",    "stool",    "story",    "stove",    "strategy", "street",   "strike",   "strong",
        "struggle", "student",  "stuff",    "stumble",  "style",    "subject",  "submit",   "subway",   "success",  "such",     "sudden",   "suffer",   "sugar",    "suggest",
        "suit",     "summer",   "sun",      "sunny",    "sunset",   "super",    "supply",   "supreme",  "sure",     "surface",  "surge",    "surprise", "surround", "survey",
        "suspect",  "sustain",  "swallow",  "swamp",    "swap",     "swarm",    "swear",    "sweet",    "swift",    "swim",     "swing",    "switch",   "sword",    "symbol",
        "symptom",  "syrup",    "system",   "table",    "tackle",   "tag",      "tail",     "talent",   "talk",     "tank",     "tape",     "target",   "task",     "taste",
        "tattoo",   "taxi",     "teach",    "team",     "tell",     "ten",      "tenant",   "tennis",   "tent",     "term",     "test",     "text",     "thank",    "that",
        "theme",    "then",     "theory",   "there",    "they",     "thing",    "this",     "thought",  "three",    "thrive",   "throw",    "thumb",    "thunder",  "ticket",
        "tide",     "tiger",    "tilt",     "timber",   "time",     "tiny",     "tip",      "tired",    "tissue",   "title",    "toast",    "tobacco",  "today",    "toddler",
        "toe",      "together", "toilet",   "token",    "tomato",   "tomorrow", "tone",     "tongue",   "tonight",  "tool",     "tooth",    "top",      "topic",    "topple",
        "torch",    "tornado",  "tortoise", "toss",     "total",    "tourist",  "toward",   "tower",    "town",     "toy",      "track",    "trade",    "traffic",  "tragic",
        "train",    "transfer", "trap",     "trash",    "travel",   "tray",     "treat",    "tree",     "trend",    "trial",    "tribe",    "trick",    "trigger",  "trim",
        "trip",     "trophy",   "trouble",  "truck",    "true",     "truly",    "trumpet",  "trust",    "truth",    "try",      "tube",     "tuition",  "tumble",   "tuna",
        "tunnel",   "turkey",   "turn",     "turtle",   "twelve",   "twenty",   "twice",    "twin",     "twist",    "two",      "type",     "typical",  "ugly",     "umbrella",
        "unable",   "unaware",  "uncle",    "uncover",  "under",    "undo",     "unfair",   "unfold",   "unhappy",  "uniform",  "unique",   "unit",     "universe", "unknown",
        "unlock",   "until",    "unusual",  "unveil",   "update",   "upgrade",  "uphold",   "upon",     "upper",    "upset",    "urban",    "urge",     "usage",    "use",
        "used",     "useful",   "useless",  "usual",    "utility",  "vacant",   "vacuum",   "vague",    "valid",    "valley",   "valve",    "van",      "vanish",   "vapor",
        "various",  "vast",     "vault",    "vehicle",  "velvet",   "vendor",   "venture",  "venue",    "verb",     "verify",   "version",  "very",     "vessel",   "veteran",
        "viable",   "vibrant",  "vicious",  "victory",  "video",    "view",     "village",  "vintage",  "violin",   "virtual",  "virus",    "visa",     "visit",    "visual",
        "vital",    "vivid",    "vocal",    "voice",    "void",     "volcano",  "volume",   "vote",     "voyage",   "wage",     "wagon",    "wait",     "walk",     "wall",
        "walnut",   "want",     "warfare",  "warm",     "warrior",  "wash",     "wasp",     "waste",    "water",    "wave",     "way",      "wealth",   "weapon",   "wear",
        "weasel",   "weather",  "web",      "wedding",  "weekend",  "weird",    "welcome",  "west",     "wet",      "whale",    "what",     "wheat",    "wheel",    "when",
        "where",    "whip",     "whisper",  "wide",     "width",    "wife",     "wild",     "will",     "win",      "window",   "wine",     "wing",     "wink",     "winner",
        "winter",   "wire",     "wisdom",   "wise",     "wish",     "witness",  "wolf",     "woman",    "wonder",   "wood",     "wool",     "word",     "work",     "world",
        "worry",    "worth",    "wrap",     "wreck",    "wrestle",  "wrist",    "write",    "wrong",    "yard",     "year",     "yellow",   "you",      "young",    "youth",
        "zebra",    "zero",     "zone",     "zoo"};
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class WordEncoder {
  public:
    WordEncoder(const WordListManager &manager) : wordList(manager.getWordList()) {}

    std::vector<std::string> binaryToWords(const std::string &binaryStr) {
        std::vector<std::string> words;

        for (size_t i = 0; i + 10 < binaryStr.size(); i += 11) {
            std::string chunk = binaryStr.substr(i, 11);
            int index = std::stoi(chunk, nullptr, 2);

            if (index < wordList.size()) {
                words.push_back(wordList[index]);
            } else {
                words.push_back("[INVALID]"); // Optional error handling
            }
        }

        return words;
    }

    size_t getWordListSize() const { return wordList.size(); }

  private:
    std::vector<std::string> wordList;
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

namespace CRYPTO {
class SHA256 {
  public:
    SHA256() { reset(); }

    void update(const uint8_t *data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            buffer[bufferLen++] = data[i];
            if (bufferLen == 64) {
                transform(buffer);
                bitlen += 512;
                bufferLen = 0;
            }
        }
    }

    void update(const std::string &data) { update(reinterpret_cast<const uint8_t *>(data.c_str()), data.size()); }

    std::string digest() {
        uint64_t totalBits = bitlen + bufferLen * 8;

        buffer[bufferLen++] = 0x80;
        if (bufferLen > 56) {
            while (bufferLen < 64)
                buffer[bufferLen++] = 0x00;
            transform(buffer);
            bufferLen = 0;
        }

        while (bufferLen < 56)
            buffer[bufferLen++] = 0x00;

        for (int i = 7; i >= 0; --i)
            buffer[bufferLen++] = (totalBits >> (i * 8)) & 0xFF;

        transform(buffer);

        std::ostringstream oss;
        for (int i = 0; i < 8; ++i)
            oss << std::hex << std::setw(8) << std::setfill('0') << h[i];

        reset(); // reset internal state after digest
        return oss.str();
    }

    std::string digestBinary() {
        std::string hex = digest();
        std::string binary;
        for (char c : hex) {
            uint8_t val = (c <= '9') ? c - '0' : 10 + (std::tolower(c) - 'a');
            for (int i = 3; i >= 0; --i)
                binary += ((val >> i) & 1) ? '1' : '0';
        }
        return binary;
    }

    void reset() {
        h[0] = 0x6a09e667;
        h[1] = 0xbb67ae85;
        h[2] = 0x3c6ef372;
        h[3] = 0xa54ff53a;
        h[4] = 0x510e527f;
        h[5] = 0x9b05688c;
        h[6] = 0x1f83d9ab;
        h[7] = 0x5be0cd19;
        bitlen = 0;
        bufferLen = 0;
    }

  private:
    uint32_t h[8];
    uint64_t bitlen;
    uint8_t buffer[64];
    size_t bufferLen;

    void transform(const uint8_t block[64]) {
        uint32_t w[64];

        for (int i = 0; i < 16; ++i) {
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | (block[i * 4 + 3]);
        }

        for (int i = 16; i < 64; ++i) {
            w[i] = theta1(w[i - 2]) + w[i - 7] + theta0(w[i - 15]) + w[i - 16];
        }

        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t h_val = h[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t temp1 = h_val + sig1(e) + choose(e, f, g) + K[i] + w[i];
            uint32_t temp2 = sig0(a) + majority(a, b, c);
            h_val = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += h_val;
    }

    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t choose(uint32_t e, uint32_t f, uint32_t g) { return (e & f) ^ (~e & g); }
    static uint32_t majority(uint32_t a, uint32_t b, uint32_t c) { return (a & b) ^ (a & c) ^ (b & c); }
    static uint32_t sig0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    static uint32_t sig1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    static uint32_t theta0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    static uint32_t theta1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    const uint32_t K[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
                            0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
                            0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
                            0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
                            0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
};
} // namespace CRYPTO

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

inline std::string sha256(const std::string &data) {
    CRYPTO::SHA256 sha;
    sha.update(data);
    return sha.digest();
}

inline std::string sha256Binary(const std::string &data) {
    CRYPTO::SHA256 sha;
    sha.update(data);
    return sha.digestBinary(); // directly returns 256-bit binary string
}

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class MetaData {
  public:
    // Convert binary input to base62 and 8-bit padded binary output
    inline std::string binaryToBase62WithPadding(const std::string &binaryStr) {
        std::string result;
        std::string paddedBinary;

        for (size_t i = 0; i + 5 < binaryStr.size(); i += 6) {
            std::string chunk6 = binaryStr.substr(i, 6);
            int value = std::stoi(chunk6, nullptr, 2); // 6-bit binary to int

            if (value < 62) {
                char base62Char = base62[value];
                result += base62Char;

                std::string paddedChunk = "00" + chunk6; // Add 2-bit leading padding
                paddedBinary += paddedChunk;
            }
        }

        // Optional: Store the padded binary if needed later
        paddedBits = paddedBinary;

        return result; // Return the base62-encoded string
    }

    inline std::string getPaddedBinary() const { return paddedBits; }

  private:
    std::string paddedBits;
    const std::string base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class RandomNumberGenerator {
  public:
    inline std::string run() {
        std::string result;
        result.reserve((totalIterations - localBufferSize) * 256);

        for (int i = 0; i < totalIterations; ++i) {

            long long duration = countdown();
            ++count;
            globalSum += duration;
            globalAvg = globalSum / count;

            int bit = duration < globalAvg ? 0 : 1;

            if (localBits.size() >= localBufferSize)
                localBits.pop_front();

            localBits.push_back(bit);

            if (localBits.size() == localBufferSize) {
                // 32 raw bytes → 256 bit string
                std::string hashBits = hashLocalBits();
                result += hashBits;
            }
        }

        return result;
    }

  private:
    CRYPTO::SHA256 sha;
    std::deque<int> localBits;
    const int totalIterations = 1000;
    const size_t localBufferSize = 512;
    long long globalSum = 0;
    long long globalAvg = 0;
    int count = 0;

    inline long long countdown() {
        int x = 10;
        auto start = systemClock.getNanoseconds();
        while (x > 0)
            x--;
        auto end = systemClock.getNanoseconds();
        return end - start;
    }

    inline std::string hashLocalBits() {
        // Build 64-byte block
        uint8_t bytes[64] = {0};
        for (size_t i = 0; i < localBits.size(); ++i) {
            if (localBits[i]) {
                bytes[i / 8] |= (1 << (7 - (i % 8)));
            }
        }

        sha.update(bytes, 64);

        // Return 256-bit binary string using fast helper
        return sha.digestBinary();
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class BinaryEntropyPool {
  public:
    inline std::string get(size_t bitsNeeded) {
        std::lock_guard<std::mutex> lock(poolMutex);

        // Refill the pool until we have enough bits
        while (bitPool.size() < bitsNeeded) {
            bitPool += rng.run(); // rng.run() now returns a bit string
        }

        // Extract exactly the number of bits requested
        std::string result = bitPool.substr(0, bitsNeeded);
        bitPool.erase(0, bitsNeeded); // remove consumed bits

        return result;
    }

  private:
    std::string bitPool; // bit string directly
    RandomNumberGenerator rng;
    mutable std::mutex poolMutex;
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class HMAC {
  public:
    static std::string compute(const std::string &key, const std::string &message) {
        // Step 1: Normalize key to 64 bytes
        std::string K = normalizeKey(key);

        // Step 2: Create inner and outer padded keys
        std::string ipad(BLOCK_SIZE, 0x36);
        std::string opad(BLOCK_SIZE, 0x5c);

        for (size_t i = 0; i < BLOCK_SIZE; ++i) {
            ipad[i] ^= K[i];
            opad[i] ^= K[i];
        }

        // Step 3: Inner hash
        std::string inner = sha256Binary(ipad + message);

        // Step 4: Outer hash
        return sha256Binary(opad + inner);
    }

  private:
    static constexpr size_t BLOCK_SIZE = 64; // SHA-256 block size
    static constexpr size_t HASH_SIZE = 32;  // SHA-256 output size

    static std::string normalizeKey(const std::string &key) {
        if (key.size() > BLOCK_SIZE) {
            return sha256Binary(key);
        }

        std::string out = key;
        out.resize(BLOCK_SIZE, 0x00);
        return out;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

// Modified KeyDerivation to accept password directly
class KeyDerivation {
  public:
    struct DerivedKey {
        std::vector<uint8_t> salt; // 16 bytes
        std::string key;           // 32 bytes of binary data (for AES-256)
    };

    // Derive key from a given password string (with new salt)
    DerivedKey deriveKeyFromPassword(const std::string &password) {
        DerivedKey out{};

        out.salt = generateSalt();

        // Convert binary salt → string for HMAC
        std::string salt_str(reinterpret_cast<const char *>(out.salt.data()), out.salt.size());

        std::string U = HMAC::compute(password, salt_str);
        std::string T = U;

        // Show initial progress
        functions.updateProgress(0, ITERATIONS);

        for (uint32_t i = 1; i < ITERATIONS; ++i) {
            U = HMAC::compute(password, U);
            xorInPlace(T, U);

            // Only update progress bar every 1000 iterations for performance
            if (i % 1000 == 0 || i == ITERATIONS - 1) {
                functions.updateProgress(i, ITERATIONS);
            }
        }

        // Print final newline
        std::cout << "\n";

        out.key = T;
        return out;
    }

    // Derive key from a given password string (with existing salt)
    DerivedKey deriveKeyFromPassword(const std::string &password, const std::vector<uint8_t> &salt) {
        DerivedKey out{};
        out.salt = salt;

        std::string salt_str(reinterpret_cast<const char *>(salt.data()), salt.size());

        std::string U = HMAC::compute(password, salt_str);
        std::string T = U;

        // Show initial progress
        functions.updateProgress(0, ITERATIONS);

        for (uint32_t i = 1; i < ITERATIONS; ++i) {
            U = HMAC::compute(password, U);
            xorInPlace(T, U);

            // Only update progress bar every 1000 iterations for performance
            if (i % 1000 == 0 || i == ITERATIONS - 1) {
                functions.updateProgress(i, ITERATIONS);
            }
        }

        out.key = T;
        return out;
    }

    // Convert bit string "101010..." → actual bytes
    std::vector<uint8_t> bitStringToBytes(const std::string &bits, size_t wanted_bytes) {
        if (bits.size() < wanted_bytes * 8) {
            throw std::runtime_error("Not enough bits for requested byte length");
        }
        std::vector<uint8_t> result(wanted_bytes, 0);
        for (size_t i = 0; i < wanted_bytes * 8; ++i) {
            if (bits[i] == '1') {
                size_t byte_idx = i / 8;
                int bit_pos = 7 - static_cast<int>(i % 8);
                result[byte_idx] |= (1u << bit_pos);
            }
        }
        return result;
    }

  private:
    static constexpr uint32_t ITERATIONS = 100'000;
    static constexpr size_t SALT_BYTES = 16;

    std::vector<uint8_t> generateSalt() {
        BinaryEntropyPool bep;
        std::string bitString = bep.get(SALT_BYTES * 8);
        return bitStringToBytes(bitString, SALT_BYTES);
    }

    void xorInPlace(std::string &a, const std::string &b) {
        if (a.size() != b.size()) {
            throw std::runtime_error("XOR size mismatch");
        }
        for (size_t i = 0; i < a.size(); ++i) {
            a[i] ^= b[i];
        }
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

// Master key holder - keeps derived key in memory for the session
struct MasterKey {
    std::vector<uint8_t> key;  // 32 bytes for AES-256
    std::vector<uint8_t> salt; // 16 bytes
    bool isValid = false;

    void set(const std::vector<uint8_t> &k, const std::vector<uint8_t> &s) {
        key = k;
        salt = s;
        isValid = true;
    }

    void clear() {
        // Securely wipe the key from memory
        if (!key.empty()) {
            volatile uint8_t *p = key.data();
            for (size_t i = 0; i < key.size(); ++i) {
                p[i] = 0;
            }
            key.clear();
            key.shrink_to_fit();
        }
        if (!salt.empty()) {
            salt.clear();
            salt.shrink_to_fit();
        }
        isValid = false;
    }

    ~MasterKey() { clear(); }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class AES {
  public:
    using byte = uint8_t;

    // ===== Public CBC entry points =====
    std::vector<byte> encryptCBC128(const std::vector<byte> &plaintext, const byte key[16], const byte iv[16]) { return encryptCBC(plaintext, key, 4, 10, iv); }
    std::vector<byte> encryptCBC192(const std::vector<byte> &plaintext, const byte key[24], const byte iv[16]) { return encryptCBC(plaintext, key, 6, 12, iv); }
    std::vector<byte> encryptCBC256(const std::vector<byte> &plaintext, const byte key[32], const byte iv[16]) { return encryptCBC(plaintext, key, 8, 14, iv); }

    std::vector<byte> decryptCBC128(const std::vector<byte> &plaintext, const byte key[16], const byte iv[16]) { return decryptCBC(plaintext, key, 4, 10, iv); }
    std::vector<byte> decryptCBC192(const std::vector<byte> &plaintext, const byte key[24], const byte iv[16]) { return decryptCBC(plaintext, key, 6, 12, iv); }
    std::vector<byte> decryptCBC256(const std::vector<byte> &plaintext, const byte key[32], const byte iv[16]) { return decryptCBC(plaintext, key, 8, 14, iv); }

    // Generate random IV (16 bytes) using entropy pool
    std::array<AES::byte, 16> generateIV(BinaryEntropyPool &bep) {
        std::string ivBits = bep.get(128); // 128 bits = 16 bytes
        std::vector<uint8_t> ivBytes = kd.bitStringToBytes(ivBits, 16);
        std::array<AES::byte, 16> iv{};
        std::copy(ivBytes.begin(), ivBytes.end(), iv.begin());
        return iv;
    }

  private:
    KeyDerivation kd;
    static constexpr int BLOCK_SIZE = 16;

    // ===== Core AES operations =====
    byte gmul(byte a, byte b) {
        byte p = 0;
        while (b) {
            if (b & 1)
                p ^= a;
            a = (a << 1) ^ ((a & 0x80) ? 0x1B : 0);
            b >>= 1;
        }
        return p;
    }

    void AddRoundKey(byte *s, const byte *rk) {
        for (int i = 0; i < 16; i++)
            s[i] ^= rk[i];
    }

    void SubBytes(byte *s) {
        for (int i = 0; i < 16; i++)
            s[i] = sbox[s[i]];
    }

    void InvSubBytes(byte *s) {
        for (int i = 0; i < 16; i++)
            s[i] = inv_sbox[s[i]];
    }

    void ShiftRows(byte *s) {
        byte t[16];
        memcpy(t, s, 16);

        // Row 0 (no shift)
        s[0] = t[0];
        s[4] = t[4];
        s[8] = t[8];
        s[12] = t[12];

        // Row 1 (left shift by 1)
        s[1] = t[5];
        s[5] = t[9];
        s[9] = t[13];
        s[13] = t[1];

        // Row 2 (left shift by 2)
        s[2] = t[10];
        s[6] = t[14];
        s[10] = t[2];
        s[14] = t[6];

        // Row 3 (left shift by 3)
        s[3] = t[15];
        s[7] = t[3];
        s[11] = t[7];
        s[15] = t[11];
    }

    void InvShiftRows(byte *s) {
        byte t[16];
        memcpy(t, s, 16);

        // Row 0 (unchanged)
        s[0] = t[0];
        s[4] = t[4];
        s[8] = t[8];
        s[12] = t[12];

        // Row 1 (right shift by 1)
        s[1] = t[13];
        s[5] = t[1];
        s[9] = t[5];
        s[13] = t[9];

        // Row 2 (right shift by 2)
        s[2] = t[10];
        s[6] = t[14];
        s[10] = t[2];
        s[14] = t[6];

        // Row 3 (right shift by 3)
        s[3] = t[7];
        s[7] = t[11];
        s[11] = t[15];
        s[15] = t[3];
    }

    void MixColumns(byte *s) {
        for (int c = 0; c < 4; c++) {
            int i = c * 4;
            byte a = s[i];
            byte b = s[i + 1];
            byte c_ = s[i + 2];
            byte d = s[i + 3];

            s[i] = gmul(a, 2) ^ gmul(b, 3) ^ c_ ^ d;
            s[i + 1] = a ^ gmul(b, 2) ^ gmul(c_, 3) ^ d;
            s[i + 2] = a ^ b ^ gmul(c_, 2) ^ gmul(d, 3);
            s[i + 3] = gmul(a, 3) ^ b ^ c_ ^ gmul(d, 2);
        }
    }

    void InvMixColumns(byte *s) {
        for (int c = 0; c < 4; c++) {
            int i = c * 4;
            byte a = s[i];
            byte b = s[i + 1];
            byte c_ = s[i + 2];
            byte d = s[i + 3];

            s[i] = gmul(a, 0x0e) ^ gmul(b, 0x0b) ^ gmul(c_, 0x0d) ^ gmul(d, 0x09);
            s[i + 1] = gmul(a, 0x09) ^ gmul(b, 0x0e) ^ gmul(c_, 0x0b) ^ gmul(d, 0x0d);
            s[i + 2] = gmul(a, 0x0d) ^ gmul(b, 0x09) ^ gmul(c_, 0x0e) ^ gmul(d, 0x0b);
            s[i + 3] = gmul(a, 0x0b) ^ gmul(b, 0x0d) ^ gmul(c_, 0x09) ^ gmul(d, 0x0e);
        }
    }

    // ===== Key expansion (generic) =====
    void KeyExpansion(const byte *key, int Nk, int Nr, byte *roundKeys) {
        constexpr int Nb = 4;
        int totalWords = Nb * (Nr + 1);

        memcpy(roundKeys, key, Nk * 4);

        byte temp[4];

        for (int i = Nk; i < totalWords; i++) {
            memcpy(temp, &roundKeys[4 * (i - 1)], 4);

            if (i % Nk == 0) {
                byte t = temp[0];
                temp[0] = sbox[temp[1]] ^ Rcon[i / Nk];
                temp[1] = sbox[temp[2]];
                temp[2] = sbox[temp[3]];
                temp[3] = sbox[t];
            } else if (Nk > 6 && i % Nk == 4) {
                for (int j = 0; j < 4; j++)
                    temp[j] = sbox[temp[j]];
            }

            for (int j = 0; j < 4; j++)
                roundKeys[4 * i + j] = roundKeys[4 * (i - Nk) + j] ^ temp[j];
        }
    }

    // ===== Block encryption (generic) =====
    void EncryptBlock(byte *block, const byte *rk, int Nr) {
        AddRoundKey(block, rk);

        for (int r = 1; r < Nr; r++) {
            SubBytes(block);
            ShiftRows(block);
            MixColumns(block);
            AddRoundKey(block, rk + 16 * r);
        }

        SubBytes(block);
        ShiftRows(block);
        AddRoundKey(block, rk + 16 * Nr);
    }

    void DecryptBlock(byte *block, const byte *rk, int Nr) {
        AddRoundKey(block, rk + 16 * Nr);
        for (int r = Nr - 1; r >= 1; r--) {
            InvShiftRows(block);
            InvSubBytes(block);
            AddRoundKey(block, rk + 16 * r);
            InvMixColumns(block);
        }
        InvShiftRows(block);
        InvSubBytes(block);
        AddRoundKey(block, rk);
    }

    // ===== CBC mode (generic) =====
    std::vector<byte> encryptCBC(const std::vector<byte> &plaintext, const byte *key, int Nk, int Nr, const byte iv[16]) {
        byte roundKeys[240];
        KeyExpansion(key, Nk, Nr, roundKeys);

        std::vector<byte> data = pkcs7_pad(plaintext);
        std::vector<byte> out(data.size());

        byte prev[16];
        memcpy(prev, iv, 16);

        for (size_t i = 0; i < data.size(); i += 16) {
            byte block[16];
            for (int j = 0; j < 16; j++)
                block[j] = data[i + j] ^ prev[j];

            EncryptBlock(block, roundKeys, Nr);
            memcpy(&out[i], block, 16);
            memcpy(prev, block, 16);
        }

        return out;
    }

    std::vector<byte> decryptCBC(const std::vector<byte> &ciphertext, const byte *key, int Nk, int Nr, const byte iv[16]) {
        byte roundKeys[240];
        KeyExpansion(key, Nk, Nr, roundKeys);

        if (ciphertext.size() % 16 != 0)
            throw std::runtime_error("Ciphertext not multiple of 16 bytes");

        std::vector<byte> out(ciphertext.size());
        byte prev[16];
        memcpy(prev, iv, 16);

        for (size_t i = 0; i < ciphertext.size(); i += 16) {
            byte block[16];
            memcpy(block, &ciphertext[i], 16);

            DecryptBlock(block, roundKeys, Nr);

            // XOR with previous ciphertext (or IV)
            for (int j = 0; j < 16; j++)
                block[j] ^= prev[j];

            memcpy(&out[i], block, 16);
            memcpy(prev, &ciphertext[i], 16);
        }

        // Remove PKCS#7 padding
        pkcs7_unpad(out);

        return out;
    }

    // ===== PKCS#7 Padding =====
    std::vector<byte> pkcs7_pad(const std::vector<byte> &in) {
        size_t pad = BLOCK_SIZE - (in.size() % BLOCK_SIZE);
        if (pad == 0)
            pad = BLOCK_SIZE;

        std::vector<byte> out = in;
        out.insert(out.end(), pad, static_cast<byte>(pad));
        return out;
    }

    // ===== PKCS#7 Unpadding =====
    void pkcs7_unpad(std::vector<byte> &data) {
        if (data.empty() || data.size() % BLOCK_SIZE != 0)
            throw std::runtime_error("Invalid padded data size");

        byte pad = data.back();
        if (pad < 1 || pad > BLOCK_SIZE)
            throw std::runtime_error("Invalid PKCS#7 padding");

        for (size_t i = 0; i < pad; i++) {
            if (data[data.size() - 1 - i] != pad)
                throw std::runtime_error("Invalid PKCS#7 padding");
        }

        data.resize(data.size() - pad);
    }

    static inline constexpr byte inv_sbox[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e,
        0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66,
        0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65,
        0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
        0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91,
        0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
        0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2,
        0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb,
        0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

    // === Constants ===
    static inline constexpr byte sbox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4,
        0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3,
        0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3,
        0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c,
        0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
        0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
        0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
        0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

    static inline constexpr byte Rcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class FileStorage {
  public:
    std::vector<std::vector<Line>> columns = {col1, col2, col3};

    void initializeMasterKeyFromPassword(const std::string &password, bool createNew) {
        KeyDerivation::DerivedKey dk;

        if (createNew) {
            dk = kd.deriveKeyFromPassword(password);
            writeFile(fileSystem.file_salt, dk.salt); // Use FileSystem instance
        } else {
            auto salt = readFile(fileSystem.file_salt); // Use FileSystem instance
            dk = kd.deriveKeyFromPassword(password, salt);
        }

        // Convert string key to bytes
        std::vector<uint8_t> keyBytes(dk.key.begin(), dk.key.end());

        // Store in master key
        masterKey.set(keyBytes, dk.salt);

        col2.push_back({"Master key initialized and ready", Align::LEFT});
        columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4);

        // Wait for a second or two, or three...
        std::this_thread::sleep_for(std::chrono::seconds(2));

        col2.clear();
        functions.clearConsole();
    }

    void encryptAppFiles() {
        if (!masterKey.isValid) {
            LOG_ERROR("Master key not initialized!");
            return;
        }

        // Get files from FileSystem instance
        std::vector<fs::path> files = {
            fileSystem.file_1, fileSystem.file_2, fileSystem.file_3, fileSystem.file_4, fileSystem.file_5, fileSystem.file_6, fileSystem.file_7, fileSystem.file_8};

        for (const auto &srcPath : files) {
            if (!fs::exists(srcPath)) {
                continue;
            }

            auto fileData = readFile(srcPath);

            std::vector<uint8_t> plaintext;

            // Add actual file data
            plaintext.insert(plaintext.end(), fileData.begin(), fileData.end());

            // Skip if no data to encrypt
            if (plaintext.empty()) {
                continue;
            }

            // --- Create header (unencrypted) ---
            std::string header = "APPDATAv1\nFILE:" + srcPath.filename().string() + "\n\n";

            // --- Generate IV ---
            auto iv = aes.generateIV(bep);

            // Use master key
            uint8_t key[32];
            std::copy(masterKey.key.begin(), masterKey.key.end(), key);

            // --- Encrypt ---
            auto ciphertext = aes.encryptCBC256(plaintext, key, iv.data());

            fs::path encPath = srcPath.string() + ".enc";

            // Write to file in a scoped block to ensure it's closed
            {
                std::ofstream out(encPath, std::ios::binary);
                if (!out) {
                    LOG_ERROR("Failed to create encrypted file: " + encPath.string());
                    continue;
                }

                // Write header as text (unencrypted)
                out << header;

                // Write salt (binary)
                out.write(reinterpret_cast<const char *>(masterKey.salt.data()), masterKey.salt.size());

                // Write IV (binary)
                out.write(reinterpret_cast<const char *>(iv.data()), iv.size());

                // Write ciphertext (binary)
                out.write(reinterpret_cast<const char *>(ciphertext.data()), ciphertext.size());

                out.flush();
                out.close();
            }

            // Now safe to remove original file
            try {
                fs::remove(srcPath);
                col2.push_back({"Encrypted: " + srcPath.string() + " -> " + encPath.string(), Align::LEFT});
                columns = {col1, col2, col3};
                std::cout << render.printColumns(columns, 80, 4);
            } catch (const fs::filesystem_error &e) {
                LOG_ERROR("[WARN] Could not delete original file: " + srcPath.string() + " ... " + e.what());
            }
        }

        col2.push_back({"File encryption complete", Align::LEFT});
        columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4);
    }

    void decryptAppFiles() {
        if (!masterKey.isValid) {
            LOG_ERROR("Master key not initialized!");
            return;
        }

        col2.push_back({"Decrypting files with master key...", Align::LEFT});
        columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4);

        // Get files from FileSystem instance
        std::vector<fs::path> files = {
            fileSystem.file_1, fileSystem.file_2, fileSystem.file_3, fileSystem.file_4, fileSystem.file_5, fileSystem.file_6, fileSystem.file_7, fileSystem.file_8};

        size_t fileIndex = 0;

        for (const auto &plainPath : files) {
            ++fileIndex;

            fs::path encPath = plainPath.string() + ".enc";

            if (!fs::exists(encPath)) {
                // No encrypted file exists, skip silently
                continue;
            }

            std::vector<uint8_t> salt(16);
            std::array<uint8_t, 16> iv{};
            std::vector<uint8_t> ciphertext;
            std::string header;

            // Read file in scoped block
            {
                std::ifstream in(encPath, std::ios::binary);
                if (!in) {
                    LOG_ERROR("Failed to open file: " + encPath.string());
                    continue;
                }

                // Read header (unencrypted) - stop at double newline "\n\n"
                char ch;
                char prevCh = 0;
                while (in.get(ch)) {
                    header += ch;
                    // Check for double newline (end of header)
                    if (prevCh == '\n' && ch == '\n') {
                        break;
                    }
                    prevCh = ch;
                }

                // Read salt (ignore it, we use master key)
                in.read(reinterpret_cast<char *>(salt.data()), salt.size());

                // Read IV
                in.read(reinterpret_cast<char *>(iv.data()), iv.size());

                // Read ciphertext
                ciphertext.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());

                in.close();
            }

            // --- Sanity checks ---
            if (ciphertext.empty()) {
                // No encrypted data, create empty file
                std::ofstream out(plainPath, std::ios::binary);
                out.close();
                continue;
            }

            if (ciphertext.size() % 16 != 0) {
                LOG_ERROR("Ciphertext not AES-block aligned in " + encPath.string());
                continue;
            }

            // --- Use master key ---
            uint8_t key[32];
            std::copy(masterKey.key.begin(), masterKey.key.end(), key);

            // --- Decrypt ---
            auto plaintext = aes.decryptCBC256(ciphertext, key, iv.data());

            // --- Write plaintext ---
            writeFile(plainPath, plaintext);

            // --- Remove encrypted file ---
            try {
                fs::remove(encPath);
            } catch (const fs::filesystem_error &e) {
                LOG_ERROR("Could not delete encrypted file: " + encPath.string());
            }
        }

        col2.push_back({"File decryption complete", Align::LEFT});
        columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4);
    }

    // Clear master key from memory (call on exit)
    void clearMasterKey() { masterKey.clear(); }

  private:
    KeyDerivation kd;
    AES aes;
    BinaryEntropyPool bep;
    MasterKey masterKey; // Single master key for entire session
    Render render;

    // Helper: read entire file into vector<byte>
    std::vector<AES::byte> readFile(const fs::path &path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) {
            LOG_ERROR("FileStorage::readFile... Cannot open file: " + path.string());
            throw std::runtime_error("Cannot open file: " + path.string());
        }

        auto size = file.tellg();
        std::vector<AES::byte> buffer(size);

        file.seekg(0, std::ios::beg);
        file.read(reinterpret_cast<char *>(buffer.data()), size);
        if (file.gcount() != size) {
            LOG_ERROR("FileStorage::readFile... Incomplete read from file: " + path.string());
            throw std::runtime_error("Incomplete read from file: " + path.string());
        }

        return buffer;
    }

    // Helper: write vector<byte> to file
    void writeFile(const fs::path &path, const std::vector<AES::byte> &data) {
        std::ofstream file(path, std::ios::binary);
        if (!file) {
            LOG_ERROR("FileStorage::writeFile... Cannot write file: " + path.string());
            throw std::runtime_error("Cannot write file: " + path.string());
        }

        file.write(reinterpret_cast<const char *>(data.data()), data.size());
        file.flush();
        file.close();
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class GenerateUUID {
  public:
    GenerateUUID() : UUIDGenerated(false) {}

    inline std::pair<std::string, std::string> generateUUID() {
        std::string timestamp = generateTimestamp(); // 13-digit timestamp

        std::string binary = entropyPool.get(152); // 19 * 8, binary to Base62
        std::string randomPart = metaData.binaryToBase62WithPadding(binary);
        std::string fullStr = timestamp + randomPart; // Concatenate

        std::string UUID = formatUUID(fullStr); // Add hyphens

        if (!UUIDGenerated) {
            UUIDGenerated = true;
            firstUUID = UUID;
            return {firstUUID, firstUUID};
        } else {
            lastUUID = UUID;
            return {firstUUID, lastUUID};
        }
    }

  private:
    RandomNumberGenerator rng;
    BinaryEntropyPool entropyPool;
    MetaData metaData;

    bool UUIDGenerated;

    std::string firstUUID;
    std::string lastUUID;

    inline std::string generateTimestamp() { return std::to_string(systemClock.getMilliseconds()); }

    inline std::string formatUUID(const std::string &fullStr) {
        std::stringstream uuid;

        // Format: 8-4-4-4-12 = 32 characters total
        uuid << fullStr.substr(0, 8) << "-";
        uuid << fullStr.substr(8, 4) << "-";
        uuid << fullStr.substr(12, 4) << "-";
        uuid << fullStr.substr(16, 4) << "-";
        uuid << fullStr.substr(20, 12);

        return uuid.str();
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class myRSA {
  public:
    // Constructor: provide two 32-bit primes
    myRSA(uint32_t prime1, uint32_t prime2) : P1(prime1), P2(prime2) {
        n = static_cast<uint64_t>(P1) * static_cast<uint64_t>(P2);
        totient = static_cast<uint64_t>(P1 - 1) * static_cast<uint64_t>(P2 - 1);

        e = 65537; // common public exponent

        d = modInverse(e, totient);
        if (d == 0)
            throw std::runtime_error("Failed to compute modular inverse for private exponent");
    }

    // Show key info
    void showKeys() const {
        std::cout << "P1 = " << P1 << ", P2 = " << P2 << "\n";
        std::cout << "n  = " << n << ", totient = " << totient << "\n";
        std::cout << "Public key (n,e) = (" << n << ", " << e << ")\n";
        std::cout << "Private key (n,d) = (" << n << ", " << d << ")\n";
    }

    std::pair<uint64_t, uint64_t> getPublicKey() const { return {n, e}; }
    std::pair<uint64_t, uint64_t> getPrivateKey() const { return {n, d}; }

    // Encrypt small integer message
    uint64_t encrypt(uint64_t message) const {
        if (message >= n)
            throw std::runtime_error("Message too large for this key");
        return modExp(message, e, n);
    }

    // Decrypt small integer message
    uint64_t decrypt(uint64_t ciphertext) const { return modExp(ciphertext, d, n); }

    // Sign a message (64-bit integer)
    uint64_t sign(uint64_t message) const {
        if (message >= n)
            throw std::runtime_error("Message too large for signing");
        return modExp(message, d, n);
    }

    // Verify a signature (returns true if valid)
    bool verify(uint64_t message, uint64_t signature) const {
        uint64_t recovered = modExp(signature, e, n);
        return recovered == message;
    }

    // Verify a signature using a supplied public key (n,e)
    bool verifyWithPublicKey(const std::string &pubKeyStr, uint64_t message, uint64_t signature) const {
        // Parse "n,e" from string
        size_t commaPos = pubKeyStr.find(',');
        if (commaPos == std::string::npos)
            return false;

        uint64_t n_ = std::stoull(pubKeyStr.substr(0, commaPos));
        uint64_t e_ = std::stoull(pubKeyStr.substr(commaPos + 1));

        // Recover the message using the provided public key
        uint64_t recovered = modExp(signature, e_, n_);
        return recovered == message;
    }

    std::string getReceiveAddress() const {
        auto [n, e] = getPublicKey();
        std::ostringstream oss;
        oss << n << "," << e; // public key as string
        return oss.str();
    }

    uint64_t computeGCD(uint64_t a, uint64_t b) const { return gcd(a, b); }

    uint64_t computeModExp(uint64_t base, uint64_t exp, uint64_t mod) const { return modExp(base, exp, mod); }

    uint64_t computeModInverse(uint64_t a, uint64_t m) const { return modInverse(a, m); }

    uint64_t computeModMul(uint64_t a, uint64_t b, uint64_t mod) const { return modMul(a, b, mod); }

    uint64_t generateRandomCoprime(uint64_t mod) const { return randomCoprime(mod); }

  private:
    uint64_t P1;
    uint64_t P2;
    uint64_t n;
    uint64_t totient;
    uint64_t e;
    uint64_t d;

    // GCD
    uint64_t gcd(uint64_t a, uint64_t b) const {
        while (b != 0) {
            uint64_t t = b;
            b = a % b;
            a = t;
        }
        return a;
    }

    // Random coprime
    uint64_t randomCoprime(uint64_t n) const {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dist(2, n - 1);
        uint64_t r;
        do {
            r = dist(gen);
        } while (gcd(r, n) != 1);
        return r;
    }

    // Modular multiply
    static uint64_t modMul(uint64_t a, uint64_t b, uint64_t mod) {
        uint64_t result = 0;
        a %= mod;
        b %= mod;
        while (b > 0) {
            if (b & 1)
                result = (result + a) % mod;
            a = (a << 1) % mod;
            b >>= 1;
        }
        return result;
    }

    // Modular exponentiation
    static uint64_t modExp(uint64_t base, uint64_t exp, uint64_t mod) {
        uint64_t result = 1;
        base %= mod;
        while (exp > 0) {
            if (exp & 1)
                result = modMul(result, base, mod);
            base = modMul(base, base, mod);
            exp >>= 1;
        }
        return result;
    }

    // Modular inverse
    static uint64_t modInverse(uint64_t a, uint64_t m) {
        int64_t m0 = m, t, q;
        int64_t x0 = 0, x1 = 1;

        if (m == 1)
            return 0;

        int64_t a_ = a;
        int64_t m_ = m;

        while (a_ > 1) {
            if (m_ == 0)
                return 0; // No inverse

            q = a_ / m_;
            t = m_;
            m_ = a_ % m_;
            a_ = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }

        if (x1 < 0)
            x1 += m0;

        return static_cast<uint64_t>(x1);
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

// --- Global RSA instances ---
myRSA Alice(2147483647, 2147483629);  // Alice's 32-bit primes
myRSA Bob(2147483613, 2147483623);    // Bob's 32-bit primes
myRSA Kraken(2147483659, 2147483663); // Kraken's 32-bit primes

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

// Type aliases
using u64 = unsigned long long;
using u128 = unsigned __int128;

// Modular arithmetic
u64 modAdd(u64 a, u64 b, u64 m) {
    return (a % m + b % m) % m;
}
u64 modSub(u64 a, u64 b, u64 m) {
    return (a % m + m - b % m) % m;
}
u64 modMul(u64 a, u64 b, u64 m) {
    return (u64)((u128)a * b % m);
}

// Extended Euclidean Algorithm for modular inverse
u64 modInv(u64 a, u64 m) {
    long long t = 0, newt = 1;
    long long r = m, newr = a;
    while (newr != 0) {
        long long q = r / newr;
        long long tmp = newt;
        newt = t - q * newt;
        t = tmp;
        tmp = newr;
        newr = r - q * newr;
        r = tmp;
    }
    if (r > 1)
        throw std::runtime_error("Not invertible");
    if (t < 0)
        t += m;
    return (u64)t;
}

// Elliptic curve point
struct Point {
    u64 x, y;
    bool inf;
    Point() : x(0), y(0), inf(true) {}
    Point(u64 _x, u64 _y) : x(_x), y(_y), inf(false) {}
};

// Toy curve: y^2 = x^3 + 7 mod p
class Curve {
  public:
    static constexpr u64 P = (1ULL << 61) - 1; // prime < 2^61
    Point G;

    Curve() : G(2, 22) {} // chosen generator point

    Point add(const Point &A, const Point &B) const {
        if (A.inf)
            return B;
        if (B.inf)
            return A;
        if (A.x == B.x && A.y != B.y)
            return Point(); // infinity

        u64 m;
        if (A.x == B.x && A.y == B.y) {
            // slope = (3x^2) / (2y)
            u64 num = modMul(3, modMul(A.x, A.x, P), P);
            u64 den = modInv(modMul(2, A.y, P), P);
            m = modMul(num, den, P);
        } else {
            u64 num = modSub(B.y, A.y, P);
            u64 den = modInv(modSub(B.x, A.x, P), P);
            m = modMul(num, den, P);
        }

        u64 xr = modSub(modMul(m, m, P), modAdd(A.x, B.x, P), P);
        u64 yr = modSub(modMul(m, modSub(A.x, xr, P), P), A.y, P);
        return Point(xr, yr);
    }

    Point mul(u64 k, Point P) const {
        Point R; // infinity
        while (k > 0) {
            if (k & 1)
                R = add(R, P);
            P = add(P, P);
            k >>= 1;
        }
        return R;
    }
};

// ECDSA
class ECDSA {
    const Curve &curve;
    u64 order; // subgroup order (toy: use P)
  public:
    struct KeyPair {
        u64 priv;
        Point pub;
    };
    struct Signature {
        u64 r, s;
    };

    ECDSA(const Curve &c) : curve(c), order(c.P) {}

    KeyPair generateKey() {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<u64> dist(1, order - 1);

        u64 priv = dist(gen);
        Point pub = curve.mul(priv, curve.G);
        return {priv, pub};
    }

    Signature sign(u64 priv, u64 msgHash) {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<u64> dist(1, order - 1);

        u64 k = dist(gen);

        Point R = curve.mul(k, curve.G);
        u64 r = R.x % order;
        u64 kinv = modInv(k, order);
        u64 s = modMul(kinv, (msgHash + modMul(r, priv, order)) % order, order);

        return {r, s};
    }

    bool verify(const Point &pub, u64 msgHash, const Signature &sig) {
        if (sig.r == 0 || sig.s == 0)
            return false;
        u64 w = modInv(sig.s, order);
        u64 u1 = modMul(msgHash, w, order);
        u64 u2 = modMul(sig.r, w, order);

        Point P1 = curve.mul(u1, curve.G);
        Point P2 = curve.mul(u2, pub);
        Point X = curve.add(P1, P2);

        return (X.x % order) == sig.r;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class GlobalDatabase {
  public:
    struct DatasetEntry {
        std::string uuid;
        std::string publicKey;
        std::string endpoint;
        std::string address;
        std::string message;
        std::string hash;
        std::string signature;

        DatasetEntry() = default;

        DatasetEntry(
            const std::string &uuid, const std::string &modulus, const std::string &exponent, const std::string &ipAddress, const std::string &port, const std::string &address)
            : uuid(uuid), address(address) {
            // Build publicKey and endpoint
            publicKey = modulus + ":" + exponent;
            endpoint = ipAddress + ":" + port;

            // Build the message, hash it, and sign
            message = uuid + ":" + publicKey + ":" + endpoint + ":" + address;
            hash = sha256(message);
            uint64_t txHashInt = functions.hashToUint60(hash);
            signature = Alice.sign(txHashInt);
        }
    };

    // Add a dataset entry using only modulus, exponent, IP, port, and address
    void add(const std::string &modulus, const std::string &exponent, const std::string &ipAddress, const std::string &port, const std::string &address) {
        // Generate UUID internally
        auto [_, uuid] = uuidGenerator.generateUUID();

        // Create entry
        DatasetEntry entry(uuid, modulus, exponent, ipAddress, port, address);

        // Store in maps
        uuidMap[uuid] = entry;
        publicKeyMap[entry.publicKey] = entry;
        endpointMap[entry.endpoint] = entry;
    }

    const DatasetEntry *getByUUID(const std::string &uuid) const {
        auto it = uuidMap.find(uuid);
        return it != uuidMap.end() ? &it->second : nullptr;
    }

    const DatasetEntry *getByPublicKey(const std::string &publicKey) const {
        auto it = publicKeyMap.find(publicKey);
        return it != publicKeyMap.end() ? &it->second : nullptr;
    }

    const DatasetEntry *getByEndpoint(const std::string &endpoint) const {
        auto it = endpointMap.find(endpoint);
        return it != endpointMap.end() ? &it->second : nullptr;
    }

  private:
    std::unordered_map<std::string, DatasetEntry> uuidMap;
    std::unordered_map<std::string, DatasetEntry> publicKeyMap;
    std::unordered_map<std::string, DatasetEntry> endpointMap;

    GenerateUUID uuidGenerator; // internal UUID generator
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class SetMnemonic {
  public:
    SetMnemonic() : manager(), encoder(manager), bep() { LOG_INFO("Class: SetMnemonic"); }

    void run() {
        std::string mnemonicBits = bep.get(bitsNeeded);
        words = encoder.binaryToWords(mnemonicBits);

        displayMnemonic(words);

        while (!verifyMnemonic(words)) {
            retryScreen();
        }

        mnemonicString.clear();
        for (const auto &w : words)
            mnemonicString += w; // ← NO SPACES

        successScreen();
    }

    std::string getMnemonicString() const { return mnemonicString; }

  private:
    WordListManager manager;
    WordEncoder encoder;
    BinaryEntropyPool bep;
    Render render;

    std::vector<std::string> words;
    std::string mnemonicString;

    const int wordCount = 12;
    const int bitsNeeded = wordCount * 11;
    std::string dash = std::string(80, '-');

    void retryScreen() {
        col2.clear();
        functions.clearConsole();
        header();
        col2.push_back({"Verification failed. Try again.", Align::CENTER});
        std::cout << render.printColumns({col1, col2, col3}, 80, 4);
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    void successScreen() {
        col2.clear();
        functions.clearConsole();
        header();
        col2.push_back({"Mnemonic verified successfully!", Align::CENTER});
        std::cout << render.printColumns({col1, col2, col3}, 80, 4);
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    void header() {
        render.addEmptyLines(col2, 10);
        col2.push_back({dash, Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({"--- RECOVERY PHRASE SETUP ---", Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({dash, Align::CENTER});
    }

    void displayMnemonic(const std::vector<std::string> &words) {
        col2.clear();
        functions.clearConsole();
        header();
        render.addEmptyLines(col2, 1);

        col2.push_back({"Your 12-Word Recovery Phrase", Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({dash, Align::CENTER});
        render.addEmptyLines(col2, 1);

        col2.push_back({"WRITE DOWN THESE WORDS IN ORDER:", Align::CENTER});
        render.addEmptyLines(col2, 1);

        // Display words in pairs (2 columns)
        for (size_t i = 0; i < words.size(); i += 2) {
            std::string line1 = " " + std::to_string(i + 1) + ". " + words[i];
            std::string line2 = "";

            if (i + 1 < words.size()) {
                line2 = "        " + std::to_string(i + 2) + ". " + words[i + 1];
            }

            col2.push_back({line1 + line2, Align::LEFT});
        }

        render.addEmptyLines(col2, 2);
        col2.push_back({dash, Align::CENTER});
        render.addEmptyLines(col2, 1);

        col2.push_back({"IMPORTANT SECURITY WARNINGS:", Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({" - Write these words on paper - DO NOT save digitally", Align::LEFT});
        col2.push_back({" - Store in a safe, secure location", Align::LEFT});
        col2.push_back({" - NEVER share your recovery phrase with anyone", Align::LEFT});
        col2.push_back({" - Anyone with these words can access your account", Align::LEFT});
        col2.push_back({" - If you lose these words, you cannot recover your account", Align::LEFT});
        render.addEmptyLines(col2, 2);

        col2.push_back({"Press Enter when you have written down all 12 words...", Align::CENTER});

        std::vector<std::vector<Line>> columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4);

        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get();
    }

    bool verifyMnemonic(const std::vector<std::string> &originalWords) {
        col2.clear();
        functions.clearConsole();
        header();
        render.addEmptyLines(col2, 2);

        col2.push_back({"Verification Required", Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({dash, Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({"Please re-enter your 12-word recovery phrase.", Align::CENTER});
        col2.push_back({"Enter each word one at a time.", Align::CENTER});
        render.addEmptyLines(col2, 2);

        std::vector<std::vector<Line>> columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4);

        std::vector<std::string> inputWords;
        inputWords.reserve(originalWords.size());

        for (size_t i = 0; i < originalWords.size(); ++i) {
            col2.clear();
            functions.clearConsole();
            header();
            render.addEmptyLines(col2, 1);

            col2.push_back({"Verification - Word " + std::to_string(i + 1) + " of 12", Align::CENTER});
            render.addEmptyLines(col2, 1);
            col2.push_back({dash, Align::CENTER});
            render.addEmptyLines(col2, 2);

            // Show previously entered words
            if (i > 0) {
                col2.push_back({"Words entered so far:", Align::LEFT});
                render.addEmptyLines(col2, 1);
                for (size_t j = 0; j < i; ++j) {
                    col2.push_back({" " + std::to_string(j + 1) + ". " + inputWords[j] + " ✓", Align::LEFT});
                }
                render.addEmptyLines(col2, 2);
            }

            col2.push_back({"Enter word " + std::to_string(i + 1) + ": ", Align::LEFT});

            columns = {col1, col2, col3};
            std::cout << render.printColumns(columns, 80, 4);

            std::string word;
            std::getline(std::cin, word);
            word = normalizeWord(word);

            if (word != originalWords[i]) {
                col2.clear();
                functions.clearConsole();
                header();
                render.addEmptyLines(col2, 2);
                col2.push_back({"Incorrect word entered!", Align::CENTER});
                render.addEmptyLines(col2, 1);
                col2.push_back({"You entered: " + word, Align::LEFT});
                col2.push_back({"Expected: " + originalWords[i], Align::LEFT});
                render.addEmptyLines(col2, 2);
                col2.push_back({"Please start again from the beginning.", Align::CENTER});
                render.addEmptyLines(col2, 2);

                columns = {col1, col2, col3};
                std::cout << render.printColumns(columns, 80, 4);

                std::this_thread::sleep_for(std::chrono::seconds(3));
                return false;
            }
            inputWords.push_back(word);
        }

        return true;
    }

    std::string normalizeWord(const std::string &input) {
        std::string s = input;
        // trim leading/trailing whitespace
        size_t start = s.find_first_not_of(" \t\n\r");
        size_t end = s.find_last_not_of(" \t\n\r");
        if (start == std::string::npos)
            return "";
        s = s.substr(start, end - start + 1);

        // to lowercase
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });

        return s;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class SetUUID {
  public: /*
       void message() {
           Alice.showKeys();

           // Step 1: Create UUID
           auto [uuid, _] = uuidGenerator.generateUUID();

           // Step 2: Create Message
           std::string message = "Hi";

           // Step 3: Create Public Key (unsigned long long)
           auto [n, e] = Alice.getPublicKey();
           std::cout << "\n| Public key: (" << n << ", " << e << ")\n";

           // Step 4: Sign Encrypted Message
           uint64_t signature = Alice.sign(message);

           // Step 5: Return Message and Signature
           std::cout << "\n| Message: " << message << "\n";
           std::cout << "| Signature: " << signature << "\n";

           // Step 6: Verify Message
           bool valid = rsa.verify(message, signature);
           std::cout << "| Verification result: " << (valid ? "Valid" : "Invalid") << "\n";

           // Step 7: Create combined string for hashing
           std::ostringstream oss;
           oss << uuid << "|" << message << "|" << signature << "|" << m << "|" << e;
           std::string combined = oss.str();

           // Step 8: Hash
           sha.update(combined);
           std::string hash = sha.digest();

           // Step 9: Store in database — pass m and e directly (unsigned long long)
           globalDB.addNextDataset(uuid, message, std::to_string(signature), std::to_string(m), std::to_string(e),
       "127.0.0.1", "8080", hash);

           // Step 10: Output
           const auto* data = globalDB.getDataset(uuid);
           if (data) {
               std::cout << "| \n--- Dataset Information ---\n";
               std::cout << "| UUID: " << data->uuid << "\n";
               std::cout << "| Message: " << data->message << "\n";
               std::cout << "| Signature: " << data->signature << "\n";
               std::cout << "| Public Key (n): " << data->modulus << "\n";
               std::cout << "| Public Key (e): " << data->exponent << "\n";
               std::cout << "| IP: " << data->ipAddress << ", Port: " << data->portNumber << "\n";
               std::cout << "| Hash: " << data->hash << "\n";
           }

       }*/
  private:
    GlobalDatabase globalDB;
    GenerateUUID uuidGenerator;
    // RSA Alice;
    CRYPTO::SHA256 sha;
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class SecureInput {
  public:
    std::string getInput(const std::string &prompt) {
        std::cout << prompt;
        std::cout.flush();

        // Turn off echo
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode;
        GetConsoleMode(hStdin, &mode);
        SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);

        std::string input;
        char c;
        while (std::cin.get(c)) {
            if (c == '\n' || c == '\r') {
                break;
            }
            input += c;
            std::cout << '*';
            std::cout.flush();
        }

        std::cout << std::endl;

        // Turn echo back on
        SetConsoleMode(hStdin, mode);

        return input;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class BlockchainFunctions {
  public:
    struct TxInput {
        std::string previous_txid;
        int output_index;
        std::vector<std::string> signatures; // M signatures for multisig
    };

    struct TxOutput {
        std::vector<std::string> pubkeyHashes; // multiple keys
        int requiredSignatures = 1;            // M-of-N threshold
        double amount;                         // total amount sent
        std::vector<std::string> types;        // "payment", "change", "coinbase"
    };

    struct UTXO {
        std::string txid;
        int index;
        TxOutput output;

        double amount() const { return output.amount; }
    };

    struct Wallet {
        std::string publicKey;  // e.g., "n,e"
        std::string privateKey; // e.g., "n,d"
        std::vector<std::pair<std::string, std::string>> addresses;
        std::vector<UTXO> utxos;
        int addressCounter = 0;
        std::string minerAddress;

        void setMinerAddress(const std::string &addr) { minerAddress = addr; }

        std::string getPrivateKey() const { return privateKey; }
        std::string getPublicKey() const { return publicKey; }

        double getBalance(const std::string &address) const {
            double total = 0.0;
            for (const auto &utxo : utxos) {
                if (std::find(utxo.output.pubkeyHashes.begin(), utxo.output.pubkeyHashes.end(), address) != utxo.output.pubkeyHashes.end()) {
                    total += utxo.amount();
                }
            }
            return total;
        }
    };

    struct BlockchainTransaction {
        std::string txid;
        std::vector<TxInput> inputs;
        std::vector<TxOutput> outputs;

        std::string toString() const {
            std::ostringstream oss;
            oss << "{\n";
            oss << "  \"txid\": \"" << txid << "\",\n";

            // Inputs
            oss << "  \"inputs\": [\n";
            for (size_t i = 0; i < inputs.size(); ++i) {
                const auto &in = inputs[i];
                oss << "    {\n";
                oss << "      \"previous_txid\": \"" << in.previous_txid << "\",\n";
                oss << "      \"output_index\": " << in.output_index << ",\n";
                oss << "      \"signatures\": [";
                for (size_t j = 0; j < in.signatures.size(); ++j) {
                    oss << "\"" << in.signatures[j] << "\"";
                    if (j + 1 < in.signatures.size())
                        oss << ", ";
                }
                oss << "]\n";
                oss << "    }" << (i + 1 < inputs.size() ? "," : "") << "\n";
            }
            oss << "  ],\n";

            // Outputs
            oss << "  \"outputs\": [\n";
            for (size_t i = 0; i < outputs.size(); ++i) {
                const auto &out = outputs[i];
                oss << "    {\n";
                oss << "      \"pubkeyHashes\": [";
                for (size_t j = 0; j < out.pubkeyHashes.size(); ++j) {
                    oss << "\"" << out.pubkeyHashes[j] << "\"";
                    if (j + 1 < out.pubkeyHashes.size())
                        oss << ", ";
                }
                oss << "],\n";
                oss << "      \"requiredSignatures\": " << out.requiredSignatures << ",\n";
                oss << "      \"amount\": " << out.amount << "\n";
                oss << "    }" << (i + 1 < outputs.size() ? "," : "") << "\n";
            }
            oss << "  ]\n";
            oss << "}\n";
            return oss.str();
        }
    };

    // --- Double SHA256 hash using toString() output ---
    std::string hashTransaction(const BlockchainTransaction &tx) { return sha256(sha256(tx.toString())); }

    // --- Sign transaction hash ---
    uint64_t signInput(const BlockchainTransaction &tx, const myRSA &rsa) {
        std::string hash = this->hashTransaction(tx);
        uint64_t hashInt = functions.hashToUint60(hash);
        return rsa.sign(hashInt);
    }

  private:
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

using UTXO = BlockchainFunctions::UTXO;
using Wallet = BlockchainFunctions::Wallet;
using TxInput = BlockchainFunctions::TxInput;
using TxOutput = BlockchainFunctions::TxOutput;
using BlockchainTransaction = BlockchainFunctions::BlockchainTransaction;

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

namespace Genesis {
const std::string HASH = "00000e57e1a42aae2296668a023c2cb3c2610622693d157f95fa69b340a1af59";
const std::string PREV_HASH = "a6d72baa3db900b03e70df880e503e9164013b4d9a470853edc115776323a098";
const std::string MERKLE = "1924bfe85ca71ecfba20aa44ed7916d913e4d66efdaea4f4cb8c88fd65c53bf2";
const uint64_t TIMESTAMP = 1761918414;
const uint64_t NONCE = 531710;
const double DIFFICULTY = 1000000.0;
} // namespace Genesis

class Blockchain {
  public:
    Blockchain(Wallet &w, bool shouldPrint = true) : wallet(w), printOutput(shouldPrint), difficulty(1000000), blockCount(0), totalTimeForInterval(0.0) {}

    void initializeMessage() {
        std::string message = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
        previousHash = sha256(message);
    }

    std::vector<BlockchainTransaction> mempool;

    std::vector<UTXO> getUTXOsForAddress(const std::string &address) {
        std::vector<UTXO> result;

        for (auto &block : blocks) {
            for (auto &tx : block.body.transactions) {
                for (size_t i = 0; i < tx.outputs.size(); ++i) {
                    const auto &out = tx.outputs[i];
                    if (std::find(out.pubkeyHashes.begin(), out.pubkeyHashes.end(), address) != out.pubkeyHashes.end()) {
                        UTXO u;
                        u.txid = tx.txid;
                        u.index = static_cast<int>(i);
                        u.output = out;
                        result.push_back(u);
                    }
                }
            }
        }

        return result;
    }

    void setPrintOutput(bool value) { printOutput = value; }

    void stopMining() { mining = false; }

    std::string getMinerAddress() const { return wallet.minerAddress; }

    uint64_t getBlockHeight() const { return static_cast<uint64_t>(blockCount); }
    /*
    void utxoManagement() {
        // Recycle old UTXOs based on inactivity
        for (auto it = UTXOSet.begin(); it != UTXOSet.end(); ) {
            UTXO& utxo = it->second;

            // Decrement inactivity counter if active
            if (utxo.inactivityCounter > 0) {
                utxo.inactivityCounter--;
            }

            // If UTXO has become inactive, move to recycling pool
            if (utxo.inactivityCounter == 0) {
                recyclingPool.push_back(utxo); // Add to recycling pool
                it = UTXOSet.erase(it);        // Remove from active UTXOs
            } else {
                ++it; // Only advance iterator if not erasing
            }
        }
    }
    */

    void run() {
        /*
        if (blockCount == 0 && previousHash.empty()) {
            initializeMessage(); // Set genesis "previous hash" once
        }
        */
        // Insert Genesis block if needed
        if (blocks.empty()) {
            Block genesis = createGenesisBlock();
            blocks.push_back(genesis);
            previousHash = genesis.header.blockHash; // Next block uses this as prev hash
            blockCount = 1;                          // Next mined block will be height 1
        }

        mining = true; // start mining
        while (mining) {
            uint64_t startTime = systemClock.getMilliseconds();
            uint64_t target = static_cast<uint64_t>(MAX_VALUE / difficulty);
            std::string timestamp = std::to_string(startTime);

            // Clear current transactions
            currentTransactions.clear();
            currentBlockSize = 0;

            // utxoManagement();

            BlockchainTransaction coinbaseTx = createCoinbaseTransaction(blockCount, minerAddress);
            currentTransactions.push_back(coinbaseTx);
            currentBlockSize += TRANSACTION_SIZE_ESTIMATE;

            // Include mempool transactions
            for (const auto &tx : mempool) {
                if (currentBlockSize + TRANSACTION_SIZE_ESTIMATE > MAX_BLOCK_SIZE)
                    break;
                currentTransactions.push_back(tx);
                currentBlockSize += TRANSACTION_SIZE_ESTIMATE;
            }

            // Compute Merkle root
            merkleRoot = buildMerkleRoot(currentTransactions);

            // Start mining
            uint64_t nonce = 0;
            while (mining) {
                BlockHeader header;
                header.height = blockCount;
                header.prevHash = previousHash;
                header.merkleRoot = merkleRoot;
                header.timestamp = startTime;
                header.nonce = nonce;
                header.difficulty = difficulty;
                header.target = static_cast<uint64_t>(MAX_VALUE / difficulty);

                std::string hash = computeBlockHash(header);
                uint64_t hashValue = functions.hexToUint64(hash.substr(0, 16));

                if (printOutput && nonce % 100000 == 0) {
                    if (nonce == 100000)
                        std::cout << "\n"; // add a newline before the first printed hash
                    std::cout << "Nonce: " << nonce << " Hash: " << hash.substr(0, 16) << " (value: " << hashValue << ")\n";
                }

                if (hashValue < target) {
                    uint64_t endTime = systemClock.getMilliseconds();
                    uint64_t timeTaken = endTime - startTime;

                    Block newBlock = createBlock(blockCount, previousHash, merkleRoot, endTime, nonce, hash, timeTaken, difficulty, currentTransactions);
                    blocks.push_back(newBlock);

                    // Add UTXOs for all transactions in this block
                    for (const auto &tx : currentTransactions) {
                        addUTXO(tx);
                    }

                    // Track block times for difficulty adjustment
                    blockTimes.push_back(static_cast<double>(timeTaken));
                    totalTimeForInterval += timeTaken;

                    // Compute summary stats
                    int numTxs = static_cast<int>(currentTransactions.size());
                    double totalTransferred = 0.0;
                    double totalFees = 0.0;
                    double coinbaseReward = 0.0;

                    for (size_t i = 0; i < currentTransactions.size(); i++) {
                        const auto &tx = currentTransactions[i];
                        double txOutputsSum = 0.0;
                        for (const auto &out : tx.outputs)
                            txOutputsSum += out.amount;
                        totalTransferred += txOutputsSum;

                        if (i == 0) {
                            // Coinbase is always the first transaction
                            coinbaseReward = txOutputsSum;
                        }
                    }

                    int count = std::min(static_cast<int>(blockTimes.size()), DIFFICULTY_ADJUSTMENT_INTERVAL);
                    double sum = 0.0;
                    for (int j = static_cast<int>(blockTimes.size()) - count; j < static_cast<int>(blockTimes.size()); j++)
                        sum += blockTimes[j];
                    double averageTime = sum / count;

                    // Print block summary
                    if (printOutput) {
                        std::cout << (blockCount == 0 ? "✅ GenesisBlockMined!\n" : "✅ Block #" + std::to_string(blockCount) + " mined!\n") << "Nonce: " << nonce << "\n"
                                  << "Hash: " << hash << "\n"
                                  << "Previous Hash: " << previousHash << "\n"
                                  << "Merkle Root: " << merkleRoot << "\n"
                                  << "Difficulty: " << difficulty << "\n"
                                  << "Timestamp: " << endTime << "\n"
                                  << "Duration: " << timeTaken << " seconds\n"
                                  << "Average time (last " << count << " blocks): " << averageTime << " seconds\n"
                                  << "Transactions: " << numTxs << "\n"
                                  << "Coinbase Reward: " << coinbaseReward << "\n"
                                  << "Total Transferred: " << totalTransferred << "\n"
                                  << "Fees Collected: " << totalFees << "\n"
                                  << "----------------------------------------------\n\n";
                    }

                    wallet.utxos = getUTXOsForAddress(wallet.minerAddress);

                    blockCount++;
                    if (blockCount % DIFFICULTY_ADJUSTMENT_INTERVAL == 0) {
                        updateDifficulty(totalTimeForInterval / DIFFICULTY_ADJUSTMENT_INTERVAL, TARGET_BLOCK_TIME);
                        totalTimeForInterval = 0.0;
                        blockTimes.clear();
                    }

                    previousHash = hash;
                    break;
                }
                nonce++;
            }
        }
    }

    void viewBlock(uint64_t height) {
        if (height >= blocks.size()) {
            std::cout << "❌ Block #" << height << " not found.\n";
            return;
        }

        const Block &block = blocks[height];
        const BlockHeader &h = block.header;

        std::cout << "\n📦 Block #" << h.height << " Details:\n";
        std::cout << "Hash: " << h.blockHash << "\n";
        std::cout << "Prev Hash: " << h.prevHash << "\n";
        std::cout << "Merkle Root: " << h.merkleRoot << "\n";
        std::cout << "Timestamp: " << h.timestamp << "\n";
        std::cout << "Nonce: " << h.nonce << "\n";
        std::cout << "Difficulty: " << h.difficulty << "\n";
        std::cout << "Target: " << h.target << "\n";
        std::cout << "Time Taken: " << block.actualTime << " seconds\n";
        std::cout << "Transactions (" << block.body.transactions.size() << "):\n";

        for (const auto &tx : block.body.transactions) {
            std::cout << " - " << tx.toString() << "\n";
        }
        std::cout << "----------------------------------------------\n";
    }

    struct BlockchainTransactionInfo {
        const BlockchainTransaction *tx = nullptr;
        size_t blockIndex = 0;
    };

    BlockchainTransactionInfo findTransactionByTxID(const std::string &txid) const {
        for (size_t i = 0; i < blocks.size(); ++i) {
            const auto &block = blocks[i];
            for (const auto &tx : block.body.transactions) {
                if (tx.txid == txid) {
                    return {&tx, i}; // Found the transaction in this block
                }
            }
        }
        return {nullptr, SIZE_MAX}; // Not found
    }

    UTXO *findUTXO(const std::string &prev_txid, uint32_t output_index) const {
        std::string key = prev_txid + ":" + std::to_string(output_index);
        auto it = UTXOSet.find(key);
        if (it != UTXOSet.end()) {
            return const_cast<UTXO *>(&it->second);
        }
        return nullptr;
    }

  private:
    Wallet &wallet;
    bool printOutput;
    double difficulty;
    int blockCount;
    double totalTimeForInterval;

    BlockchainFunctions bf;
    CRYPTO::SHA256 hasher;
    GenerateUUID uuidGenerator;

    bool mining = false;      // flag to control mining loop
    std::thread miningThread; // thread for mining
    std::string minerAddress; // store miner address

    uint64_t fee = 10'000; // 0.0001 coin = 10,000 satoshis

    std::string previousHash;

    std::string merkleRoot;
    std::mutex blocksMutex;

    std::vector<double> blockTimes;
    std::vector<BlockchainTransaction> currentTransactions;
    std::vector<std::pair<int, std::string>> derivedAddresses;
    std::unordered_map<std::string, UTXO> UTXOSet;
    std::vector<UTXO> recyclingPool;
    std::vector<UTXO> allUTXOs;

    size_t currentBlockSize = 0;

    struct BlockHeader {
        uint64_t height;        // position in the chain
        std::string prevHash;   // hash of previous block
        std::string merkleRoot; // root hash of all txs
        uint64_t timestamp;     // block creation time
        uint64_t nonce;         // proof-of-work value
        uint64_t target;        // difficulty target
        double difficulty;      // difficulty level
        std::string blockHash;  // hash of this header
    };

    struct BlockBody {
        std::vector<BlockchainTransaction> transactions; // full tx list
    };

    struct Block {
        BlockHeader header;  // header portion (metadata)
        BlockBody body;      // body portion (transactions)
        uint64_t actualTime; // seconds since previous block
    };

    std::vector<Block> blocks;

    Block createGenesisBlock() {
        std::vector<BlockchainTransaction> txs;
        BlockchainTransaction coinbase = createCoinbaseTransaction(0, wallet.minerAddress);
        txs.push_back(coinbase);

        Block genesis;
        genesis.header.height = 0;
        genesis.header.prevHash = Genesis::PREV_HASH;
        genesis.header.merkleRoot = Genesis::MERKLE;
        genesis.header.timestamp = Genesis::TIMESTAMP;
        genesis.header.nonce = Genesis::NONCE;
        genesis.header.difficulty = Genesis::DIFFICULTY;
        genesis.header.target = static_cast<uint64_t>(MAX_VALUE / genesis.header.difficulty);
        genesis.body.transactions = txs;
        genesis.header.blockHash = Genesis::HASH;

        return genesis;
    }

    Block createBlock(uint64_t height,
                      const std::string &prevHash,
                      const std::string &merkleRoot,
                      uint64_t timestamp,
                      uint64_t nonce,
                      const std::string &hash,
                      uint64_t timeTaken,
                      double difficulty,
                      const std::vector<BlockchainTransaction> &txs) {
        Block block;
        block.header.height = height;
        block.header.prevHash = prevHash;
        block.header.merkleRoot = merkleRoot;
        block.header.timestamp = timestamp;
        block.header.nonce = nonce;
        block.header.difficulty = difficulty;
        block.header.blockHash = hash;
        block.header.target = static_cast<uint64_t>(MAX_VALUE / difficulty);

        block.actualTime = timeTaken;
        block.body.transactions = txs;
        return block;
    }

    void updateDifficulty(double avgBlockTime, double targetTime) {
        difficulty *= targetTime / avgBlockTime;
        if (difficulty < 1)
            difficulty = 1;
        if (difficulty > MAX_DIFFICULTY)
            difficulty = MAX_DIFFICULTY;

        if (printOutput) {
            std::cout << "🔧 Difficulty adjusted to: " << difficulty << "\n\n";
        }
    }

    std::vector<UTXO> collectUTXOs(const std::string &masterPubKey, int maxCounter) {
        std::vector<UTXO> allUTXOs;

        for (int i = 1; i <= maxCounter; i++) {
            std::string derivedAddress = sha256(masterPubKey + std::to_string(i));
            auto utxos = getUTXOsForAddress(derivedAddress);
            allUTXOs.insert(allUTXOs.end(), utxos.begin(), utxos.end());
        }

        return allUTXOs;
    }

    uint64_t getBlockSubsidy(int blockHeight) {
        int era = blockHeight / HALVING_INTERVAL;
        uint64_t subsidy = INITIAL_SUBSIDY >> era;
        if (subsidy < 1)
            subsidy = 0;

        // Pull a small portion from recyclingPool
        if (!recyclingPool.empty()) {
            size_t amountToPull = 1; // e.g., 1 UTXO per block
            if (amountToPull > recyclingPool.size())
                amountToPull = recyclingPool.size();
            for (size_t i = 0; i < amountToPull; i++) {
                subsidy += recyclingPool.back().output.amount;
                recyclingPool.pop_back();
            }
        }
        return subsidy;
    }

    BlockchainTransaction createCoinbaseTransaction(int blockHeight, const std::string &minerAddress) {
        uint64_t subsidy = getBlockSubsidy(blockHeight);

        BlockchainTransaction coinbaseTx;
        coinbaseTx.inputs.clear();

        TxOutput output;
        output.pubkeyHashes = {minerAddress};
        output.requiredSignatures = 1;
        output.amount = INITIAL_SUBSIDY;
        output.types.push_back("coinbase");

        coinbaseTx.outputs.clear();
        coinbaseTx.outputs.push_back(output);

        auto [_, uuid] = uuidGenerator.generateUUID();
        coinbaseTx.txid = uuid;

        return coinbaseTx;
    }

    void addUTXO(const BlockchainTransaction &tx) {
        // Remove spent UTXOs
        for (const auto &input : tx.inputs) {
            std::string spentKey = input.previous_txid + ":" + std::to_string(input.output_index);
            auto it = UTXOSet.find(spentKey);
            if (it != UTXOSet.end()) {
                UTXOSet.erase(it);
            }
        }

        // Add new UTXOs
        for (size_t i = 0; i < tx.outputs.size(); i++) {
            const auto &out = tx.outputs[i];
            UTXO utxo;
            utxo.txid = tx.txid;
            utxo.index = static_cast<int>(i);
            utxo.output = out;

            std::string key = tx.txid + ":" + std::to_string(i);
            UTXOSet[key] = utxo;
        }
    }

    std::string buildMerkleRoot(std::vector<BlockchainTransaction> transactions) {
        if (transactions.empty())
            return "";

        // Sort transactions by timestamp extracted from UUID
        std::sort(
            transactions.begin(), transactions.end(), [this](const auto &a, const auto &b) { return functions.extractTimestamp(a.txid) < functions.extractTimestamp(b.txid); });

        // Collect ordered txids
        std::vector<std::string> hashes;
        for (const auto &tx : transactions)
            hashes.push_back(tx.txid);

        // Handle the single-transaction case
        if (hashes.size() == 1)
            return sha256(hashes[0]);

        // Build Merkle tree
        while (hashes.size() > 1) {
            if (hashes.size() % 2 != 0)
                hashes.push_back(hashes.back());

            std::vector<std::string> newLevel;
            for (size_t i = 0; i < hashes.size(); i += 2)
                newLevel.push_back(sha256(hashes[i] + hashes[i + 1]));
            hashes = newLevel;
        }

        return hashes[0];
    }

    std::string computeBlockHash(const BlockHeader &header) {
        std::ostringstream oss;
        oss << header.height << header.prevHash << header.merkleRoot << header.timestamp << header.nonce << header.difficulty;
        return sha256(oss.str());
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Interface_Transactions {
  public:
    Interface_Transactions(Wallet &w, Blockchain &bc) : wallet(w), blockchain(bc) {}

    // Single-signature transaction
    void SinglePayment() {
        getAmount();
        sendingAddress();
        recipientAddress();
        selectUTXOs();
        buildRecipientTx();
        addChange();
        finaliseAndBroadcastTx();
    }

    // --- main multisig function ---
    void MultiSignature() {
        getAmount();
        getKeys(keys, n, m, wallet);
        selectMultiSigUTXOs(keys);                 // Select inputs
        selectUTXOs();                             // Populate transaction inputs from selectedUTXOs
        buildMultiSigRecipientTx(keys, m, amount); // Add multisig recipient output
        addChange();                               // Add change if required
        finaliseAndBroadcastTx();                  // Finalize
    }

  private:
    Wallet &wallet;
    Blockchain &blockchain;
    BlockchainFunctions bf;
    GenerateUUID uuidGenerator;

    BlockchainTransaction tx;

    int64_t amount = 0;     // sats
    int64_t fee = 0;        // sats
    int64_t totalInput = 0; // sats
    int n, m;

    std::string fromAddress;
    std::string toAddress;

    // Contains all UTXOs associated with the wallet or the current fromAddress.
    // Acts as a local cache of the blockchain state for this wallet.
    std::vector<UTXO> utxos;

    // The subset of UTXOs that the user has chosen to spend in the current transaction.
    // Populated during sendingAddress() or selectFromAndUTXOs().
    std::vector<UTXO> selectedUTXOs;

    // Stores public key hashes (addresses) selected for multi-signature transactions.
    // Used in MultiSignature() when choosing N-of-M keys for a multisig output.
    std::vector<std::string> keys;

    // --- SinglePayment & MultiSignature Step 1: getAmount ---
    void getAmount() {
        std::cout << "Enter amount to send: ";
        std::cin >> amount;
        if (amount <= 0) {
            std::cout << "Amount must be positive.\n";
            return;
        }
    }

    // --- SinglePayment Step 2: sendingAddress ---
    void sendingAddress() {
        // Let the user select any address
        std::cout << "\nSelect sending address:\n";
        for (size_t i = 0; i < wallet.addresses.size(); ++i) {
            std::cout << i + 1 << ". " << wallet.addresses[i].first << " -> " << wallet.addresses[i].second << "\n";
        }

        size_t fromIndex{};
        std::cout << "Enter choice: ";
        std::cin >> fromIndex;
        if (fromIndex < 1 || fromIndex > wallet.addresses.size()) {
            std::cout << "Invalid selection!\n";
            return;
        }
        fromIndex--;
        fromAddress = wallet.addresses[fromIndex].second;

        // Get UTXOs for selected address
        utxos = blockchain.getUTXOsForAddress(fromAddress);

        if (utxos.empty()) {
            std::cout << "Selected address has no UTXOs.\n";
            return; // proceed, user can continue without inputs
        }

        // Let the user pick which UTXOs to use
        std::cout << "\nSelect UTXOs to spend (enter indices, 0 to finish):\n";
        for (size_t i = 0; i < utxos.size(); ++i) {
            std::cout << i + 1 << ". TXID: " << utxos[i].txid << "\n";

            // Display amount with commas
            std::cout << "    Amount: " << utxos[i].amount() << " sats\n";

            // std::cout << "    Locked: " << (utxos[i].locked ? "Yes" : "No") << "\n";
        }

        selectedUTXOs.clear();
        totalInput = 0; // reset totalInput before accumulating

        size_t choice{};
        while (true) {
            std::cout << "UTXO index (0 to finish): ";
            std::cin >> choice;
            if (choice == 0)
                break;
            if (choice < 1 || choice > utxos.size()) {
                std::cout << "Invalid index!\n";
                continue;
            }
            auto &u = utxos[choice - 1];
            selectedUTXOs.push_back(u);
            totalInput += u.amount(); // sum up total selected input
        }

        std::cout << "\nTotal input selected: " << totalInput << " sats\n";
    }

    // --- SinglePayment & MultiTransactional Step 3: recipientAddress ---
    void recipientAddress() {
        std::cout << "\nSelect recipient address or enter 0 for manual input:\n";
        std::vector<size_t> addrMapping;
        size_t displayIndex = 1;
        for (size_t i = 0; i < wallet.addresses.size(); ++i) {
            if (wallet.addresses[i].second == fromAddress)
                continue; // skip sender
            std::cout << displayIndex << ". " << wallet.addresses[i].first << " -> " << wallet.addresses[i].second << "\n";
            addrMapping.push_back(i);
            displayIndex++;
        }

        size_t toIndex{};
        std::cout << "Enter choice: ";
        std::cin >> toIndex;

        if (toIndex == 0) {
            std::cout << "Enter recipient address manually: ";
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // flush leftover newline
            std::getline(std::cin, toAddress);
            if (toAddress.empty()) {
                std::cout << "Recipient address cannot be empty.\n";
                return;
            }
        } else if (toIndex >= 1 && toIndex <= addrMapping.size()) {
            toAddress = wallet.addresses[addrMapping[toIndex - 1]].second;
        } else {
            std::cout << "Invalid recipient selection!\n";
            return;
        }
    }

    // --- SinglePayment & MultiSignature & MultiTransactional Step 4: selectUTXOs ---
    void selectUTXOs() {
        tx.inputs.clear();
        for (const auto &utxo : selectedUTXOs) {
            TxInput input;
            input.previous_txid = utxo.txid;
            input.output_index = utxo.index;
            tx.inputs.push_back(std::move(input));
        }
    }

    // --- SinglePayment Step 5: buildRecipientTx ---
    void buildRecipientTx() {
        TxOutput recipientOutput;
        recipientOutput.amount = amount;
        recipientOutput.requiredSignatures = 1;
        recipientOutput.types.push_back("payment");
        recipientOutput.pubkeyHashes.push_back(toAddress);
        tx.outputs.push_back(std::move(recipientOutput));
    }

    // --- SinglePayment & MultiSignature Step 6: change ---
    void addChange() {
        double changeAmount = totalInput - amount - fee;
        if (changeAmount > 0) {
            TxOutput changeOutput;
            changeOutput.amount = changeAmount;
            changeOutput.pubkeyHashes.push_back(fromAddress);
            changeOutput.requiredSignatures = 1;
            changeOutput.types.push_back("change");
            tx.outputs.push_back(std::move(changeOutput));
        }
    }

    // --- SinglePayment & MultiSignature Step 7: finalise and broadcast ---
    void finaliseAndBroadcastTx() {
        // Generate a unique TXID for this transaction
        auto [_, uuid] = uuidGenerator.generateUUID();
        tx.txid = uuid;

        std::string txHashHex = bf.hashTransaction(tx);
        uint64_t txHashInt = functions.hashToUint60(txHashHex);

        // Sign the transaction with Alice's private key
        for (auto &input : tx.inputs) {
            uint64_t sig = Alice.sign(txHashInt);
            input.signatures.push_back(std::to_string(sig));
        }

        // Push transaction to mempool
        blockchain.mempool.push_back(tx);

        std::cout << "\nSigned Transaction:\n" << tx.toString() << "\n";
        std::cout << "\nTransaction complete.\n";
    }

    // --- MultiSignature Step 2: get Keys ---
    void getKeys(std::vector<std::string> &selectedKeys, int &n, int &m, Wallet &wallet) {
        std::cout << "Enter total number of keys to include (N): ";
        std::cin >> n;

        if (n <= 0) {
            std::cout << "Number of keys must be positive.\n";
            return;
        }
        if (n > wallet.addresses.size()) {
            std::cout << "You only have " << wallet.addresses.size() << " keys in the wallet.\n";
            return;
        }

        selectedKeys.clear();
        std::cout << "Select " << n << " keys from wallet:\n";
        for (size_t i = 0; i < wallet.addresses.size(); ++i) {
            std::cout << i + 1 << ". " << wallet.addresses[i].first << " -> " << wallet.addresses[i].second << "\n";
        }

        for (int i = 0; i < n; ++i) {
            size_t keyIndex;
            std::cout << "Select key " << (i + 1) << ": ";
            std::cin >> keyIndex;

            if (keyIndex == 0 || keyIndex > wallet.addresses.size()) {
                std::cout << "Invalid key index.\n";
                --i; // retry
                continue;
            }

            selectedKeys.push_back(wallet.addresses[keyIndex - 1].second);
        }

        std::cout << "Enter required signatures (M): ";
        std::cin >> m;
        if (m <= 0 || m > n) {
            std::cout << "M must be positive and less than or equal to N.\n";
            return;
        }
    }

    // --- MultiSignature Step 3: select UTXOs ---
    void selectMultiSigUTXOs(const std::vector<std::string> &keys) {
        selectedUTXOs.clear();
        totalInput = 0;

        if (keys.empty()) {
            std::cout << "No keys provided.\n";
            return;
        }

        // Treat the first key as the funding (sender) address.
        fromAddress = keys[0];

        // Pull UTXOs from the sender address
        auto utxos = blockchain.getUTXOsForAddress(fromAddress);

        for (const auto &utxo : utxos) {
            selectedUTXOs.push_back(utxo);
            // Use the same accessor you use elsewhere (be consistent)
            totalInput += utxo.amount(); // not utxo.output.amount
            if (totalInput >= amount + fee)
                break;
        }

        if (totalInput < amount + fee) {
            std::cout << "Not enough funds to cover amount + fee!\n";
            return;
        }
    }

    // --- MultiSignature Step 4: build recipient output ---
    void buildMultiSigRecipientTx(const std::vector<std::string> &keys, int m, double amount) {
        TxOutput recipientOutput;
        recipientOutput.amount = amount;
        recipientOutput.requiredSignatures = m;
        recipientOutput.types.push_back("payment");

        // Add all keys to one multisig output
        for (const auto &key : keys) {
            recipientOutput.pubkeyHashes.push_back(key);
        }

        tx.outputs.push_back(std::move(recipientOutput));
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Interface_Wallet {
  public:
    Interface_Wallet(Blockchain &bc, Wallet &w) : blockchain(bc), wallet(w), ui_transactions(w, bc) {}

    void viewWallet(Wallet &wallet, bool mining) {
        int choice = -1;

        while (choice != 0) {
            // clearColumns();
            header();
            status(mining);
            menu();

            std::vector<std::vector<Line>> columns = {col1, col2, col3};
            std::cout << render.printColumns(columns, 80, 4);

            std::cin >> choice;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // clear buffer

            switch (choice) {

            case 1: { // Create new address
                functions.clearColumns();
                header();
                createNewAddress();

                std::vector<std::vector<Line>> columns = {col1, col2, col3};
                std::cout << render.printColumns(columns, 80, 4);

                break;
            }

            case 2: { // List addresses
                functions.clearColumns();
                listAddresses();

                std::vector<std::vector<Line>> columns = {col1, col2, col3};
                std::cout << render.printColumns(columns, 80, 4);

                functions.pause(); // REQUIRED
                break;
            }

            case 3: { // Send
                functions.clearColumns();

                int txType = 0;
                while (txType != 1 && txType != 2) {
                    functions.clearColumns();

                    col2.push_back({"Select transaction type:", Align::CENTER});
                    col2.push_back({"1. Single-Signature Transaction", Align::CENTER});
                    col2.push_back({"2. Multi-Signature Transaction", Align::CENTER});

                    std::vector<std::vector<Line>> columns = {col1, col2, col3};
                    std::cout << render.printColumns(columns, 80, 4);

                    std::cin >> txType;
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

                    if (txType != 1 && txType != 2) {
                        col2.push_back({"Invalid selection. Try again.", Align::CENTER});
                    }
                }

                functions.clearColumns();

                if (txType == 1)
                    ui_transactions.SinglePayment();
                else
                    ui_transactions.MultiSignature();

                std::vector<std::vector<Line>> columns = {col1, col2, col3};
                std::cout << render.printColumns(columns, 80, 4);

                functions.pause(); // REQUIRED
                break;
            }

            case 4: { // Receive
                functions.clearColumns();
                receive();

                col2.push_back({"Receiving address created.", Align::CENTER});

                std::vector<std::vector<Line>> columns = {col1, col2, col3};
                std::cout << render.printColumns(columns, 80, 4);

                functions.pause(); // REQUIRED
                break;
            }

            case 0:
                break;

            default: {
                functions.clearColumns();
                col2.push_back({"Invalid option. Try again.", Align::CENTER});

                std::vector<std::vector<Line>> columns = {col1, col2, col3};
                std::cout << render.printColumns(columns, 80, 4);

                functions.pause();
                break;
            }
            }
        }
    }

    void header() {
        render.addEmptyLines(col2, 10);
        col2.push_back({dash, Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({"--- WALLET TERMINAL ---", Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({dash, Align::CENTER});
    }

    void status(bool mining) {
        // Current Miner Address
        std::string minerAddr = wallet.minerAddress.empty() ? "[None]" : wallet.minerAddress;
        col2.emplace_back("Current Miner Address: " + minerAddr, Align::LEFT);

        // Mining Status
        std::string miningStatus = mining ? "Mining" : "Not Mining";
        col2.emplace_back("Mining Status: " + miningStatus, Align::LEFT);
    }

    void menu() {
        col2.push_back({dash, Align::CENTER});
        col2.push_back({"1. Create new address", Align::LEFT});
        col2.push_back({"2. List addresses", Align::LEFT});
        col2.push_back({"3. Send", Align::LEFT});
        col2.push_back({"4. Receive", Align::LEFT});
        col2.push_back({"0. Back", Align::LEFT});
        col2.push_back({dash, Align::CENTER});
    }

    void createNewAddress() {
        wallet.addressCounter++;
        std::string rawAddress = Alice.getReceiveAddress() + std::to_string(wallet.addressCounter);
        std::string newAddress = sha256(rawAddress);

        col2.push_back({"Enter a name for this address:", Align::LEFT});

        std::vector<std::vector<Line>> columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4) << std::flush;

        // std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        std::string name;
        std::cin >> name;
        // std::getline(std::cin, name);
        // std::getline(std::cin >> std::ws, name);
        // std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        // clearColumns();

        wallet.addresses.push_back({name, newAddress});
        col2.push_back({"Created new address " + name + ":", Align::LEFT});
        col2.push_back({newAddress, Align::LEFT});

        col2.push_back({"Set this address as miner address? (y/n):", Align::LEFT});

        char makeMiner;
        std::cin >> makeMiner;

        if (makeMiner == 'y' || makeMiner == 'Y') {
            wallet.setMinerAddress(newAddress);
            col2.push_back({"Miner address updated to:", Align::LEFT});
            col2.push_back({newAddress, Align::LEFT});
        }
    }

    void listAddresses() {
        if (wallet.addresses.empty()) {
            col2.push_back({"No addresses yet.", Align::CENTER});
            return;
        }

        // Clear previous cached wallet UTXOs
        wallet.utxos.clear();

        col2.push_back({"Your Wallet Addresses: ", Align::CENTER});

        for (auto &[name, address] : wallet.addresses) {
            // Get UTXOs for this address (assume this returns std::vector<UTXO>)
            auto utxos = blockchain.getUTXOsForAddress(address);

            // Append the returned UTXOs to wallet.utxos
            wallet.utxos.insert(wallet.utxos.end(), utxos.begin(), utxos.end());

            // Compute balance by summing the UTXO amounts
            double balanceSats = 0.0;
            for (const auto &u : utxos) {
                // Use u.amount() if UTXO exposes a method, otherwise u.amount
                balanceSats += u.amount(); // <-- if your UTXO has field 'amount' replace with u.amount
            }
            double balanceBTC = balanceSats / SATOSHIS;

            // Sort the local utxos vector (not wallet.utxos) by timestamp extracted from txid
            std::sort(utxos.begin(), utxos.end(), [&](const UTXO &a, const UTXO &b) { return functions.extractTimestamp(a.txid) < functions.extractTimestamp(b.txid); });

            col2.push_back({dash, Align::CENTER});
            col2.push_back({"Address: " + name, Align::CENTER});
            col2.push_back({"  " + address, Align::CENTER});
            col2.push_back({"  Balance: " + std::to_string(balanceBTC) + " BTC" + "  (" + std::to_string(balanceSats) + " sats)", Align::CENTER});
            col2.push_back({"  --- UTXOs ---", Align::CENTER});

            if (utxos.empty()) {
                col2.push_back({"  (none)", Align::CENTER});
                continue;
            }

            for (const auto &u : utxos) {
                col2.push_back({"    TXID: " + u.txid, Align::CENTER});
                col2.push_back({"      Index: " + u.index, Align::CENTER});
                col2.push_back({"      Amount: " + std::to_string(u.amount()) + " sats", Align::CENTER});
            }
        }
    }

    void receive() {
        wallet.addressCounter++;
        std::string rawAddress = Alice.getReceiveAddress() + std::to_string(wallet.addressCounter);
        std::string recievingAddress = sha256(rawAddress); // hash to get unique address
        wallet.addresses.push_back({"Recieving Address", recievingAddress});
    }

  private:
    Blockchain &blockchain;
    Wallet &wallet;
    Interface_Transactions ui_transactions;
    Render render;

    std::string dash = std::string(80, '-');
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Interface_Blockchain {
  public:
    Interface_Blockchain(Blockchain &bc, Wallet &w) : ui_wallet(bc, w), blockchain(bc), wallet(w), mining(false) {
        LOG_INFO("Class: Interface_Blockchain");
        initializeMinerAddress();
    }

    void initializeMinerAddress() {
        LOG_INFO("Class: Interface_Blockchain... Running initializeMinerAddress logic");
        wallet.addressCounter++;
        std::string rawAddress = Alice.getReceiveAddress() + std::to_string(wallet.addressCounter);
        std::string minerAddress = sha256(rawAddress); // hash to get unique address

        wallet.addresses.push_back({"Miner Address", minerAddress});
        wallet.setMinerAddress(minerAddress);
    }

    void run() {
        LOG_INFO("Class: Interface_Blockchain... Running run logic");
        int choice = -1;
        while (choice != 0) {
            functions.clearColumns();

            // Static menu
            header();
            status(mining);
            menu();

            std::vector<std::vector<Line>> columns = {col1, col2, col3};
            std::cout << render.printColumns(columns, 80, 4);

            std::cin >> choice;

            switch (choice) {
            case 1:
                LOG_INFO("Class: running run logic... Selected startBlockchain");
                functions.clearColumns();
                startBlockchain();
                break;
            case 2:
                LOG_INFO("Class: running run logic... Selected stopBlockchain");
                functions.clearColumns();
                stopBlockchain();
                break;
            case 3:
                LOG_INFO("Class: running run logic... Selected enableOutput");
                functions.clearColumns();
                enableOutput();
                break;
            case 4:
                LOG_INFO("Class: running run logic... Selected disableOutput");
                functions.clearColumns();
                disableOutput();
                break;
            case 5:
                LOG_INFO("Class: running run logic... Selected viewWallet");
                functions.clearColumns();
                ui_wallet.viewWallet(wallet, mining);
                break;
            case 0:
                LOG_INFO("Class: running run logic... Selected nExiting");
                functions.clearColumns();
                std::cout << "\nExiting Blockchain Interface...\n";
                return;
            default:
                LOG_INFO("Class: running run logic... Selected Invalid choice");
                functions.clearColumns();
                std::cout << "Invalid choice.\n";
            }
        }
    }

  private:
    Interface_Wallet ui_wallet;
    Blockchain &blockchain;
    Wallet &wallet;
    bool mining;
    Render render;

    std::thread miningThread;

    std::string dash = std::string(80, '-');

    void header() {
        render.addEmptyLines(col2, 10);
        col2.push_back({dash, Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({"--- BLOCKCHAIN TERMINAL ---", Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({dash, Align::CENTER});
    }

    void status(bool mining) {
        // Current Miner Address
        std::string minerAddr = wallet.minerAddress.empty() ? "[None]" : wallet.minerAddress;
        col2.emplace_back("Current Miner Address: " + minerAddr, Align::LEFT);

        // Mining Status
        std::string miningStatus = mining ? "Mining" : "Not Mining";
        col2.emplace_back("Mining Status: " + miningStatus, Align::LEFT);
    }

    void menu() {
        col2.push_back({dash, Align::CENTER});
        col2.push_back({"1. Start Mining", Align::LEFT});
        col2.push_back({"2. Stop Mining", Align::LEFT});
        col2.push_back({"3. Enable Output", Align::LEFT});
        col2.push_back({"4. Disable Output", Align::LEFT});
        col2.push_back({"5. View Wallet", Align::LEFT});
        col2.push_back({"0. Exit", Align::LEFT});
        col2.push_back({dash, Align::CENTER});
    }

    void startBlockchain() {
        if (mining)
            return;
        mining = true;
        miningThread = std::thread(&Blockchain::run, &blockchain);
    }

    void stopBlockchain() {
        if (!mining)
            return;
        mining = false;
        blockchain.stopMining(); // tell the thread to exit

        if (miningThread.joinable()) {
            miningThread.join(); // wait for mining to stop
        }
    }

    void enableOutput() { blockchain.setPrintOutput(true); }
    void disableOutput() { blockchain.setPrintOutput(false); }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Accounting {
  public:
    Accounting() {
        LOG_INFO("Class: Accounting");
        // Initialize all supported currencies to zero
        balances = {{"BTC", 0}, {"USD", 0}, {"EUR", 0}, {"CAD", 0}, {"GBP", 0}, {"CHF", 0}, {"AUD", 0}, {"JPY", 0}};
    }

    inline void deposit(const std::string &currency, uint64_t amount) {
        validateCurrency(currency);
        if (amount == 0)
            std::cout << "deposit must be positive\n"; // throw std::invalid_argument("Deposit must be positive");
        balances[currency] += amount;
    }

    inline bool withdraw(const std::string &currency, uint64_t amount) {
        validateCurrency(currency);
        if (amount == 0)
            std::cout << "withdraw cant be negative\n"; // throw std::invalid_argument("Withdraw can't be negative");

        uint64_t &balance = balances[currency];
        if (balance < amount) {
            return false;
        }

        balance -= amount;
        return true;
    }

    inline uint64_t getBalance(const std::string &currency) const {
        auto it = balances.find(currency);
        return (it != balances.end()) ? it->second : 0;
    }

    inline void printBalances() const {
        std::cout << "\n[Accounting] Balances:\n";
        for (const auto &[currency, value] : balances)
            std::cout << "  " << currency << ": " << value << "\n";
    }

  private:
    std::unordered_map<std::string, uint64_t> balances;

    inline void validateCurrency(const std::string &currency) const {
        if (balances.find(currency) == balances.end())
            throw std::invalid_argument("Unsupported currency: " + currency);
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Banking {
  public:
    explicit Banking(Accounting &acc) : accounting(acc) { LOG_INFO("Class: Banking"); }

    inline void deposit(const std::string &currency, uint64_t amount) { accounting.deposit(currency, amount); }

    inline bool withdraw(const std::string &currency, uint64_t amount) { return accounting.withdraw(currency, amount); }

    inline uint64_t getBalance(const std::string &currency) const { return accounting.getBalance(currency); }

    void print() const { accounting.printBalances(); }

  private:
    Accounting &accounting;
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class PriceFeedEntropy {
  public:
    PriceFeedEntropy(uint64_t startPrice = 10000000ULL) // price in dollars
        : price(startPrice), currentPrice(startPrice), useOuter(true), outerRunRemaining(0), outerDirection(1) {}

    inline uint64_t getCurrentPrice(int mag, int run) {
        if (useOuter) {
            applyOuterMove(mag, run);
        } else {
            applyInnerMove(mag);
        }

        useOuter = !useOuter; // alternate each call
        if (price < 1)
            price = 1; // minimum price = 1 satoshi
        currentPrice = price;
        return currentPrice;
    }

  private:
    BinaryEntropyPool entropyPool;
    uint64_t price;
    uint64_t currentPrice;
    bool useOuter;
    int outerDirection;    // 0=down, 1=up
    int outerRunRemaining; // how many outer steps left
    int outerMagnitude;

    inline void applyOuterMove(int mag, int run) {
        if (outerRunRemaining == 0) {
            // Direction
            std::string dirStr = entropyPool.get(1);
            outerDirection = binaryStringToInt(dirStr); // 0 or 1

            // Run length
            std::string runStr = entropyPool.get(run);
            outerRunRemaining = binaryStringToInt(runStr);
            if (outerRunRemaining == 0)
                outerRunRemaining = 1;

            // Magnitude per tick
            std::string magStr = entropyPool.get(mag);
            outerMagnitude = binaryStringToInt(magStr);
            if (outerMagnitude == 0)
                outerMagnitude = 1;
        }

        int64_t movement = (outerDirection == 1 ? +outerMagnitude : -outerMagnitude);
        // Ensure no underflow
        if (movement < 0 && static_cast<uint64_t>(-movement) > price)
            price = 1;
        else
            price += movement;

        outerRunRemaining--;
    }

    inline void applyInnerMove(int mag) {
        std::string dirStr = entropyPool.get(1);
        int direction = binaryStringToInt(dirStr); // 0 down, 1 up

        std::string magStr = entropyPool.get(mag); // 14 bits = 0-16383
        int magnitude = binaryStringToInt(magStr); // 0–255

        int64_t movement = (direction == 1 ? +magnitude : -magnitude);

        if (movement < 0 && static_cast<uint64_t>(-movement) > price)
            price = 1;
        else
            price += movement;
    }

    inline int binaryStringToInt(const std::string &bin) {
        int value = 0;
        for (char c : bin) {
            value <<= 1;
            if (c == '1')
                value |= 1;
        }
        return value;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class CorrelatedFeed {
  public:
    CorrelatedFeed(PriceFeedEntropy &feed) : feed(feed) {}

    inline std::tuple<uint64_t, uint64_t, uint64_t> getCorrelatedPrice() {

        int mag = 14;
        int run = 5;

        // Step 1: base BTC price
        uint64_t priceBTC_USD = feed.getCurrentPrice(mag, run);

        // Step 2: generate small correlated movements
        int movementGBP = getMovement();
        int movementEUR = getMovement();

        // Step 3: correlated prices
        uint64_t priceBTC_GBP = priceBTC_USD - 2200000 + movementGBP;
        uint64_t priceBTC_EUR = priceBTC_USD - 1300000 + movementEUR;

        return {priceBTC_USD, priceBTC_GBP, priceBTC_EUR};
    }

  private:
    PriceFeedEntropy &feed;
    BinaryEntropyPool entropy;

    inline int getMovement() {
        int dir = binaryStringToInt(entropy.get(1));
        int mag = binaryStringToInt(entropy.get(14));
        if (mag == 0)
            mag = 1;
        return (dir == 1 ? mag : -mag);
    }

    inline int binaryStringToInt(const std::string &bin) {
        int value = 0;
        for (char c : bin) {
            value <<= 1;
            if (c == '1')
                value |= 1;
        }
        return value;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class CurlClient {
  public:
    CurlClient() {
        LOG_INFO("Class: CurlClient");
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curlHandle = curl_easy_init();
        if (!curlHandle)
            throw std::runtime_error("Failed to initialize curl");
    }

    ~CurlClient() {
        if (curlHandle)
            curl_easy_cleanup(curlHandle);
        curl_global_cleanup();
    }

    std::string get(const std::string &url) {
        std::string response;

        curl_easy_setopt(curlHandle, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curlHandle, CURLOPT_CAINFO, fileSystem.path_1);
        curl_easy_setopt(curlHandle, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curlHandle, CURLOPT_WRITEDATA, &response);

        CURLcode res = curl_easy_perform(curlHandle);
        if (res != CURLE_OK)
            throw std::runtime_error(curl_easy_strerror(res));

        return response;
    }

  private:
    CURL *curlHandle;

    static size_t writeCallback(void *contents, size_t size, size_t nmemb, void *userp) {
        size_t total = size * nmemb;
        std::string *str = static_cast<std::string *>(userp);
        str->append(static_cast<char *>(contents), total);
        return total;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

struct Candle { // changed from OHLC
    std::string readableTime;
    uint64_t timestamp;
    double open;
    double high;
    double low;
    double close;
    double volume;
    int count;
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class KrakenOHLCFetcher {
  public:
    KrakenOHLCFetcher(CurlClient &curlClient) : curl(curlClient) { LOG_INFO("Class: KrakenOHLCFetcher"); }

    std::vector<Candle> getOHLC(const std::string &pair, int intervalMinutes, bool realTime, uint64_t since) {
        std::vector<Candle> candles;

        std::string url = "https://api.kraken.com/0/public/OHLC?pair=" + pair + "&interval=" + std::to_string(intervalMinutes);

        if (!realTime) {
            url += "&since=" + std::to_string(since);
        }

        std::string response = curl.get(url);
        auto j = json::parse(response);

        if (!j["error"].empty())
            throw std::runtime_error(j["error"].dump());

        const auto &arrList = j["result"][pair];
        for (const auto &arr : arrList) {
            Candle c;
            c.timestamp = arr[0].is_string() ? std::stoull(arr[0].get<std::string>()) : arr[0].get<uint64_t>();

            c.readableTime = functions.timestampToReadable(c.timestamp);

            auto parseDouble = [](const json &v) -> double { return v.is_string() ? std::stod(v.get<std::string>()) : v.get<double>(); };
            c.open = parseDouble(arr[1]);
            c.high = parseDouble(arr[2]);
            c.low = parseDouble(arr[3]);
            c.close = parseDouble(arr[4]);
            c.volume = parseDouble(arr[6]);
            c.count = arr[7].get<int>();
            candles.push_back(c);
        }

        return candles;
    }

    uint64_t getUnixTimeDaysAgo(int days) {
        using namespace std::chrono;
        auto now = system_clock::now();
        auto past = now - hours(24 * days);
        return duration_cast<seconds>(past.time_since_epoch()).count();
    }

    static void saveToCSV(const std::string &filename, const std::vector<Candle> &candleData) {
        std::ofstream file(filename);
        if (!file.is_open())
            throw std::runtime_error("Failed to open file for writing");

        file << "timestamp,open,high,low,close,volume,count\n";
        for (auto &c : candleData)
            file << c.timestamp << "," << c.open << "," << c.high << "," << c.low << "," << c.close << "," << c.volume << "," << c.count << "\n";
    }

  private:
    CurlClient &curl;
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class CreatePriceFile {
  public:
    void initializeRecentHistory(const std::string &filename, KrakenOHLCFetcher &fetcher) {
        uint64_t since = getLastTimestamp(filename);

        auto missing = fetcher.getOHLC("XXBTZUSD", 1, false, since);
        if (missing.empty())
            return;

        // std::cout << "Appending " << missing.size() << " missing candles...\n";

        size_t processed = 0;
        for (const auto &c : missing) {
            appendCandle(filename, c);
            ++processed;
            // std::cout << "\rProcessing candle " << processed << " of " << missing.size() << std::flush;
        }
        // std::cout << "\nDone appending missing history.\n";
    }

    void updateRecentHistory(const std::string &filename, const Candle &newest) {
        uint64_t lastTs = getLastTimestamp(filename);
        if (newest.timestamp <= lastTs)
            return;

        appendCandle(filename, newest);
    }

    uint64_t getLastTimestamp(const std::string &filename) {
        LOG_INFO("Class: CreatePriceFile... Running getLastTimestamp logic");
        std::ifstream file(filename);
        if (!file.is_open()) {
            LOG_ERROR("Class: CreatePriceFile... No history file — will fetch full recent data");
            return 0;
        }

        std::string line;
        std::string lastDataLine;

        while (std::getline(file, line)) {
            if (line.empty() || line.find("Timestamp") != std::string::npos || line.find("---") != std::string::npos) {
                continue;
            }
            lastDataLine = line;
        }

        if (lastDataLine.empty()) {
            LOG_ERROR("Class: CreatePriceFile... File empty — fetching full recent data");
            return 0;
        }

        if (lastDataLine.length() < 32) { // 20 for date + 12 for timestamp
            LOG_ERROR("Class: CreatePriceFile... Last line too short (" + std::to_string(lastDataLine.length()) + " chars) — fetching full recent data");
            return 0;
        }

        std::string tsStr = lastDataLine.substr(20, 12);

        try {
            uint64_t lastTs = std::stoull(tsStr);

            auto now = std::chrono::system_clock::now();
            uint64_t currentTime = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
            uint64_t ageSeconds = currentTime - lastTs;

            if (ageSeconds < 721 * 60) {
                uint64_t since = lastTs + 60;
                LOG_INFO("Class: CreatePriceFile... History recent — fetching since " + std::to_string(since));
                return since;
            } else {
                LOG_INFO("Class: CreatePriceFile... History too old (" + std::to_string(ageSeconds / 60) + " minutes) — fetching full");
                return 0;
            }
        } catch (const std::exception &e) {
            LOG_ERROR("Class: CreatePriceFile... Failed to parse timestamp from: " + tsStr + " — fetching full recent data");
            return 0;
        }
    }

    void appendCandle(const std::string &filename, const Candle &c) {
        LOG_INFO("Class: CreatePriceFile... Running appendCandle logic");
        bool fileIsNew = false;
        {
            std::ifstream check(filename);
            if (!check.is_open() || check.peek() == std::ifstream::traits_type::eof()) {
                fileIsNew = true;
            }
        }

        std::ofstream file(filename, std::ios::app);
        if (!file.is_open()) {
            LOG_ERROR("Class: CreatePriceFile... Running appendCandle logic - Failed to open file for writing: " + filename);
            std::exit(1);
        }

        if (fileIsNew) {
            file << std::left << std::setw(20) << "Date Time (UTC)" << std::setw(12) << "Timestamp" << std::setw(12) << "Open" << std::setw(12) << "High" << std::setw(12) << "Low"
                 << std::setw(12) << "Close" << std::setw(14) << "Volume" << std::setw(8) << "Count" << "\n";
            file << std::string(102, '-') << "\n";
        }

        std::string readableTime = timestampToReadable(c.timestamp);

        file << std::left << std::setw(20) << readableTime << std::setw(12) << c.timestamp << std::setw(12) << std::fixed << std::setprecision(1) << c.open << std::setw(12)
             << c.high << std::setw(12) << c.low << std::setw(12) << c.close << std::setw(14) << std::setprecision(6) << c.volume << std::setw(8) << c.count << "\n";

        file.flush();
    }

  private:
    static std::string timestampToReadable(uint64_t ts) {
        auto timePoint = std::chrono::time_point<std::chrono::system_clock>(std::chrono::seconds(ts));
        auto tt = std::chrono::system_clock::to_time_t(timePoint);

        std::ostringstream ss;
        ss << std::put_time(std::gmtime(&tt), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class TextFileLoader {
  public:
    TextFileLoader(const std::string &filename) : fileName(filename) {
        LOG_INFO("Class: TextFileLoader");
        LOG_INFO("Class: TextFileLoader... Looking for file: " + fileName);
        LOG_INFO("Class: TextFileLoader... Current working directory: " + std::filesystem::current_path().string());

        if (!loadFixedWidthData()) {
            LOG_ERROR("Class: TextFileLoader... File '" + fileName + "' not found or empty - starting with fresh data");
            data.clear();
        } else {
            LOG_INFO("Class: TextFileLoader... Loaded " + std::to_string(data.size()) + " candles from '" + fileName);
        }
    }

    const std::vector<Candle> &getActiveCandles() const { return data; }
    bool isEmpty() const { return data.empty(); }

    bool loadFixedWidthData() {
        std::vector<Candle> candles;
        std::ifstream file(fileName);
        if (!file.is_open()) {
            LOG_ERROR("Class: TextFileLoader... File '" + fileName + "' not found - starting empty");
            return false;
        }

        std::string line;
        bool inDataSection = false;

        while (std::getline(file, line)) {
            if (line.empty())
                continue;

            // Skip header and separator
            if (line.find("Date Time (UTC)") != std::string::npos)
                continue;
            if (line.find("---") != std::string::npos) {
                inDataSection = true;
                continue;
            }

            if (inDataSection) {
                // Use stringstream — skips all whitespace automatically
                std::istringstream iss(line.substr(20)); // Skip the date

                Candle c;
                if (iss >> c.timestamp >> c.open >> c.high >> c.low >> c.close >> c.volume >> c.count) {
                    c.readableTime = functions.timestampToReadable(c.timestamp);
                    candles.push_back(c);
                } else {
                    LOG_WARNING("Class: TextFileLoader... Failed to parse candle line: " + line);
                }
            }
        }

        data = std::move(candles);
        return !data.empty();
    }

  private:
    std::vector<Candle> data;
    std::string fileName;
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Loader {
  public:
    Loader() {
        LOG_INFO("Class: Loader");
        TextFileLoader loader("btc_history.txt");
        LOG_INFO("Class: Loader... loaded file");

        if (loader.isEmpty()) {
            LOG_INFO("Class: Loader... No saved history — starting fresh (file will be created on first candle)");
            data.clear();
        } else {
            data = loader.getActiveCandles();
            LOG_INFO("Class: Loader... Loaded " + std::to_string(data.size()) + " historical candles");
        }
    }

    const std::vector<Candle> &getActiveCandles() const { return data; }

  private:
    std::vector<Candle> data;
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class CandleCollector {
  public:
    // ← ADD THIS BACK
    using CandleTuple = std::tuple<uint64_t, // timestamp
                                   double,   // open
                                   double,   // high
                                   double,   // low
                                   double,   // close
                                   double,   // volume
                                   int       // count
                                   >;

    explicit CandleCollector(const Loader &loader) : index(0) {
        LOG_INFO("Class: CandleCollector");
        const auto &raw = loader.getActiveCandles();

        if (raw.empty()) {
            LOG_ERROR("Class: CandleCollector... No loaded candles yet...");
            return;
        }

        size_t n = raw.size();

        timestamps.reserve(n);
        opens.reserve(n);
        highs.reserve(n);
        lows.reserve(n);
        closes.reserve(n);
        volumes.reserve(n);
        counts.reserve(n);
        readableTimes.reserve(n);

        for (const auto &c : raw) {
            timestamps.push_back(c.timestamp);
            opens.push_back(c.open);
            highs.push_back(c.high);
            lows.push_back(c.low);
            closes.push_back(c.close);
            volumes.push_back(c.volume);
            counts.push_back(c.count);
            readableTimes.push_back(c.readableTime);
        }

        LOG_INFO("Class: CandleCollector... Loaded " + std::to_string(n) + " candles.");
    }

    std::optional<CandleTuple> getNext() {
        if (index >= timestamps.size())
            return std::nullopt;

        CandleTuple tup{timestamps[index], opens[index], highs[index], lows[index], closes[index], volumes[index], counts[index]};

        ++index;
        return tup;
    }

    double getNextClose() {
        auto t = getNext();
        if (!t.has_value())
            return 0.0;
        return std::get<4>(*t); // close
    }

    const std::vector<uint64_t> &getTimestamps() const { return timestamps; }
    const std::vector<double> &getOpens() const { return opens; }
    const std::vector<double> &getHighs() const { return highs; }
    const std::vector<double> &getLows() const { return lows; }
    const std::vector<double> &getCloses() const { return closes; }
    const std::vector<double> &getVolumes() const { return volumes; }
    const std::vector<int> &getCounts() const { return counts; }
    const std::vector<std::string> &getReadableTimes() const { return readableTimes; }

    size_t size() const { return timestamps.size(); }

  private:
    size_t index = 0;

    std::vector<uint64_t> timestamps;
    std::vector<double> opens, highs, lows, closes, volumes;
    std::vector<int> counts;
    std::vector<std::string> readableTimes;
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class TwitterCurlClient {
  public:
    TwitterCurlClient(const std::string &consumer_key, const std::string &consumer_secret, const std::string &access_token, const std::string &access_token_secret)
        : consumer_key(consumer_key), consumer_secret(consumer_secret), access_token(access_token), access_token_secret(access_token_secret), headers(nullptr) {
        LOG_INFO("Class: TwitterCurlClient");
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curlHandle = curl_easy_init();
        if (!curlHandle)
            LOG_ERROR("Class: TwitterCurlClient... Failed to initialize curl");
        headers = curl_slist_append(headers, "Content-Type: application/json");
    }

    ~TwitterCurlClient() {
        if (headers)
            curl_slist_free_all(headers);
        if (curlHandle)
            curl_easy_cleanup(curlHandle);
        curl_global_cleanup();
    }

    std::string post(const std::string &url, const std::string &body) {
        std::string response;

        // Generate OAuth params
        std::string nonce = generate_nonce();
        std::string timestamp = std::to_string(std::time(nullptr));

        // OAuth params only (sorted automatically via map)
        std::map<std::string, std::string> oauth_params;
        oauth_params["oauth_consumer_key"] = consumer_key;
        oauth_params["oauth_nonce"] = nonce;
        oauth_params["oauth_signature_method"] = "HMAC-SHA1";
        oauth_params["oauth_timestamp"] = timestamp;
        oauth_params["oauth_token"] = access_token;
        oauth_params["oauth_version"] = "1.0";

        // Build sorted parameter string for signature
        std::ostringstream params_oss;
        bool first = true;
        for (const auto &p : oauth_params) {
            if (!first)
                params_oss << "&";
            params_oss << url_encode(p.first) << "=" << url_encode(p.second);
            first = false;
        }
        std::string params_str = params_oss.str();

        // Generate signature (only OAuth params)
        std::string signature = generate_signature("POST", url, params_str, consumer_secret, access_token_secret);

        // Build Authorization header
        std::ostringstream auth_header;
        auth_header << "Authorization: OAuth "
                    << "oauth_consumer_key=\"" << url_encode(consumer_key) << "\", "
                    << "oauth_nonce=\"" << url_encode(nonce) << "\", "
                    << "oauth_signature=\"" << url_encode(signature) << "\", "
                    << "oauth_signature_method=\"HMAC-SHA1\", "
                    << "oauth_timestamp=\"" << url_encode(timestamp) << "\", "
                    << "oauth_token=\"" << url_encode(access_token) << "\", "
                    << "oauth_version=\"1.0\"";

        struct curl_slist *temp_headers = curl_slist_append(headers, auth_header.str().c_str());
        curl_easy_setopt(curlHandle, CURLOPT_HTTPHEADER, temp_headers);

        curl_easy_setopt(curlHandle, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curlHandle, CURLOPT_POST, 1L);
        curl_easy_setopt(curlHandle, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curlHandle, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curlHandle, CURLOPT_WRITEDATA, &response);

        perform();

        long http_code = 0;
        curl_easy_getinfo(curlHandle, CURLINFO_RESPONSE_CODE, &http_code);
        LOG_ERROR("Class: TwitterCurlClient... --- API REQUEST DEBUG ---");
        LOG_ERROR("Class: TwitterCurlClient... HTTP Status Code: " + http_code);
        LOG_ERROR("Class: TwitterCurlClient... Full Response Body:\n" + response);
        LOG_ERROR("Class: TwitterCurlClient... --- END DEBUG ---");

        if (http_code != 200 && http_code != 201) {
            LOG_ERROR("Class: TwitterCurlClient... Tweet failed to send! Check the response above for details");
            LOG_ERROR("Class: TwitterCurlClient... Common fixes:");
            LOG_ERROR("Class: TwitterCurlClient... - Wrong keys/tokens? (401 Unauthorized)");
            LOG_ERROR("Class: TwitterCurlClient... - App permissions not set to Read + Write? (403 Forbidden)");
            LOG_ERROR("Class: TwitterCurlClient... - Rate limited? (429 Too Many Requests)");
        }

        curl_slist_free_all(temp_headers);

        return response;
    }

    // Add this inside CurlClient class (public)
    std::string uploadMedia(const std::string &filePath) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open())
            LOG_ERROR("Class: TwitterCurlClient... Runnning uploadMedia logic - Cannot open image file: " + filePath);

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<char> buffer(size);
        if (!file.read(buffer.data(), size))
            LOG_ERROR("Class: TwitterCurlClient... Runnning uploadMedia logic - Failed to read file");

        std::string boundary = "----Boundary" + generate_nonce(); // Random boundary
        std::string body;

        // Multipart body
        body += "--" + boundary + "\r\n";
        body += "Content-Disposition: form-data; name=\"media\"; filename=\"" + filePath.substr(filePath.find_last_of("/\\") + 1) + "\"\r\n";
        body += "Content-Type: image/png\r\n\r\n";
        body.append(buffer.data(), size);
        body += "\r\n";
        body += "--" + boundary + "--\r\n";

        std::string response;

        // OAuth params (same as post, no extra params)
        std::string nonce = generate_nonce();
        std::string timestamp = std::to_string(std::time(nullptr));

        std::map<std::string, std::string> oauth_params;
        oauth_params["oauth_consumer_key"] = consumer_key;
        oauth_params["oauth_nonce"] = nonce;
        oauth_params["oauth_signature_method"] = "HMAC-SHA1";
        oauth_params["oauth_timestamp"] = timestamp;
        oauth_params["oauth_token"] = access_token;
        oauth_params["oauth_version"] = "1.0";

        std::ostringstream params_oss;
        bool first = true;
        for (const auto &p : oauth_params) {
            if (!first)
                params_oss << "&";
            params_oss << url_encode(p.first) << "=" << url_encode(p.second);
            first = false;
        }
        std::string params_str = params_oss.str();

        std::string signature = generate_signature("POST", "https://upload.twitter.com/1.1/media/upload.json", params_str, consumer_secret, access_token_secret);

        std::ostringstream auth_header;
        auth_header << "Authorization: OAuth "
                    << "oauth_consumer_key=\"" << url_encode(consumer_key) << "\", "
                    << "oauth_nonce=\"" << url_encode(nonce) << "\", "
                    << "oauth_signature=\"" << url_encode(signature) << "\", "
                    << "oauth_signature_method=\"HMAC-SHA1\", "
                    << "oauth_timestamp=\"" << url_encode(timestamp) << "\", "
                    << "oauth_token=\"" << url_encode(access_token) << "\", "
                    << "oauth_version=\"1.0\"";

        struct curl_slist *temp_headers = nullptr;
        temp_headers = curl_slist_append(temp_headers, auth_header.str().c_str());
        temp_headers = curl_slist_append(temp_headers, ("Content-Type: multipart/form-data; boundary=" + boundary).c_str());

        curl_easy_setopt(curlHandle, CURLOPT_URL, "https://upload.twitter.com/1.1/media/upload.json");
        curl_easy_setopt(curlHandle, CURLOPT_POST, 1L);
        curl_easy_setopt(curlHandle, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curlHandle, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
        curl_easy_setopt(curlHandle, CURLOPT_HTTPHEADER, temp_headers);
        curl_easy_setopt(curlHandle, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curlHandle, CURLOPT_WRITEDATA, &response);

        perform();

        curl_slist_free_all(temp_headers);

        // Debug output
        LOG_ERROR("Class: TwitterCurlClient... Runnning uploadMedia logic - Media Upload Response: " + response);

        json resp_json = json::parse(response);
        if (!resp_json.contains("media_id_string")) {
            throw std::runtime_error("Media upload failed: " + response);
        }

        return resp_json["media_id_string"].get<std::string>();
    }

    std::string loadFromFile(const std::string &path) {
        std::ifstream file(path);
        if (!file.is_open())
            LOG_ERROR("Class: TwitterCurlClient... Runnning uploadMedia logic - Failed to open file: " + path);
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();
        while (!content.empty() && std::isspace(content.back()))
            content.pop_back();
        if (content.empty())
            LOG_ERROR("Class: TwitterCurlClient... Runnning uploadMedia logic - Failed to open file: " + path);
        return content;
    }

  private:
    std::string consumer_key, consumer_secret, access_token, access_token_secret;
    CURL *curlHandle;
    struct curl_slist *headers;

    static size_t writeCallback(void *contents, size_t size, size_t nmemb, void *userp) {
        size_t total = size * nmemb;
        static_cast<std::string *>(userp)->append(static_cast<char *>(contents), total);
        return total;
    }

    void perform() {
        CURLcode res = curl_easy_perform(curlHandle);
        if (res != CURLE_OK)
            throw std::runtime_error(curl_easy_strerror(res));
    }

    // URL encode (RFC 3986)
    std::string url_encode(const std::string &str) {
        std::ostringstream escaped;
        escaped << std::hex << std::uppercase;
        for (char c : str) {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                escaped << c;
            } else {
                escaped << '%' << std::setw(2) << int(static_cast<unsigned char>(c));
            }
        }
        return escaped.str();
    }

    std::string base64_encode(const unsigned char *data, size_t len) {
        BIO *bio = BIO_new(BIO_s_mem());
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);

        BIO_write(bio, data, static_cast<int>(len));
        BIO_flush(bio);

        BUF_MEM *buffer_ptr;
        BIO_get_mem_ptr(bio, &buffer_ptr);

        std::string encoded(buffer_ptr->data, buffer_ptr->length);

        BIO_free_all(bio);
        return encoded;
    }

    // Generate random nonce
    std::string generate_nonce() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        unsigned char bytes[16];
        for (int i = 0; i < 16; ++i)
            bytes[i] = dis(gen);
        return base64_encode(bytes, 16);
    }

    // Generate HMAC-SHA1 signature
    std::string
    generate_signature(const std::string &method, const std::string &url, const std::string &params_str, const std::string &consumer_secret, const std::string &token_secret) {
        std::string signing_key = url_encode(consumer_secret) + "&" + url_encode(token_secret);
        std::string base_string = url_encode(method) + "&" + url_encode(url) + "&" + url_encode(params_str);

        unsigned char digest[SHA_DIGEST_LENGTH];
        unsigned int digest_len;
        HMAC(EVP_sha1(), signing_key.c_str(), signing_key.size(), reinterpret_cast<const unsigned char *>(base_string.c_str()), base_string.size(), digest, &digest_len);

        return base64_encode(digest, digest_len);
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class TwitterClient {
  public:
    TwitterClient() = default;

    void enableTwitter(const std::string &filePath) {
        if (!curl) { // only initialize once
            creds = getTwitterCredentials(filePath);
            curl = std::make_unique<TwitterCurlClient>(creds.at("consumer_key"), creds.at("consumer_secret"), creds.at("access_token"), creds.at("access_token_secret"));
            LOG_INFO("TwitterClient initialized with user credentials");
        }
    }

    void postText(const std::string &text) {
        if (!curl) {
            LOG_ERROR("TwitterClient: Tried to post tweet, but Twitter is not enabled");
            return;
        }

        json j;
        j["text"] = text;
        std::string response = curl->post("https://api.x.com/2/tweets", j.dump());

        try {
            json resp_json = json::parse(response);
            if (resp_json.contains("data") && resp_json["data"].contains("id")) {
                LOG_INFO("Class: TwitterClient... Tweet sent! ID: " + resp_json["data"]["id"].get<std::string>());
            }
        } catch (...) {
            LOG_ERROR("Class: TwitterClient... Invalid response: " + response);
        }
    }

    void postTweetWithImage(const std::string &text, const std::string &imagePath) {
        if (!curl) {
            LOG_ERROR("TwitterClient: Tried to post tweet with image, but Twitter is not enabled");
            return;
        }

        std::string media_id = curl->uploadMedia(imagePath);

        json j;
        j["text"] = text;
        j["media"]["media_ids"] = {media_id};

        std::string response = curl->post("https://api.x.com/2/tweets", j.dump());

        try {
            json resp_json = json::parse(response);
            if (resp_json.contains("data") && resp_json["data"].contains("id")) {
                LOG_INFO("Class: TwitterClient... Tweet with image sent! ID: " + resp_json["data"]["id"].get<std::string>());
            } else {
                LOG_ERROR("Class: TwitterClient... Failed: " + response);
            }
        } catch (...) {
            LOG_ERROR("Class: TwitterClient... Invalid response: " + response);
        }
    }

  private:
    std::unordered_map<std::string, std::string> creds;
    std::unique_ptr<TwitterCurlClient> curl;

    bool fileExists(const std::string &path) {
        std::ifstream f(path);
        return f.good();
    }

    std::unordered_map<std::string, std::string> readConfig(const std::string &path) {
        std::unordered_map<std::string, std::string> config;
        std::ifstream file(path);
        std::string line;
        while (std::getline(file, line)) {
            // Skip comments and empty lines
            if (line.empty() || line[0] == '#') {
                continue;
            }

            size_t pos = line.find('=');
            if (pos != std::string::npos) {
                std::string key = line.substr(0, pos);
                std::string value = line.substr(pos + 1);
                config[key] = value;
            }
        }
        return config;
    }

    void writeConfig(const std::string &path, const std::unordered_map<std::string, std::string> &config) {
        std::ofstream file(path);

        // Header
        file << "################################################################################\n";
        file << "#                          TWITTER API CREDENTIALS                             #\n";
        file << "################################################################################\n";
        file << "#                                                                              #\n";
        file << "# To get your Twitter API credentials:                                         #\n";
        file << "# 1. Go to https://developer.x.com/en/portal/dashboard                         #\n";
        file << "# 2. Create a new app (or use existing)                                        #\n";
        file << "# 3. Navigate to 'Keys and Tokens' section                                     #\n";
        file << "# 4. Copy the values below                                                     #\n";
        file << "#                                                                              #\n";
        file << "################################################################################\n";
        file << "\n";

        // Consumer Key
        file << "# Consumer Key (API Key)\n";
        file << "# Also called 'API Key' - identifies your application\n";
        file << "consumer_key=" << config.at("consumer_key") << "\n";
        file << "\n";

        // Consumer Secret
        file << "# Consumer Secret (API Secret Key)\n";
        file << "# Also called 'API Secret Key' - authenticates your application\n";
        file << "# Keep this SECRET - do not share!\n";
        file << "consumer_secret=" << config.at("consumer_secret") << "\n";
        file << "\n";

        // Access Token
        file << "# Access Token\n";
        file << "# Identifies which Twitter account the app acts on behalf of\n";
        file << "access_token=" << config.at("access_token") << "\n";
        file << "\n";

        // Access Token Secret
        file << "# Access Token Secret\n";
        file << "# Authenticates the access token\n";
        file << "# Keep this SECRET - do not share!\n";
        file << "access_token_secret=" << config.at("access_token_secret") << "\n";
        file << "\n";

        // Footer
        file << "################################################################################\n";
        file << "#                                                                              #\n";
        file << "# SECURITY WARNING: This file contains sensitive credentials.                  #\n";
        file << "# Keep it secure and never commit it to version control!                       #\n";
        file << "#                                                                              #\n";
        file << "################################################################################\n";
    }

    std::unordered_map<std::string, std::string> getTwitterCredentials(const std::string &configPath) {
        if (!fileExists(configPath)) {
            std::unordered_map<std::string, std::string> newConfig;

            std::cout << "\n";
            std::cout << "================================================================================\n";
            std::cout << "                     TWITTER API CREDENTIALS SETUP                              \n";
            std::cout << "================================================================================\n";
            std::cout << "\n";
            std::cout << "To get your credentials, visit:\n";
            std::cout << "https://developer.x.com/en/portal/dashboard\n";
            std::cout << "\n";
            std::cout << "Then navigate to: Your App > Keys and Tokens\n";
            std::cout << "\n";
            std::cout << "================================================================================\n";
            std::cout << "\n";

            std::cout << "Enter Consumer Key (API Key): ";
            std::getline(std::cin, newConfig["consumer_key"]);

            std::cout << "Enter Consumer Secret (API Secret Key): ";
            std::getline(std::cin, newConfig["consumer_secret"]);

            std::cout << "Enter Access Token: ";
            std::getline(std::cin, newConfig["access_token"]);

            std::cout << "Enter Access Token Secret: ";
            std::getline(std::cin, newConfig["access_token_secret"]);

            std::cout << "\n";
            std::cout << "Credentials saved to: " << configPath << "\n";
            std::cout << "\n";

            writeConfig(configPath, newConfig);
            return newConfig;
        } else {
            return readConfig(configPath);
        }
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class TradeBroadcaster {
  public:
    TradeBroadcaster(TwitterClient &client) : twitter(client) { LOG_INFO("Class: TradeBroadcaster"); }

    enum class Direction { Long, Short };

    struct PositionFilledInfo {
        std::string pair;
        Direction direction; // Long = green, Short = red
        uint64_t entry;
        uint64_t amount;
    };

    struct PositionCloseInfo {
        std::string pair;
        int positionsClosed;
        uint64_t avgEntry;
        uint64_t exit;
        double pnlPercent;
    };

    // FILLED → green/red tile
    void postFilled(const PositionFilledInfo &info) { twitter.postTweetWithImage(formatFilled(info), selectTile(info.direction)); }

    // CLOSED → text only
    void postClosed(const PositionCloseInfo &info) { twitter.postText(formatClosed(info)); }

  private:
    TwitterClient &twitter;

    std::string formatFilled(const PositionFilledInfo &info) {
        std::ostringstream oss;
        oss << "FILLED\n";
        oss << info.pair << "\n";
        oss << (info.direction == Direction::Long ? "BUY\n" : "SELL\n");
        oss << "Entry Price: $" << functions.formatIntUSD(info.entry) << "\n";
        oss << "Amount in Satoshis: " << functions.formatIntBTC(info.amount);
        return oss.str();
    }

    std::string formatClosed(const PositionCloseInfo &info) {
        std::ostringstream oss;
        oss << "CLOSED\n";
        oss << info.pair << "\n";
        oss << "Positions: " << info.positionsClosed << "\n";
        oss << "Average Entry Price: " << functions.formatIntUSD(info.avgEntry) << "\n";
        oss << "Exit Price: " << functions.formatIntUSD(info.exit) << "\n";
        oss << "Profit'n'Loss: " << formatPnL(info.pnlPercent);
        return oss.str();
    }

    std::string formatPnL(double pnl) {
        std::ostringstream oss;
        if (pnl >= 0.0)
            oss << "+";
        oss << pnl << "%";
        return oss.str();
    }

    std::string selectTile(Direction dir) { return (dir == Direction::Long) ? fileSystem.path_2.string() : fileSystem.path_3.string(); }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
/*
class TradingStrategy {
public:
    TradingStrategy(int period = 14)
        : period(period),
          inShortPosition(false),
          inLongPosition(false),
          shortEntryPrice(0.0),
          longEntryPrice(0.0),
          shortExitTarget(0.0),
          longExitTarget(0.0)
    {}

    void evaluate(const CandleCollector& collector) {
        auto USD = getLastNCloses(collector, "priceBTC_USD");
        auto GBP = getLastNCloses(collector, "priceBTC_GBP");
        auto EUR = getLastNCloses(collector, "priceBTC_EUR");

        if (USD.size() < period || GBP.size() < period || EUR.size() < period)
            return;

        // -------- Strategy 1: Pairs Trading --------
        std::vector<std::pair<std::string,std::string>> pairs = {
            {"priceBTC_USD","priceBTC_EUR"},
            {"priceBTC_USD","priceBTC_GBP"},
            {"priceBTC_EUR","priceBTC_GBP"},
        };

        for (auto& p : pairs) {
            std::string A = p.first;
            std::string B = p.second;
            auto closesA = getLastNCloses(collector, A);
            auto closesB = getLastNCloses(collector, B);
            tradingStrategy_1(A, B, closesA, closesB);
        }

        // -------- Strategy 2: SHORT Mean Reversion --------
        for (const auto& asset : assets) {
            auto closes = getLastNCloses(collector, asset);
            if (closes.size() < period) continue;
            tradingStrategy_2(asset, closes);
        }

        // -------- Strategy 3: LONG Mean Reversion --------
        for (const auto& asset : assets) {
            auto closes = getLastNCloses(collector, asset);
            if (closes.size() < period) continue;
            tradingStrategy_3(asset, closes);
        }
    }

private:
    int period;

    bool inShortPosition;
    bool inLongPosition;

    double shortEntryPrice;
    double longEntryPrice;

    double shortExitTarget;
    double longExitTarget;

    std::vector<std::string> assets = {"priceBTC_USD", "priceBTC_GBP", "priceBTC_EUR"};

    std::vector<uint64_t> getLastNCloses(const CandleCollector& collector, const std::string& symbol) {
        std::vector<uint64_t> out;

        auto it = collector.data.find(symbol);
        if (it == collector.data.end()) return out;

        const auto& closes = it->second.closes;
        size_t size = closes.size();

        if (size < period) return out;

        out.assign(closes.end() - period, closes.end());
        return out;
    }

    void tradingStrategy_1(const std::string& A, const std::string& B,
                           const std::vector<uint64_t>& closesA,
                           const std::vector<uint64_t>& closesB) {

        double h = computeHedgeRatio(closesA, closesB);

        std::vector<double> spread;
        for (size_t i = 0; i < closesA.size(); ++i)
            spread.push_back(double(closesA[i]) - h * double(closesB[i]));

        auto [mean, stddev] = computeStats(spread);
        double last = spread.back();

        if (last > mean + stddev) {
            placePairTradeShortA_LongB(A, B, h);
        }
        else if (last < mean - stddev) {
            placePairTradeLongA_ShortB(A, B, h);
        }
    }

    // -----------------------------------------------------
    // Strategy 2: SHORT — above upper band, exit at lower band
    // -----------------------------------------------------
    void tradingStrategy_2(const std::string& asset,
                           const std::vector<uint64_t>& closes) {

        auto [mean, stddev] = computeStats(closes);
        double last = closes.back();
        double upper = mean + stddev;
        double lower = mean - stddev;

        // ENTRY: Price crosses ABOVE upper band → SHORT
        if (!inShortPosition && last > upper) {

            inShortPosition = true;
            shortEntryPrice = last;
            shortExitTarget = lower;

            placeShortTrade(asset,
                            "SHORT ENTRY",
                            shortEntryPrice,
                            shortExitTarget,
                            mean, stddev
                           );

            return;
        }

        // EXIT: Price crosses BELOW lower band → close SHORT
        if (inShortPosition && last < shortExitTarget) {

            double exitPrice = last;
            double spread = shortEntryPrice - exitPrice;   // Short profit
            double pct = (spread / shortEntryPrice) * 100.0;

            placeShortTrade(asset,
                            "SHORT EXIT",
                            exitPrice,
                            shortExitTarget,
                            spread,
                            pct
                           );

            inShortPosition = false;
        }
    }

    // -----------------------------------------------------
    // Strategy 3: LONG — below lower band, exit at upper band
    // -----------------------------------------------------
    void tradingStrategy_3(const std::string& asset,
                           const std::vector<uint64_t>& closes) {

        auto [mean, stddev] = computeStats(closes);
        double last = closes.back();
        double upper = mean + stddev;
        double lower = mean - stddev;

        // ENTRY: Price crosses BELOW lower band → LONG
        if (!inLongPosition && last < lower) {

            inLongPosition = true;
            longEntryPrice = last;
            longExitTarget = upper;

            placeLongTrade(asset,
                           "LONG ENTRY",
                           longEntryPrice,
                           longExitTarget,
                           mean, stddev
                          );

            return;
        }

        // EXIT: Price crosses ABOVE upper band → close LONG
        if (inLongPosition && last > longExitTarget) {

            double exitPrice = last;
            double spread = exitPrice - longEntryPrice;
            double pct = (spread / longEntryPrice) * 100.0;

            placeLongTrade(asset,
                           "LONG EXIT",
                           exitPrice,
                           longExitTarget,
                           spread,
                           pct
                          );

            inLongPosition = false;
        }
    }

    template<typename T>
    std::pair<double,double> computeStats(const std::vector<T>& v) {
        int n = v.size();
        double mean = 0;
        for (auto x : v) mean += x;
        mean /= n;

        double var = 0;
        for (auto x : v) {
            double d = double(x) - mean;
            var += d*d;
        }
        var /= n;

        return { mean, std::sqrt(var) };
    }

    double computeHedgeRatio(const std::vector<uint64_t>& A,
                             const std::vector<uint64_t>& B) {

        int n = A.size();
        double meanA = 0, meanB = 0;
        for (int i=0; i<n; i++) {
            meanA+=A[i];
            meanB+=B[i];
        }
        meanA /= n;
        meanB /= n;

        double cov=0, varA=0;
        for (int i=0; i<n; i++) {
            cov += (A[i]-meanA)*(B[i]-meanB);
            varA += (A[i]-meanA)*(A[i]-meanA);
        }

        if (varA == 0) return 1.0;
        return cov / varA;
    }

    // -----------------------------------------------------
    // OUTPUT FUNCTIONS
    // -----------------------------------------------------

    void placePairTradeShortA_LongB(const std::string& A,
                                    const std::string& B,
                                    double h) {
        std::cout
                << "PAIR TRADE SIGNAL: Short " << A
                << " and Long " << B
                << " with hedge ratio h=" << h << "\n";
    }

    void placePairTradeLongA_ShortB(const std::string& A,
                                    const std::string& B,
                                    double h) {
        std::cout
                << "PAIR TRADE SIGNAL: Long " << A
                << " and Short " << B
                << " with hedge ratio h=" << h << "\n";
    }

    void placeShortTrade(const std::string& asset,
                         const std::string& type,
                         double price,
                         double target,
                         double a,
                         double b) {

        if (type == "SHORT ENTRY") {
            std::cout
                    << "[STRAT 2] " << type
                    << " on " << asset
                    << " @ " << price
                    << " | Exit Target: " << target
                    << " | Mean=" << a << " | StdDev=" << b
                    << "\n";
        }
        else {
            std::cout
                    << "[STRAT 2] SHORT EXIT"
                    << " on " << asset
                    << " @ " << price
                    << " | Profit=" << target
                    << " | %=" << a
                    << "\n";
        }
    }

    void placeLongTrade(const std::string& asset,
                        const std::string& type,
                        double price,
                        double target,
                        double a,
                        double b) {

        if (type == "LONG ENTRY") {
            std::cout
                    << "[STRAT 3] " << type
                    << " on " << asset
                    << " @ " << price
                    << " | Exit Target: " << target
                    << " | Mean=" << a << " | StdDev=" << b
                    << "\n";
        }
        else {
            std::cout
                    << "[STRAT 3] LONG EXIT"
                    << " on " << asset
                    << " @ " << price
                    << " | Profit=" << target
                    << " | %=" << a
                    << "\n";
        }
    }
};
*/

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class ReinforcementLearning {
  public:
    // Public types
    enum class StateType : int { Up = 0, Same = 1, Down = 2, Count = 3 };
    enum class ActionType : int { Buy = 0, Sell = 1, Count = 2 };

    ReinforcementLearning(double alpha = 0.1,
                          double gamma = 0.95,
                          double epsilon = 0.5,
                          double epsilonMin = 0.01,
                          double epsilonDecay = 0.999,
                          double increment = 1.0,
                          unsigned int rngSeed = std::random_device{}())
        : alpha(alpha), gamma(gamma), epsilon(epsilon), epsilonMin(epsilonMin), epsilonDecay(epsilonDecay), increment(increment), rng(rngSeed) {
        LOG_INFO("Class: ReinforcementLearning");
        resetQ();
        loadQTable(fileSystem.file_7); // Use FileSystem's qtable path
    }

    ActionType trainMarket(double currentPrice) {
        // Current price state transition
        StateType currentState = classifyState(previousPrice, currentPrice);

        // Reward for the transition
        int reward = computeReward(previousState, previousAction, currentState);

        // Update Q-table
        updateQ(previousState, previousAction, reward, currentState);

        // Select a new action (Buy or Sell)
        std::uniform_real_distribution<double> uni(0.0, 1.0);
        ActionType action = selectAction(currentState, uni);

        // Track reward
        totalReward += reward;

        // Move forward
        previousAction = action;
        previousState = currentState;
        previousPrice = currentPrice;

        // Save Q-table
        saveQTable(fileSystem.file_7); // Use FileSystem's qtable path

        // Return the chosen action
        return action;
    }

    // Train the agent on a price series for numEpisodes
    void trainData(const std::vector<double> &prices, int numEpisodes) {
        if (prices.size() < 3) {
            std::cerr << "Error: prices vector too small for training.\n";
            return;
        }

        const auto startTime = std::chrono::steady_clock::now();
        std::uniform_real_distribution<double> uni(0.0, 1.0);

        for (int episode = 1; episode <= numEpisodes; ++episode) {
            int totalReward = 0;

            // iterate transitions in price series (knowing next state)
            for (size_t i = 1; i < prices.size() - 1; ++i) {
                StateType currentState = classifyState(prices[i - 1], prices[i]);
                StateType nextState = classifyState(prices[i], prices[i + 1]);

                ActionType action = selectAction(currentState, uni);
                int reward = computeReward(currentState, action, nextState);

                updateQ(currentState, action, reward, nextState);
                totalReward += reward;

                // Save Q-table every 10,000 candles
                if (i % 10000 == 0) {
                    saveQTable(fileSystem.file_7); // Use FileSystem's qtable path
                }
            }

            // ETA calculation
            const auto now = std::chrono::steady_clock::now();
            double elapsedSec = std::chrono::duration<double>(now - startTime).count();
            double avgTimePerEpisode = elapsedSec / static_cast<double>(episode);
            double remainingTime = avgTimePerEpisode * (numEpisodes - episode);
            int etaMinutes = static_cast<int>(remainingTime) / 60;
            int etaSeconds = static_cast<int>(remainingTime) % 60;

            // Decay epsilon (but do not go below epsilonMin)
            if (epsilon > epsilonMin) {
                epsilon *= epsilonDecay;
                if (epsilon < epsilonMin)
                    epsilon = epsilonMin;
            }

            saveQTable(fileSystem.file_7); // Use FileSystem's qtable path

            // Print progress and ETA
            functions.printProgressBar(episode, numEpisodes);

            if (episode % 1 == 0 || episode == numEpisodes) {
                // std::cout << " Episode: " << episode << " ETA: " << etaMinutes << "m " << etaSeconds << "s"
                //          << " Reward: " << functions.formatWithCommas(totalReward) << " eps: " << std::fixed << std::setprecision(4) << epsilon;
            }
            std::cout << std::endl;
        }

        // std::cout << "\nTraining complete! \nPrinting Q-Table...";
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get();
        // std::this_thread::sleep_for(std::chrono::milliseconds(10000));

        // Final print and save
        printQTable();
        saveQTable(fileSystem.file_7); // Use FileSystem's qtable path
        // std::cout << "\nTraining complete. Final Q-table saved to qtable.csv\n";
    }

    // Reset Q-values to zero
    void resetQ() {
        for (auto &row : Q)
            row.fill(0.0);
    }

    // Save Q table to CSV (stateIndex,actionIndex,qvalue)
    void saveQTable(const fs::path &filepath) const {
        std::ofstream out(filepath);
        if (!out) {
            std::cerr << "Error opening file for saving Q-table: " << filepath << "\n";
            return;
        }
        for (int s = 0; s < static_cast<int>(StateType::Count); ++s) {
            for (int a = 0; a < static_cast<int>(ActionType::Count); ++a) {
                out << s << "," << a << "," << std::setprecision(12) << Q[s][a] << "\n";
            }
        }
    }

    // Load Q table from CSV (if present). Will silently skip bad lines.
    void loadQTable(const fs::path &filepath) {
        std::ifstream in(filepath);
        if (!in) {
            std::cerr << "Q-table file not found. Starting fresh.\n";
            return;
        }

        resetQ();
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty())
                continue;
            std::istringstream ss(line);
            int s, a;
            double q;
            char comma;
            if ((ss >> s >> comma >> a >> comma >> q) || parseCsvLine(line, s, a, q)) {
                if (s >= 0 && s < static_cast<int>(StateType::Count) && a >= 0 && a < static_cast<int>(ActionType::Count)) {
                    Q[s][a] = q;
                }
            }
        }
    }

    // Print Q table (compact)
    void printQTable() const {
        // std::cout << "\nFinal Q-Table (rows = State: Up, Same, Down; cols = Action: Buy, Sell)\n";
        // std::cout << std::setw(8) << "" << std::setw(12) << "Buy" << std::setw(12) << "Sell" << "\n";
        for (int s = 0; s < static_cast<int>(StateType::Count); ++s) {
            // std::cout << std::setw(8) << stateToString(static_cast<StateType>(s));
            for (int a = 0; a < static_cast<int>(ActionType::Count); ++a) {
                // std::cout << std::setw(12) << std::fixed << std::setprecision(6) << Q[s][a];
            }
            // std::cout << "\n";
        }
    }

  private:
    // Initialize previous state/action properly
    StateType previousState = StateType::Same;   // arbitrary start state
    ActionType previousAction = ActionType::Buy; // arbitrary start action
    double previousPrice = 0.0;
    int totalReward;

    // Q is a 3 x 2 table (states x actions)
    // Q[stateIndex][actionIndex]
    std::array<std::array<double, static_cast<int>(ActionType::Count)>, static_cast<int>(StateType::Count)> Q{};

    // Hyperparameters and internal state
    double alpha;
    double gamma;
    double epsilon;
    double epsilonMin;
    double epsilonDecay;
    double increment;

    // RNG for epsilon-greedy
    mutable std::mt19937 rng;

    // Utility: convert enums to indices
    static inline int sIndex(StateType s) { return static_cast<int>(s); }
    static inline int aIndex(ActionType a) { return static_cast<int>(a); }

    // Action selection (epsilon-greedy)
    ActionType selectAction(StateType s, std::uniform_real_distribution<double> &uni) {
        double r = uni(rng);
        if (r < epsilon) {
            // random action
            std::uniform_int_distribution<int> di(0, static_cast<int>(ActionType::Count) - 1);
            return static_cast<ActionType>(di(rng));
        }

        // greedy: choose action with max Q
        int si = sIndex(s);
        double qBuy = Q[si][aIndex(ActionType::Buy)];
        double qSell = Q[si][aIndex(ActionType::Sell)];
        return (qBuy >= qSell) ? ActionType::Buy : ActionType::Sell;
    }

    // Update rule (Q-learning)
    void updateQ(StateType s, ActionType a, double reward, StateType nextS) {
        int si = sIndex(s);
        int ai = aIndex(a);
        int nsi = sIndex(nextS);

        double maxNextQ = Q[nsi][0];
        for (int i = 1; i < static_cast<int>(ActionType::Count); ++i)
            maxNextQ = std::max(maxNextQ, Q[nsi][i]);

        Q[si][ai] = Q[si][ai] + alpha * (reward + gamma * maxNextQ - Q[si][ai]);
    }

    int computeReward(StateType currentState, ActionType action, StateType nextState) const {
        int base = 0;

        // Correct predictions
        if (currentState == StateType::Up && action == ActionType::Buy && nextState == StateType::Up) {
            base = 2;
        }
        if (currentState == StateType::Down && action == ActionType::Sell && nextState == StateType::Down) {
            base = 2;
        }
        if (currentState == StateType::Same && action == ActionType::Buy && nextState == StateType::Up) {
            base = 1;
        }
        if (currentState == StateType::Same && action == ActionType::Sell && nextState == StateType::Down) {
            base = 1;
        }

        // Incorrect predictions
        if (currentState == StateType::Up && action == ActionType::Buy && nextState == StateType::Down) {
            base = -2;
        }
        if (currentState == StateType::Down && action == ActionType::Sell && nextState == StateType::Up) {
            base = -2;
        }
        if (currentState == StateType::Same && action == ActionType::Buy && nextState == StateType::Down) {
            base = -1;
        }
        if (currentState == StateType::Same && action == ActionType::Sell && nextState == StateType::Up) {
            base = -1;
        }

        return base;
    }

    // Classify state from previous and current price (uses increment threshold)
    StateType classifyState(double prev, double curr) const {
        double diff = curr - prev;
        if (std::abs(diff) < increment)
            return StateType::Same;
        if (diff >= increment)
            return StateType::Up;
        return StateType::Down;
    }

    // Pretty names
    static std::string stateToString(StateType s) {
        switch (s) {
        case StateType::Up:
            return "Up";
        case StateType::Same:
            return "Same";
        case StateType::Down:
            return "Down";
        default:
            return "Unknown";
        }
    }

    // Helper: parse CSV line "s,a,q" robustly
    static bool parseCsvLine(const std::string &line, int &s, int &a, double &q) {
        std::istringstream ss(line);
        std::string part;
        if (!std::getline(ss, part, ','))
            return false;
        try {
            s = std::stoi(part);
        } catch (...) {
            return false;
        }
        if (!std::getline(ss, part, ','))
            return false;
        try {
            a = std::stoi(part);
        } catch (...) {
            return false;
        }
        if (!std::getline(ss, part, ','))
            return false;
        try {
            q = std::stod(part);
        } catch (...) {
            return false;
        }
        return true;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class MovingAverage {
  public:
    // Simple Moving Average
    static double SMA(const CandleCollector &collector, int period) {
        const auto &closes = collector.getCloses();

        if (closes.size() < period || period <= 0)
            return 0.0;

        double sum = 0.0;
        for (size_t i = closes.size() - period; i < closes.size(); ++i)
            sum += closes[i];

        return sum / period;
    }

    // Exponential Moving Average
    static double EMA(const CandleCollector &collector, int period) {
        const auto &closes = collector.getCloses();

        if (closes.size() < period || period <= 0)
            return 0.0;

        double k = 2.0 / (period + 1); // smoothing factor
        double emaPrev = 0.0;

        // Seed EMA with SMA of first period
        for (int i = 0; i < period; ++i)
            emaPrev += closes[i];
        emaPrev /= period;

        // EMA calculation
        for (size_t i = period; i < closes.size(); ++i)
            emaPrev = (closes[i] * k) + (emaPrev * (1 - k));

        return emaPrev;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class RelativeStrengthIndex {
  public:
    static double calculateRSI(const CandleCollector &collector, int period = 14) {
        const std::vector<double> &prices = collector.getCloses();

        if (prices.size() <= static_cast<size_t>(period))
            return 0.0;

        double gain = 0.0, loss = 0.0;

        // Initial average gain/loss
        for (int i = 1; i <= period; ++i) {
            double change = prices[i] - prices[i - 1];
            if (change > 0.0)
                gain += change;
            else
                loss += -change;
        }

        double avgGain = gain / period;
        double avgLoss = loss / period;

        double rs = (avgLoss == 0.0) ? 0.0 : (avgGain / avgLoss);
        double rsi = (avgLoss == 0.0) ? 100.0 : 100.0 - (100.0 / (1.0 + rs));

        // Smoothing for subsequent values
        for (size_t i = period + 1; i < prices.size(); ++i) {
            double change = prices[i] - prices[i - 1];
            double g = (change > 0.0) ? change : 0.0;
            double l = (change < 0.0) ? -change : 0.0;

            avgGain = ((avgGain * (period - 1)) + g) / period;
            avgLoss = ((avgLoss * (period - 1)) + l) / period;

            rs = (avgLoss == 0.0) ? 0.0 : (avgGain / avgLoss);
            rsi = (avgLoss == 0.0) ? 100.0 : 100.0 - (100.0 / (1.0 + rs));
        }

        return rsi;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class MACD {
  public:
    struct MACDResult {
        double macdLine;
        double signalLine;
        double histogram;
        std::string trend;
    };

    // Self-contained MACD calculation
    static MACDResult calculate(const CandleCollector &collector, int fastPeriod = 12, int slowPeriod = 26, int signalPeriod = 9) {
        const auto &closes = collector.getCloses();
        size_t n = closes.size();
        if (n < static_cast<size_t>(slowPeriod))
            return {0.0, 0.0, 0.0, "Neutral"};

        std::vector<double> fastEMA(n, 0.0);
        std::vector<double> slowEMA(n, 0.0);
        std::vector<double> macdSeries(n, 0.0);

        double kFast = 2.0 / (fastPeriod + 1);
        double kSlow = 2.0 / (slowPeriod + 1);
        double kSignal = 2.0 / (signalPeriod + 1);

        // Initialize first EMA values as simple averages
        double sumFast = 0.0, sumSlow = 0.0;
        for (int i = 0; i < fastPeriod; ++i)
            sumFast += closes[i];
        for (int i = 0; i < slowPeriod; ++i)
            sumSlow += closes[i];

        fastEMA[fastPeriod - 1] = sumFast / fastPeriod;
        slowEMA[slowPeriod - 1] = sumSlow / slowPeriod;

        // Calculate EMAs
        for (size_t i = fastPeriod; i < n; ++i)
            fastEMA[i] = closes[i] * kFast + fastEMA[i - 1] * (1 - kFast);

        for (size_t i = slowPeriod; i < n; ++i)
            slowEMA[i] = closes[i] * kSlow + slowEMA[i - 1] * (1 - kSlow);

        // Build MACD series
        for (size_t i = 0; i < n; ++i)
            macdSeries[i] = fastEMA[i] - slowEMA[i];

        // Signal line EMA
        std::vector<double> signalEMA(n, 0.0);
        double sumSignal = 0.0;
        for (int i = slowPeriod - 1; i < slowPeriod - 1 + signalPeriod && i < static_cast<int>(n); ++i)
            sumSignal += macdSeries[i];

        int signalStart = slowPeriod - 1 + signalPeriod - 1;
        if (signalStart >= static_cast<int>(n))
            signalStart = n - 1;

        signalEMA[signalStart] = sumSignal / signalPeriod;

        for (size_t i = signalStart + 1; i < n; ++i)
            signalEMA[i] = macdSeries[i] * kSignal + signalEMA[i - 1] * (1 - kSignal);

        double macdLine = macdSeries.back();
        double signalLine = signalEMA.back();
        double histogram = macdLine - signalLine;
        std::string trend = (histogram > 0.0) ? "Bullish" : (histogram < 0.0) ? "Bearish" : "Neutral";

        return {macdLine, signalLine, histogram, trend};
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class BollingerBands {
  public:
    struct BollingerBandsResult {
        double middle;
        double upper;
        double lower;
        std::string trend;
    };

    // Calculate Bollinger Bands using CandleCollector
    static BollingerBandsResult calculate(const CandleCollector &collector, int period = 20, double k = 2.0) {
        BollingerBandsResult bands{0.0, 0.0, 0.0, "Neutral"};
        const auto &closes = collector.getCloses();

        if (closes.size() < static_cast<size_t>(period))
            return bands;

        // Compute SMA
        double sum = 0.0;
        for (size_t i = closes.size() - period; i < closes.size(); ++i)
            sum += closes[i];
        double sma = sum / period;

        // Compute standard deviation
        double variance = 0.0;
        for (size_t i = closes.size() - period; i < closes.size(); ++i) {
            double diff = closes[i] - sma;
            variance += diff * diff;
        }
        variance /= period;
        double stddev = std::sqrt(variance);

        bands.middle = sma;
        bands.upper = sma + k * stddev;
        bands.lower = sma - k * stddev;

        // Trend determination
        double lastPrice = closes.back();
        if (lastPrice > bands.upper)
            bands.trend = "Overbought";
        else if (lastPrice < bands.lower)
            bands.trend = "Oversold";
        else
            bands.trend = "Neutral";

        return bands;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class VolumeIndicators {
  public:
    // On-Balance Volume (OBV) with rolling period
    static std::vector<double> calculateOBV(const CandleCollector &collector, int period = 20) {
        const auto &closes = collector.getCloses();
        const auto &volumes = collector.getVolumes();

        std::vector<double> obv(closes.size(), 0.0);
        if (closes.size() < 2)
            return obv;

        // First, compute standard cumulative OBV
        for (size_t i = 1; i < closes.size(); ++i) {
            if (closes[i] > closes[i - 1])
                obv[i] = obv[i - 1] + volumes[i];
            else if (closes[i] < closes[i - 1])
                obv[i] = obv[i - 1] - volumes[i];
            else
                obv[i] = obv[i - 1];
        }

        // Apply rolling sum if period < total size
        if (period > 0 && closes.size() > static_cast<size_t>(period)) {
            std::vector<double> rollingOBV(closes.size(), 0.0);
            for (size_t i = 0; i < closes.size(); ++i) {
                size_t start = (i < static_cast<size_t>(period)) ? 0 : i - period + 1;
                double sum = 0.0;
                for (size_t j = start; j <= i; ++j)
                    sum += (j == 0) ? obv[j] : obv[j] - obv[j - 1];
                rollingOBV[i] = sum;
            }
            return rollingOBV;
        }

        return obv;
    }

    // VWAP with rolling period
    static double calculateVWAP(const CandleCollector &collector, int period = 1) {
        const auto &closes = collector.getCloses();
        const auto &highs = collector.getHighs();
        const auto &lows = collector.getLows();
        const auto &volumes = collector.getVolumes();

        if (closes.empty())
            return 0.0;

        size_t start = (closes.size() < static_cast<size_t>(period)) ? 0 : closes.size() - period;
        double cumPV = 0.0;
        double cumVol = 0.0;

        for (size_t i = start; i < closes.size(); ++i) {
            double typicalPrice = (highs[i] + lows[i] + closes[i]) / 3.0;
            cumPV += typicalPrice * volumes[i];
            cumVol += volumes[i];
        }

        return (cumVol != 0.0) ? (cumPV / cumVol) : 0.0;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class AverageTrueRange {
  public:
    // ATR calculation using CandleCollector
    static double calculateATR(const CandleCollector &collector, int period = 14) {
        const auto &highs = collector.getHighs();
        const auto &lows = collector.getLows();
        const auto &closes = collector.getCloses();

        size_t n = closes.size();
        if (n <= static_cast<size_t>(period))
            return 0.0;

        double atr = 0.0;

        // First ATR value: simple average of True Range
        for (size_t i = 1; i <= static_cast<size_t>(period); ++i) {
            double tr = std::max({highs[i] - lows[i], std::abs(highs[i] - closes[i - 1]), std::abs(lows[i] - closes[i - 1])});
            atr += tr;
        }
        atr /= period;

        // Subsequent ATR values: Wilder's smoothing
        for (size_t i = period + 1; i < n; ++i) {
            double tr = std::max({highs[i] - lows[i], std::abs(highs[i] - closes[i - 1]), std::abs(lows[i] - closes[i - 1])});
            atr = ((atr * (period - 1)) + tr) / period;
        }

        return atr;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class StochasticOscillator {
  public:
    struct StochasticResult {
        double percentK;
        double percentD;
        std::string trend;
    };

    // Calculate Stochastic Oscillator using CandleCollector
    static StochasticResult calculate(const CandleCollector &collector, int kPeriod = 14, int dPeriod = 3) {
        const auto &highs = collector.getHighs();
        const auto &lows = collector.getLows();
        const auto &closes = collector.getCloses();

        size_t n = closes.size();
        if (n < static_cast<size_t>(kPeriod))
            return {0.0, 0.0, "Neutral"};

        // --- %K calculation ---
        double highestHigh = highs[n - kPeriod];
        double lowestLow = lows[n - kPeriod];
        for (size_t i = n - kPeriod; i < n; ++i) {
            highestHigh = std::max(highestHigh, highs[i]);
            lowestLow = std::min(lowestLow, lows[i]);
        }

        double close = closes.back();
        double percentK = (highestHigh != lowestLow) ? ((close - lowestLow) / (highestHigh - lowestLow)) * 100.0 : 0.0;

        // --- %D calculation (SMA of last dPeriod %K values) ---
        std::vector<double> kValues;
        size_t startIndex = (n >= static_cast<size_t>(kPeriod + dPeriod - 1)) ? n - dPeriod : 0;

        for (size_t i = startIndex; i < n; ++i) {
            double hHigh = highs[i], lLow = lows[i];
            size_t jStart = (i + 1 >= static_cast<size_t>(kPeriod)) ? i + 1 - kPeriod : 0;
            for (size_t j = jStart; j <= i; ++j) {
                hHigh = std::max(hHigh, highs[j]);
                lLow = std::min(lLow, lows[j]);
            }
            double k = (hHigh != lLow) ? ((closes[i] - lLow) / (hHigh - lLow)) * 100.0 : 0.0;
            kValues.push_back(k);
        }

        double percentD = 0.0;
        for (double val : kValues)
            percentD += val;
        percentD /= kValues.size();

        // --- Trend determination ---
        std::string trend;
        if (percentK > 80.0)
            trend = "Overbought";
        else if (percentK < 20.0)
            trend = "Oversold";
        else
            trend = "Neutral";

        return {percentK, percentD, trend};
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class FibonacciRetracement {
  public:
    struct FibonacciResult {
        std::vector<double> levels;
    };

    // Calculate standard Fibonacci retracement levels using CandleCollector
    static FibonacciResult calculate(const CandleCollector &collector) {
        const auto &highs = collector.getHighs();
        const auto &lows = collector.getLows();

        if (highs.empty() || lows.empty())
            return {{}}; // return empty if no data

        double recentHigh = *std::max_element(highs.begin(), highs.end());
        double recentLow = *std::min_element(lows.begin(), lows.end());

        std::vector<double> levels;
        std::vector<double> ratios = {0.236, 0.382, 0.5, 0.618, 0.786};

        for (double ratio : ratios)
            levels.push_back(recentHigh - (recentHigh - recentLow) * ratio);

        return {levels};
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class IchimokuCloud {
  public:
    struct IchimokuResult {
        double tenkanSen;
        double kijunSen;
        double senkouSpanA;
        double senkouSpanB;
        double chikouSpan;
        std::string trend;
    };

    static IchimokuResult calculate(const CandleCollector &collector) {
        const auto &highs = collector.getHighs();
        const auto &lows = collector.getLows();
        const auto &closes = collector.getCloses();

        size_t len = closes.size();
        if (len < 52)
            return {0.0, 0.0, 0.0, 0.0, 0.0, "Neutral"};

        double tenkan = midHighLow(highs, lows, 9);
        double kijun = midHighLow(highs, lows, 26);
        double senkouA = (tenkan + kijun) / 2.0;
        double senkouB = midHighLow(highs, lows, 52);
        double chikou = closes[len - 26]; // closing price 26 periods ago

        std::string trend;
        if (closes.back() > senkouA && closes.back() > senkouB)
            trend = "Bullish";
        else if (closes.back() < senkouA && closes.back() < senkouB)
            trend = "Bearish";
        else
            trend = "Neutral";

        return {tenkan, kijun, senkouA, senkouB, chikou, trend};
    }

  private:
    // Calculate midpoint of high/low over a given period
    static double midHighLow(const std::vector<double> &highs, const std::vector<double> &lows, int period) {
        if (highs.size() < static_cast<size_t>(period))
            return 0.0;

        double highest = highs[highs.size() - period];
        double lowest = lows[highs.size() - period];

        for (size_t i = highs.size() - period; i < highs.size(); ++i) {
            if (highs[i] > highest)
                highest = highs[i];
            if (lows[i] < lowest)
                lowest = lows[i];
        }

        return (highest + lowest) / 2.0;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class AverageDirectionalIndex {
  public:
    struct ADXResult {
        double plusDI;
        double minusDI;
        double adx;
        std::string trendStrength;
    };

    static ADXResult calculate(const CandleCollector &collector, int period = 14) {
        const auto &highs = collector.getHighs();
        const auto &lows = collector.getLows();
        const auto &closes = collector.getCloses();

        size_t n = closes.size();
        if (n <= static_cast<size_t>(period))
            return {0.0, 0.0, 0.0, "Neutral"};

        std::vector<double> trVec, plusDMVec, minusDMVec;

        for (size_t i = 1; i < n; ++i) {
            double highDiff = highs[i] - highs[i - 1];
            double lowDiff = lows[i - 1] - lows[i];

            double plusDM = (highDiff > lowDiff && highDiff > 0.0) ? highDiff : 0.0;
            double minusDM = (lowDiff > highDiff && lowDiff > 0.0) ? lowDiff : 0.0;

            double tr = std::max({highs[i] - lows[i], std::abs(highs[i] - closes[i - 1]), std::abs(lows[i] - closes[i - 1])});

            plusDMVec.push_back(plusDM);
            minusDMVec.push_back(minusDM);
            trVec.push_back(tr);
        }

        // Initial smoothed averages
        double smTR = 0.0, smPlus = 0.0, smMinus = 0.0;
        for (int i = 0; i < period; ++i) {
            smTR += trVec[i];
            smPlus += plusDMVec[i];
            smMinus += minusDMVec[i];
        }

        smTR /= period;
        smPlus /= period;
        smMinus /= period;

        double plusDI = 100.0 * (smPlus / smTR);
        double minusDI = 100.0 * (smMinus / smTR);
        double dx = 100.0 * std::abs(plusDI - minusDI) / (plusDI + minusDI);
        double adx = dx;

        // Wilder's smoothing for the rest
        for (size_t i = period; i < trVec.size(); ++i) {
            smTR = smTR - (smTR / period) + trVec[i];
            smPlus = smPlus - (smPlus / period) + plusDMVec[i];
            smMinus = smMinus - (smMinus / period) + minusDMVec[i];

            plusDI = 100.0 * (smPlus / smTR);
            minusDI = 100.0 * (smMinus / smTR);
            dx = 100.0 * std::abs(plusDI - minusDI) / (plusDI + minusDI);

            adx = ((adx * (period - 1)) + dx) / period;
        }

        std::string trendStrength;
        if (adx > 25.0)
            trendStrength = "Strong";
        else if (adx > 20.0)
            trendStrength = "Moderate";
        else
            trendStrength = "Weak";

        return {plusDI, minusDI, adx, trendStrength};
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class OutputBuffer {
  public:
    void add(std::string_view msg) {
        if (!enabled)
            return;
        std::lock_guard<std::mutex> lock(mtx);
        buffer.emplace_back(msg);
        cv.notify_one();
    }

    void setEnabled(bool e) { enabled = e; }
    bool isEnabled() const { return enabled; }

    void stop() {
        running = false;
        cv.notify_all();
        if (consumer.joinable())
            consumer.join();
    }

  private:
    std::vector<std::string> buffer;
    std::mutex mtx;
    std::condition_variable cv;
    std::atomic<bool> running{true};
    std::atomic<bool> enabled{true};
    std::thread consumer{[this] { consumeLoop(); }};

    void consumeLoop() {
        std::vector<std::string> local;
        while (running) {
            {
                std::unique_lock<std::mutex> lock(mtx);
                cv.wait(lock, [&] { return !buffer.empty() || !running; });
                if (!running && buffer.empty())
                    break;
                std::swap(local, buffer);
            }
            for (auto &msg : local) {
                // std::cout << msg << '\n';
            }
            std::cout.flush();
            local.clear();
        }
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
/*
struct OrderBookEntry {
    double price;
    double volume;
    uint64_t timestamp;  // seconds since epoch
};

struct OrderBook {
    std::vector<OrderBookEntry> bids;
    std::vector<OrderBookEntry> asks;
};

OrderBook getOrderBook(const std::string& pair, int count = 100) {
    OrderBook book;

    // count must be between 1 and 500
    if (count < 1) count = 1;
    if (count > 500) count = 500;

    std::string url = "https://api.kraken.com/0/public/Depth?pair=" + pair + "&count=" + std::to_string(count);

    std::string response = curl.get(url);
    auto j = json::parse(response);

    if (!j["error"].empty()) {
        throw std::runtime_error("Kraken API error: " + j["error"].dump());
    }

    const auto& result = j["result"][pair];

    // Parse asks
    for (const auto& entry : result["asks"]) {
        OrderBookEntry e;
        e.price     = entry[0].is_string() ? std::stod(entry[0].get<std::string>()) : entry[0].get<double>();
        e.volume    = entry[1].is_string() ? std::stod(entry[1].get<std::string>()) : entry[1].get<double>();
        e.timestamp = entry[2].is_string() ? std::stoull(entry[2].get<std::string>()) : entry[2].get<uint64_t>();
        book.asks.push_back(e);
    }

    // Parse bids
    for (const auto& entry : result["bids"]) {
        OrderBookEntry e;
        e.price     = entry[0].is_string() ? std::stod(entry[0].get<std::string>()) : entry[0].get<double>();
        e.volume    = entry[1].is_string() ? std::stod(entry[1].get<std::string>()) : entry[1].get<double>();
        e.timestamp = entry[2].is_string() ? std::stoull(entry[2].get<std::string>()) : entry[2].get<uint64_t>();
        book.bids.push_back(e);
    }

    return book;
}

KrakenOHLCFetcher fetcher(curlClient);

try {
    OrderBook book = fetcher.getOrderBook("XXBTZUSD", 10);  // top 10 levels

    std::cout << "=== BIDS (Buy Orders) ===\n";
    for (const auto& b : book.bids) {
        std::cout << "Price: " << std::fixed << std::setprecision(1) << b.price
                  << " | Volume: " << b.volume << "\n";
    }

    std::cout << "\n=== ASKS (Sell Orders) ===\n";
    for (const auto& a : book.asks) {
        std::cout << "Price: " << std::fixed << std::setprecision(1) << a.price
                  << " | Volume: " << a.volume << "\n";
    }
} catch (const std::exception& e) {
    std::cerr << "Error fetching order book: " << e.what() << std::endl;
}

void printOrderBookDepth(const OrderBook& book, int levels = 10) {
    // Take top N bids and asks
    auto bids = book.bids;
    auto asks = book.asks;

    // Sort bids descending (highest first)
    std::sort(bids.begin(), bids.end(), [](const auto& a, const auto& b) { return a.price > b.price; });
    // Asks already ascending

    if (bids.size() > levels) bids.resize(levels);
    if (asks.size() > levels) asks.resize(levels);

    std::cout << "--- Order Book Depth ---\n";
    std::cout << std::string(80, '-') << "\n";

    // Print asks (top down)
    for (int i = asks.size() - 1; i >= 0; --i) {
        std::cout << std::fixed << std::setprecision(1)
                  << std::setw(10) << asks[i].price << " | "
                  << std::string(static_cast<int>(asks[i].volume * 10), '#')  // scale for visibility
                  << " (" << asks[i].volume << " BTC)\n";
    }

    // Mid price
    double mid = (bids.empty() || asks.empty()) ? 0 : (bids[0].price + asks[0].price) / 2;
    std::cout << std::string(80, '-') << "\n";
    std::cout << "MID PRICE: " << std::fixed << std::setprecision(1) << mid << "\n";
    std::cout << std::string(80, '-') << "\n";

    // Print bids (top down = highest bid first)
    for (size_t i = 0; i < bids.size(); ++i) {
        std::cout << std::fixed << std::setprecision(1)
                  << std::setw(10) << bids[i].price << " | "
                  << std::string(static_cast<int>(bids[i].volume * 10), '#')
                  << " (" << bids[i].volume << " BTC)\n";
    }
}
*/

class Chart {
  public:
    Chart(const Parameters &params) : params(params), increment_double(static_cast<double>(params.increment) / 100.0), tickCount(0), hasActiveCandle(false) {
        LOG_INFO("Class: Chart");
    }

    struct OHLCV {
        uint64_t timestamp = 0;
        double open = 0.0;
        double high = 0.0;
        double low = 0.0;
        double close = 0.0;
        double volume = 0.0;
        int count = 0;
    };

    // Constants
    static constexpr int CHART_WIDTH = 69;
    static constexpr int RIGHT_PADDING = 5;
    static constexpr int VISIBLE_WIDTH = CHART_WIDTH - RIGHT_PADDING;
    static constexpr int PRICE_HEIGHT = 20;
    static constexpr int VOLUME_HEIGHT = 5;
    static constexpr int TOTAL_HEIGHT = PRICE_HEIGHT + VOLUME_HEIGHT + 3; // +3: title + blank + stats below border
    static constexpr int LABEL_WIDTH = 10;
    static constexpr int TITLE_ROW = 0;            // Timestamp at top
    static constexpr int CHART_START_ROW = 1;      // Chart starts right after title
    static constexpr int STATS_ROW = TOTAL_HEIGHT; // Stats on the very last row

    void addCandle(double rawPrice, double rawVolume, uint64_t timestamp, int tradeCount) {
        double price = rawPrice / 100.0;
        double volume = rawVolume;

        if (!hasActiveCandle) {
            current = {timestamp, price, price, price, price, volume, tradeCount};
            tickCount = 1;
            hasActiveCandle = true;
            return;
        }

        current.high = std::max(current.high, price);
        current.low = std::min(current.low, price);
        current.close = price;
        current.volume += volume;
        current.count += tradeCount;
        current.timestamp = timestamp;

        ++tickCount;

        uint64_t currentPeriod = params.getPeriod();
        if (tickCount >= currentPeriod) {
            pushCandle(current);
            hasActiveCandle = false;
            tickCount = 0;
        }
    }

    std::vector<std::string> getChartLines() const {
        std::vector<std::string> canvas(TOTAL_HEIGHT + 1, std::string(CHART_WIDTH + 1 + LABEL_WIDTH, ' '));

        bool hasData = !buffer.empty() || hasActiveCandle;
        if (!hasData)
            return canvas;

        // === Timestamp title (top) ===
        uint64_t currentTs = hasActiveCandle ? current.timestamp : buffer.back().timestamp;
        std::string titleLine = "Timestamp: " + std::to_string(currentTs);
        int titleX = (CHART_WIDTH + LABEL_WIDTH - static_cast<int>(titleLine.length())) / 2;
        titleX = std::max(titleX, 0);

        for (size_t i = 0; i < titleLine.length() && (titleX + i) < canvas[TITLE_ROW].size(); ++i) {
            canvas[TITLE_ROW][titleX + i] = titleLine[i];
        }

        double refPrice = hasActiveCandle ? current.close : buffer.back().close;
        double halfRange = (PRICE_HEIGHT / 2.0) * increment_double;
        double minPrice = std::floor((refPrice - halfRange) / increment_double) * increment_double;

        // Vertical separator
        for (int y = 0; y < PRICE_HEIGHT; ++y) {
            canvas[y + CHART_START_ROW][CHART_WIDTH] = '|';
        }

        // Price candles
        for (size_t i = 0; i < buffer.size(); ++i) {
            int x = static_cast<int>(i);
            if (x >= VISIBLE_WIDTH)
                break;

            int yHigh = PRICE_HEIGHT - 1 - static_cast<int>(std::round((buffer[i].high - minPrice) / increment_double));
            int yLow = PRICE_HEIGHT - 1 - static_cast<int>(std::round((buffer[i].low - minPrice) / increment_double));

            yHigh = std::clamp(yHigh, 0, PRICE_HEIGHT - 1);
            yLow = std::clamp(yLow, 0, PRICE_HEIGHT - 1);

            for (int y = yHigh; y <= yLow; ++y) {
                canvas[y + CHART_START_ROW][x] = '#';
            }
        }

        if (hasActiveCandle) {
            int x = static_cast<int>(buffer.size());
            if (x < VISIBLE_WIDTH) {
                int yHigh = PRICE_HEIGHT - 1 - static_cast<int>(std::round((current.high - minPrice) / increment_double));
                int yLow = PRICE_HEIGHT - 1 - static_cast<int>(std::round((current.low - minPrice) / increment_double));

                yHigh = std::clamp(yHigh, 0, PRICE_HEIGHT - 1);
                yLow = std::clamp(yLow, 0, PRICE_HEIGHT - 1);

                for (int y = yHigh; y <= yLow; ++y) {
                    canvas[y + CHART_START_ROW][x] = '*';
                }
            }
        }

        // Volume bars
        const int volumeRowStart = PRICE_HEIGHT + CHART_START_ROW + 1;
        const int maxBarHeight = VOLUME_HEIGHT;

        for (size_t i = 0; i < buffer.size(); ++i) {
            int x = static_cast<int>(i);
            if (x >= VISIBLE_WIDTH)
                break;

            double vol = buffer[i].volume;
            int barHeight = (vol > 0.0) ? static_cast<int>(std::floor(vol)) + 1 : 0;
            barHeight = std::clamp(barHeight, 0, maxBarHeight);

            for (int h = 0; h < barHeight; ++h) {
                int y = volumeRowStart + (maxBarHeight - 1 - h);
                canvas[y][x] = '#';
            }
        }

        if (hasActiveCandle) {
            int x = static_cast<int>(buffer.size());
            if (x < VISIBLE_WIDTH) {
                double vol = current.volume;
                int barHeight = (vol > 0.0) ? static_cast<int>(std::floor(vol)) + 1 : 0;
                barHeight = std::clamp(barHeight, 0, maxBarHeight);

                for (int h = 0; h < barHeight; ++h) {
                    int y = volumeRowStart + (maxBarHeight - 1 - h);
                    canvas[y][x] = '*';
                }
            }
        }

        // Price labels
        for (int y = 0; y < PRICE_HEIGHT; ++y) {
            double price = minPrice + (PRICE_HEIGHT - 1 - y) * increment_double;
            std::string label = formatDouble(price);

            int startPos = CHART_WIDTH + 1 + (LABEL_WIDTH - static_cast<int>(label.size()));
            startPos = std::max(startPos, CHART_WIDTH + 1);

            for (size_t j = 0; j < label.size(); ++j) {
                int pos = startPos + static_cast<int>(j);
                if (pos < CHART_WIDTH + 1 + LABEL_WIDTH) {
                    canvas[y + CHART_START_ROW][pos] = label[j];
                }
            }
        }

        // Separator after price/volume area
        for (int x = 0; x < CHART_WIDTH + 1 + LABEL_WIDTH; ++x) {
            canvas[PRICE_HEIGHT + CHART_START_ROW][x] = '-';
        }

        // === Bottom border (one row above stats) ===
        for (int x = 0; x < CHART_WIDTH + 1 + LABEL_WIDTH; ++x) {
            canvas[TOTAL_HEIGHT - 1][x] = '-';
        }

        // === Stats row at the very bottom ===
        int currentTrades = hasActiveCandle ? current.count : buffer.back().count;
        double currentVolume = hasActiveCandle ? current.volume : buffer.back().volume;
        double currentAvgSize = (currentTrades > 0) ? currentVolume / currentTrades : 0.0;

        double avgTradeSize14 = 0.0;
        size_t candlesToCheck = std::min<size_t>(14, buffer.size());
        if (candlesToCheck > 0) {
            double totalVol = 0.0;
            int totalTrades = 0;
            for (size_t i = buffer.size() - candlesToCheck; i < buffer.size(); ++i) {
                totalVol += buffer[i].volume;
                totalTrades += buffer[i].count;
            }
            avgTradeSize14 = (totalTrades > 0) ? totalVol / totalTrades : 0.0;
        }

        std::string pctDiff = "";
        if (avgTradeSize14 > 0.0) {
            double diff = ((currentAvgSize - avgTradeSize14) / avgTradeSize14) * 100.0;
            pctDiff = (diff >= 0 ? "+" : "") + formatDouble(diff) + "%";
        } else {
            pctDiff = "N/A";
        }

        std::string statsLine =
            "Trades: " + std::to_string(currentTrades) + "   Avg Size: " + formatBTC(currentAvgSize) + "   14-min Avg: " + formatBTC(avgTradeSize14) + "   Diff: " + pctDiff;

        int statsX = (CHART_WIDTH + LABEL_WIDTH - static_cast<int>(statsLine.length())) / 2;
        statsX = std::max(statsX, 0);

        for (size_t i = 0; i < statsLine.length() && (statsX + i) < canvas[STATS_ROW].size(); ++i) {
            canvas[STATS_ROW][statsX + i] = statsLine[i];
        }

        return canvas;
    }

  private:
    const Parameters &params;
    double increment_double;
    uint64_t tickCount;
    bool hasActiveCandle;
    OHLCV current;
    std::deque<OHLCV> buffer;

    void pushCandle(const OHLCV &candle) {
        buffer.push_back(candle);
        if (buffer.size() > VISIBLE_WIDTH)
            buffer.pop_front();
    }

    std::string formatDouble(double value) const {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2) << value;
        std::string s = ss.str();

        size_t dot_pos = s.find('.');
        if (dot_pos == std::string::npos)
            dot_pos = s.length();

        int pos = static_cast<int>(dot_pos) - 3;
        while (pos > 0) {
            s.insert(static_cast<size_t>(pos), ",");
            pos -= 3;
        }
        return s;
    }

    std::string formatBTC(double btc) const {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(8) << btc;
        return ss.str();
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class SpeedReporter {
  public:
    struct SpeedInfo {
        long double avgStep1 = 0.0L;
        long double avgStep2 = 0.0L;
        long double avgStep3 = 0.0L;
        long double avgStep4 = 0.0L;
        long double avgStep5 = 0.0L;
        long double avgStep6 = 0.0L;
        long double totalAlgo = 0.0L;
        uint64_t iterationCount = 0;
    };

    SpeedReporter(OutputBuffer &buffer, bool enabled = true) : outputBuffer(buffer), enabled(enabled) {}

    void setEnabled(bool value) { enabled = value; }

    // Call this once per iteration from Trader::run() with the fresh averages
    void updateLatest(const SpeedInfo &info) { latestInfo = info; }

    void setSpeed() const {
        if (!enabled)
            return;

        std::string dash = std::string(80, '-');
        bodyCol1.push_back({dash, Align::CENTER});
        bodyCol1.push_back({">> Average Speed", Align::LEFT});
        bodyCol1.push_back({" - Step 1: " + toMs(latestInfo.avgStep1), Align::LEFT});
        bodyCol1.push_back({" - Step 2: " + toMs(latestInfo.avgStep2), Align::LEFT});
        bodyCol1.push_back({" - Step 3: " + toMs(latestInfo.avgStep3), Align::LEFT});
        bodyCol1.push_back({" - Step 4: " + toMs(latestInfo.avgStep4), Align::LEFT});
        bodyCol1.push_back({" - Step 5: " + toMs(latestInfo.avgStep5), Align::LEFT});
        bodyCol1.push_back({" - Total (1-5): " + toMs(latestInfo.totalAlgo), Align::LEFT});
    }

  private:
    OutputBuffer &outputBuffer;
    bool enabled;
    SpeedInfo latestInfo; // holds the most recent values
    Render render;

    static std::string toMs(long double nanoseconds) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(3) << (nanoseconds / 1'000'000.0L) << " ms";
        return oss.str();
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Output {
  public:
    Output(Parameters &params, Render &render) : params(params), render(render) { LOG_INFO("Class: Header"); }

    void printHeader(uint64_t currentPrice, int iterationCount) {
        std::vector<Line> headerCol1, headerCol2, headerCol3;
        std::vector<Line> barCol1, barCol2, barCol3;

        std::string date = functions.getTimeDate();
        std::string dash = std::string(82, '-');

        // Convert iterationCount → string
        std::string iterationStr = std::to_string(iterationCount);

        // Line 1
        headerCol1.push_back({"", Align::CENTER});
        headerCol2.push_back({"", Align::CENTER});
        headerCol3.push_back({"", Align::CENTER});

        // Line 2
        headerCol1.push_back({dash, Align::CENTER});
        headerCol2.push_back({dash, Align::CENTER});
        headerCol3.push_back({dash, Align::CENTER});

        // Line 3
        headerCol1.push_back({"", Align::CENTER});
        headerCol2.push_back({"", Align::CENTER});
        headerCol3.push_back({"", Align::CENTER});

        // Line 4
        headerCol1.push_back({params.currentPair, Align::CENTER});
        headerCol2.push_back({"------- TRADE TERMINAL --------", Align::CENTER});
        headerCol3.push_back({params.currentExchange + " EXCHANGE", Align::CENTER});

        // Line 5
        headerCol1.push_back({"", Align::CENTER});
        headerCol2.push_back({"", Align::CENTER});
        headerCol3.push_back({"", Align::CENTER});

        // Line 6
        headerCol1.push_back({dash, Align::CENTER});
        headerCol2.push_back({dash, Align::CENTER});
        headerCol3.push_back({dash, Align::CENTER});

        // Line 7
        headerCol1.push_back({"Iteration: " + iterationStr, Align::CENTER});
        headerCol2.push_back({"Price: " + functions.formatIntUSD(currentPrice), Align::CENTER});
        headerCol3.push_back({"Date: " + date, Align::CENTER});

        // Line 8
        headerCol1.push_back({dash, Align::CENTER});
        headerCol2.push_back({dash, Align::CENTER});
        headerCol3.push_back({dash, Align::CENTER});

        std::vector<std::vector<Line>> headerColumns = {headerCol1, headerCol2, headerCol3};
        std::cout << render.printHeaderColumns(headerColumns);

        std::vector<Line> menuCol1, menuCol2, menuCol3, menuCol4, menuCol5, menuCol6;

        menuCol1.push_back({"1. Start Trading", Align::CENTER});
        menuCol2.push_back({"2. Stop Trading", Align::CENTER});
        menuCol3.push_back({"3. Enable Output", Align::CENTER});
        menuCol4.push_back({"4. Disable Output", Align::CENTER});
        menuCol5.push_back({"5. Trade Settings", Align::CENTER});
        menuCol6.push_back({"0. Back to Home Menu", Align::CENTER});

        std::vector<std::vector<Line>> menuColumns = {menuCol1, menuCol2, menuCol3, menuCol4, menuCol5, menuCol6};
        std::cout << render.printMenuColumns(menuColumns);

        // Line 9
        barCol1.push_back({dash, Align::CENTER});
        barCol2.push_back({dash, Align::CENTER});
        barCol3.push_back({dash, Align::CENTER});

        std::vector<std::vector<Line>> barColumns = {barCol1, barCol2, barCol3};
        std::cout << render.printHeaderColumns(barColumns);
    }

    void printFooter(TradeType currentState) {
        std::vector<Line> footerCol1, footerCol2, footerCol3;
        std::string dash = std::string(82, '-');
        std::string stateStr = params.tradeTypeToString(currentState);

        // Line 2
        footerCol1.push_back({dash, Align::CENTER});
        footerCol2.push_back({dash, Align::CENTER});
        footerCol3.push_back({dash, Align::CENTER});

        // Line 3
        footerCol1.push_back({"CurrentState " + stateStr, Align::CENTER}); // blank but same height
        footerCol2.push_back({"", Align::CENTER});
        footerCol3.push_back({std::string("Version: ") + APP_VERSION, Align::CENTER});

        // Line 2
        footerCol1.push_back({dash, Align::CENTER});
        footerCol2.push_back({dash, Align::CENTER});
        footerCol3.push_back({dash, Align::CENTER});

        std::vector<std::vector<Line>> footerColumns = {footerCol1, footerCol2, footerCol3};
        std::cout << render.printFooterColumns(footerColumns);
    }

    void titleStatistics() {
        bodyCol1.push_back({"", Align::LEFT});
        bodyCol1.push_back({"--- Order Statistics ---", Align::CENTER});
        bodyCol1.push_back({"", Align::LEFT});
    }

    void titleInformation() {
        bodyCol2.push_back({"", Align::LEFT});
        bodyCol2.push_back({"--- Order Information ---", Align::CENTER});
        bodyCol2.push_back({"", Align::LEFT});
    }

    void titleRebalanced() {
        render.pushLine(dash, Align::LEFT);
        render.pushLine(">> Rebalanced Orders", Align::LEFT);
    }

    void titleLadder() {
        render.pushLine(dash, Align::LEFT);
        render.pushLine(">> Ladder Orders", Align::LEFT);
    }

    void titleAdjusting() {
        render.pushLine(dash, Align::LEFT);
        render.pushLine(">> Adjusting Orders", Align::LEFT);
    }

    void titleBatched() {
        render.pushLine(dash, Align::LEFT);
        render.pushLine(">> Batched Orders", Align::LEFT);
    }

  private:
    Parameters &params;
    Render &render;

    std::string dash = std::string(80, '-');
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Calendar {
  public:
    struct DayInfo {
        bool hasData = false;

        double dailyPNL_USD = 0.0;
        double dailyPNL_BTC = 0.0;

        double cumulativePNL_USD = 0.0;
        double cumulativePNL_BTC = 0.0;

        double tradeVolume_BTC = 0.0;
        int tradeCount = 0;
    };

    struct MonthInfo {
        std::string name;
        int daysInMonth = 31;
        std::vector<DayInfo> days; // index 0 = day 1
    };

    enum class PNLType { USD, BTC };

    Calendar() {
        today = getCurrentDate();
        months = computeMonthlyPNLData(today.year);
    }

    std::vector<MonthInfo> &getMonths() { return months; }

    void setCalendarTrades(double pnlUSD, double pnlBTC, double volumeBTC, int trades) {
        Date currentDate = getCurrentDate();

        // Update today if it changed
        if (currentDate.year != lastTradeDate.year || currentDate.month != lastTradeDate.month || currentDate.day != lastTradeDate.day) {
            today = currentDate;
        }

        lastTradeDate = today;

        setDayTrades(today.month, today.day, pnlUSD, pnlBTC, volumeBTC, trades);
    }

    void setDayTrades(int month, int day, double pnlUSD, double pnlBTC, double volumeBTC, int trades) {
        auto &d = months[month - 1].days[day - 1];

        d.hasData = true; // ✅ mark that this day has data
        d.tradeVolume_BTC += volumeBTC;
        d.tradeCount += trades;

        d.dailyPNL_USD += pnlUSD;
        d.dailyPNL_BTC += pnlBTC;

        updateDay(months, month, day, pnlUSD, pnlBTC); // update cumulative
    }

    std::vector<Line> generate() {
        std::vector<Line> result;

        for (int m = 0; m < 12; ++m) {
            const auto &month = months[m];
            bool isCurrent = (m + 1 == today.month);
            int daysVisible = isCurrent ? today.day : month.daysInMonth;

            std::string monthLabel = (isCurrent ? "--> " : "    ") + month.name;
            monthLabel.resize(LABEL_WIDTH, ' ');

            for (int blockSize : {DAYS_FIRST_BLOCK, DAYS_SECOND_BLOCK}) {
                renderMonthBlock(result, month, monthLabel, blockSize, daysVisible);
            }
        }

        result.push_back({std::string(TOTAL_WIDTH, '-'), Align::LEFT});
        return result;
    }

    void renderMonthBlock(std::vector<Line> &result, const MonthInfo &month, const std::string &monthLabel, int blockSize, int daysVisible) {
        monthDayHeaderBlock(result, monthLabel, blockSize, month.daysInMonth);

        for (PNLType type : {PNLType::BTC, PNLType::USD}) {
            dailyProfitBlock(result, month, type, blockSize, daysVisible, month.daysInMonth);
            cumulativeProfitBlock(result, month, type, blockSize, daysVisible, month.daysInMonth);
        }

        tradeVolumeBlock(result, month, blockSize, daysVisible, month.daysInMonth);
        tradeCountBlock(result, month, blockSize, daysVisible, month.daysInMonth);
    }

    // inside Calendar class:
    void saveToFile(const std::string &filename) {
        std::ofstream file(filename, std::ios::out);

        if (!file.is_open())
            return;

        // Write header
        file << std::left << std::setw(6) << "Year" << std::setw(8) << "Month" << std::setw(6) << "Day" << std::setw(18) << "DailyPNL_USD" << std::setw(18) << "DailyPNL_BTC"
             << std::setw(18) << "PNL_USD" << std::setw(18) << "PNL_BTC" << std::setw(18) << "VolumeBTC" << std::setw(10) << "TradeCount"
             << "\n";

        file << std::string(130, '-') << "\n";

        // Write data
        for (int m = 0; m < 12; ++m) {
            const auto &month = months[m];
            for (int d = 0; d < month.daysInMonth; ++d) {
                const auto &day = month.days[d];
                if (!day.hasData)
                    continue;

                file << std::left << std::setw(6) << today.year << std::setw(8) << (m + 1) << std::setw(6) << (d + 1) << std::setw(18) << std::fixed << std::setprecision(2)
                     << day.dailyPNL_USD << std::setw(18) << std::fixed << std::setprecision(8) << day.dailyPNL_BTC << std::setw(18) << std::fixed << std::setprecision(2)
                     << day.cumulativePNL_USD << std::setw(18) << std::fixed << std::setprecision(8) << day.cumulativePNL_BTC << std::setw(18) << std::fixed << std::setprecision(8)
                     << day.tradeVolume_BTC << std::setw(10) << day.tradeCount << "\n";
            }
        }

        file.flush();
        file.close();
    }

    // Load previously saved data
    void loadFromFile(const std::string &filename) {
        std::ifstream file(filename);
        if (!file.is_open())
            return;

        std::string line;
        std::getline(file, line); // skip header

        while (std::getline(file, line)) {
            if (line.empty())
                continue;

            int year, month, day, tradeCount;
            double dailyUSD, dailyBTC, cumUSD, cumBTC, volumeBTC;

            sscanf(line.c_str(), "%d,%d,%d,%lf,%lf,%lf,%lf,%lf,%d", &year, &month, &day, &dailyUSD, &dailyBTC, &cumUSD, &cumBTC, &volumeBTC, &tradeCount);

            if (month >= 1 && month <= 12 && day >= 1 && day <= months[month - 1].daysInMonth) {
                auto &d = months[month - 1].days[day - 1];
                d.hasData = true;
                d.dailyPNL_USD = dailyUSD;
                d.dailyPNL_BTC = dailyBTC;
                d.cumulativePNL_USD = cumUSD;
                d.cumulativePNL_BTC = cumBTC;
                d.tradeVolume_BTC = volumeBTC;
                d.tradeCount = tradeCount;
            }
        }

        file.close();
    }

  private:
    std::vector<MonthInfo> months;

    constexpr static int LABEL_WIDTH = 20;
    constexpr static int DAY_WIDTH = 13;
    constexpr static int COL_GAP = 1;
    constexpr static int DAYS_FIRST_BLOCK = 15;
    constexpr static int DAYS_SECOND_BLOCK = 16;
    constexpr static int BLOCK_WIDTH = DAY_WIDTH + COL_GAP;
    constexpr static int TOTAL_WIDTH = LABEL_WIDTH + std::max(DAYS_FIRST_BLOCK, DAYS_SECOND_BLOCK) * BLOCK_WIDTH;

    struct Date {
        int year;
        int month; // 1–12
        int day;   // 1–31
    };

    Date today;
    Date lastTradeDate = {0, 0, 0};

    Date getCurrentDate() {
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm tm = *std::localtime(&t);

        return {tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday};
    }

    void updateDay(std::vector<MonthInfo> &months,
                   int month, // 1–12
                   int day,   // 1–31
                   double pnlUSD,
                   double pnlBTC) {
        auto &m = months[month - 1];
        auto &d = m.days[day - 1];

        d.hasData = true;
        d.dailyPNL_USD += pnlUSD;
        d.dailyPNL_BTC += pnlBTC;

        // Recompute cumulative PNLs for the whole month
        double runningUSD = 0.0;
        double runningBTC = 0.0;

        for (auto &dayInfo : m.days) {
            if (dayInfo.hasData) {
                runningUSD += dayInfo.dailyPNL_USD;
                runningBTC += dayInfo.dailyPNL_BTC;

                dayInfo.cumulativePNL_USD = runningUSD;
                dayInfo.cumulativePNL_BTC = runningBTC;
            }
        }
    }

    std::vector<MonthInfo> computeMonthlyPNLData(int year) {
        std::vector<MonthInfo> months(12);

        const char *names[12] = {"January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"};

        int daysPerMonth[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        if (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))
            daysPerMonth[1] = 29;

        for (int m = 0; m < 12; ++m) {
            months[m].name = names[m];
            months[m].daysInMonth = daysPerMonth[m];
            months[m].days.resize(daysPerMonth[m]); // exact size

            // days start EMPTY
            for (int d = 0; d < daysPerMonth[m]; ++d) {
                months[m].days[d] = DayInfo{};
            }
        }

        return months;
    }

    // right-aligned empty cell
    static std::string emptyCell(int width) {
        std::string s = "---";
        return std::string(width - s.size(), ' ') + s;
    }

    // Unified PNL formatter for USD or BTC
    std::string formatPNL(double value, int width, bool isBTC) const {
        std::string s;

        // Choose the right formatting
        if (isBTC) {
            s = formatDoubleBTC(value); // 8 decimal places
        } else {
            s = formatDoubleUSD(value); // 2 decimal places
        }

        // Right-align to fixed width
        if (s.size() > static_cast<size_t>(width)) {
            s.resize(width);
        } else {
            s = std::string(width - s.size(), ' ') + s;
        }

        return s;
    }

    // USD version for double (already in dollars)
    inline std::string formatDoubleUSD(double value) const {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2) << value;
        std::string s = ss.str();

        size_t dot_pos = s.find('.');
        if (dot_pos == std::string::npos)
            dot_pos = s.length();

        int pos = dot_pos - 3;
        while (pos > 0) {
            s.insert(pos, ",");
            pos -= 3;
        }

        return s;
    }

    // BTC version for double (already in BTC)
    inline std::string formatDoubleBTC(double value) const {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(8) << value;
        std::string s = ss.str();

        size_t dot_pos = s.find('.');
        if (dot_pos == std::string::npos)
            dot_pos = s.length();

        int pos = dot_pos - 3;
        while (pos > 0) {
            s.insert(pos, ",");
            pos -= 3;
        }

        return s;
    }

    static std::string centerText(const std::string &text, int width) {
        if ((int)text.size() >= width)
            return text.substr(0, width);

        int totalPadding = width - text.size();
        int leftPadding = totalPadding / 2;
        int rightPadding = totalPadding - leftPadding;

        return std::string(leftPadding, ' ') + text + std::string(rightPadding, ' ');
    }

    void monthDayHeaderBlock(std::vector<Line> &result,
                             const std::string &label,
                             int blockSize, // DAYS_FIRST_BLOCK or DAYS_SECOND_BLOCK
                             int daysInMonth) {

        std::string header(TOTAL_WIDTH, ' ');
        header.replace(0, LABEL_WIDTH, label);

        int startDay = (blockSize == DAYS_FIRST_BLOCK) ? 0 : DAYS_FIRST_BLOCK;

        for (int i = 0; i < blockSize; ++i) {
            int dayIndex = startDay + i;
            int col = LABEL_WIDTH + i * BLOCK_WIDTH;

            if (dayIndex < daysInMonth) {
                std::string dayStr = std::to_string(dayIndex + 1);
                header.replace(col, DAY_WIDTH, centerText(dayStr, DAY_WIDTH));
            }
        }

        result.push_back({header, Align::LEFT});
    }

    void dailyProfitBlock(std::vector<Line> &result, const MonthInfo &month, PNLType type, int blockSize, int daysVisible, int daysInMonth) {

        // Decide which block this is
        int startDay = (blockSize == DAYS_FIRST_BLOCK) ? 0 : DAYS_FIRST_BLOCK;

        std::string label = "      Daily Profit:";
        std::string row(TOTAL_WIDTH, ' ');
        row.replace(0, LABEL_WIDTH, label);

        for (int i = 0; i < blockSize; ++i) {
            int dayIndex = startDay + i;
            int col = LABEL_WIDTH + i * BLOCK_WIDTH;

            if (dayIndex < daysVisible && month.days[dayIndex].hasData) {
                if (type == PNLType::BTC) {
                    row.replace(col, DAY_WIDTH, formatPNL(month.days[dayIndex].dailyPNL_BTC, DAY_WIDTH, true));
                } else {
                    row.replace(col, DAY_WIDTH, formatPNL(month.days[dayIndex].dailyPNL_USD, DAY_WIDTH, false));
                }
            } else if (dayIndex < daysInMonth) {
                row.replace(col, DAY_WIDTH, emptyCell(DAY_WIDTH));
            }
        }

        result.push_back({row, Align::LEFT});
    }

    void cumulativeProfitBlock(std::vector<Line> &result, const MonthInfo &month, PNLType type, int blockSize, int daysVisible, int daysInMonth) {

        std::string row(TOTAL_WIDTH, ' ');

        std::string label = "      Total Profit:";
        label.resize(LABEL_WIDTH, ' ');
        row.replace(0, LABEL_WIDTH, label);

        // Decide where this block starts
        int startDay = (blockSize == DAYS_FIRST_BLOCK) ? 0 : DAYS_FIRST_BLOCK;

        for (int i = 0; i < blockSize; ++i) {
            int dayIndex = startDay + i;
            int col = LABEL_WIDTH + i * BLOCK_WIDTH;

            if (dayIndex < daysVisible && month.days[dayIndex].hasData) {
                if (type == PNLType::BTC) {
                    row.replace(col, DAY_WIDTH, formatPNL(month.days[dayIndex].cumulativePNL_BTC, DAY_WIDTH, true));
                } else {
                    row.replace(col, DAY_WIDTH, formatPNL(month.days[dayIndex].cumulativePNL_USD, DAY_WIDTH, false));
                }
            } else if (dayIndex < daysInMonth) {
                row.replace(col, DAY_WIDTH, emptyCell(DAY_WIDTH));
            }
        }

        result.push_back({row, Align::LEFT});
    }

    void tradeVolumeBlock(std::vector<Line> &result, const MonthInfo &month, int blockSize, int daysVisible, int daysInMonth) {

        int startDay = (blockSize == DAYS_FIRST_BLOCK) ? 0 : DAYS_FIRST_BLOCK;

        std::string row(TOTAL_WIDTH, ' ');
        row.replace(0, LABEL_WIDTH, "      Volume BTC:");

        for (int i = 0; i < blockSize; ++i) {
            int d = startDay + i;
            int col = LABEL_WIDTH + i * BLOCK_WIDTH;

            if (d < daysVisible && month.days[d].hasData) {
                row.replace(col, DAY_WIDTH, formatPNL(month.days[d].tradeVolume_BTC, DAY_WIDTH, true));
            } else if (d < daysInMonth) {
                row.replace(col, DAY_WIDTH, emptyCell(DAY_WIDTH));
            }
        }

        result.push_back({row, Align::LEFT});
    }

    void tradeCountBlock(std::vector<Line> &result, const MonthInfo &month, int blockSize, int daysVisible, int daysInMonth) {

        int startDay = (blockSize == DAYS_FIRST_BLOCK) ? 0 : DAYS_FIRST_BLOCK;

        std::string row(TOTAL_WIDTH, ' ');
        row.replace(0, LABEL_WIDTH, "      Trades:");

        for (int i = 0; i < blockSize; ++i) {
            int d = startDay + i;
            int col = LABEL_WIDTH + i * BLOCK_WIDTH;

            if (d < daysVisible && month.days[d].hasData) {
                char buf[16];
                snprintf(buf, sizeof(buf), "%*d", DAY_WIDTH, month.days[d].tradeCount);
                row.replace(col, DAY_WIDTH, buf);
            } else if (d < daysInMonth) {
                row.replace(col, DAY_WIDTH, emptyCell(DAY_WIDTH));
            }
        }

        result.push_back({row, Align::LEFT});
    }
};

// Global instance
inline Calendar calendar;

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class TradeLogger {
  public:
    TradeLogger() {
        file.open(fileSystem.file_8, std::ios::out | std::ios::app);
        if (file.is_open()) {
            log("[SYSTEM]", "=== Trade logger started ===");
        } else {
            std::cerr << "FATAL: Could not open " << fileSystem.file_8 << "!\n";
        }
    }

    ~TradeLogger() {
        if (file.is_open()) {
            log("[SYSTEM]", "=== Trade logger shutdown ===");
            file.close();
        }
    }

    // Deleted copy/move to prevent accidental misuse
    TradeLogger(const TradeLogger &) = delete;
    TradeLogger &operator=(const TradeLogger &) = delete;
    TradeLogger(TradeLogger &&) = delete;
    TradeLogger &operator=(TradeLogger &&) = delete;

    void log(const std::string &tag, const std::string &message) {
        std::lock_guard<std::mutex> lock(mutex);

        std::ostringstream ss;
        ss << getCurrentTime() << " " << tag << " " << message << "\n";

        const std::string line = ss.str();

        if (file.is_open()) {
            file << line;
            file.flush();
        }
    }

  private:
    std::string getCurrentTime() const {
        auto now = std::chrono::system_clock::now();
        auto tt = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

        std::ostringstream ss;
        ss << std::put_time(std::localtime(&tt), "%Y-%m-%d %H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }

    std::ofstream file;
    mutable std::mutex mutex;
};

// Global instance
inline TradeLogger tradeLogger;

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class FillOrderLogic {
  public:
    FillOrderLogic(Banking &bank, Render &render, bool print = true, bool tweet = true) : bank(bank), render(render), printOutput(print), tweetOutput(tweet), broadcaster(twitter) {
        LOG_INFO("Class: FillOrderLogic");
    }

    // Toggle whether messages should be printed to console/output buffer
    void setPrintOutput(bool value) { printOutput = value; }

    // Toggle whether tweets should be sent or not
    void setTweetOutput(bool value) { tweetOutput = value; }

    // ---- Getters for stats ----
    inline int getBuyCount() const {
        return buyCount; // number of buy orders filled
    }
    inline int getSellCount() const {
        return sellCount; // number of sell orders filled
    }
    inline int getFilledCount(const FilledPositions &filled) const {
        return static_cast<int>(filled.buys.size() + filled.sells.size()); // Total filled orders = number of filled buys + sells
    }
    inline int getBatchedCount() const {
        return batchedOrders.totalBatched; // Total batched orders
    }
    inline uint64_t getRollingVolume() const {
        return volumeUSD; // rolling 30-day volume in cents
    }
    inline uint64_t getTotalFeesPaid() const {
        return totalFeesUSD; // cumulative fees in cents
    }
    inline uint64_t getTotalVolume() const {
        return totalVolumeUSD; // cumulative volume in cents
    }

    // ---- Records a trade for stats & rolling volume ----
    inline void recordTrade(uint64_t usdValue, uint64_t feeUSD = 0) {
        tradeHistory.emplace_back(TradeRecord{usdValue, std::chrono::system_clock::now()});
        volumeUSD += usdValue;      // add to rolling 30-day volume
        totalVolumeUSD += usdValue; // add to total volume
        totalFeesUSD += feeUSD;     // add fees
    }

    // ---- Removes trades older than 30 days from rolling volume ----
    inline void pruneOldTrades() {
        auto now = std::chrono::system_clock::now();
        while (!tradeHistory.empty()) {
            auto age = std::chrono::duration_cast<std::chrono::hours>(now - tradeHistory.front().timestamp).count();
            if (age > 24 * DAYS_WINDOW) {                   // older than 30 days
                volumeUSD -= tradeHistory.front().usdValue; // subtract from rolling volume
                tradeHistory.pop_front();                   // remove old trade
            } else {
                break; // oldest trade is still within 30-day window
            }
        }
    }

    inline double calculateAverageBuyPrice(const Parameters &params) const {
        if (buyBatchTotalAmount == 0)
            return 0.0;

        return static_cast<double>(buyBatchWeightedPriceSum) / static_cast<double>(buyBatchTotalAmount);
    }

    inline double calculateAverageSellPrice(const Parameters &params) const {
        if (sellBatchTotalAmount == 0)
            return 0.0;

        return static_cast<double>(sellBatchWeightedPriceSum) / static_cast<double>(sellBatchTotalAmount);
    }

    struct BatchedOrders {
        int totalBatched = 0;

        void addOrder(int batched) { totalBatched += batched; }
        void removeOrder(int batched) { totalBatched -= batched; }
    };

    struct GlobalAverage {
        uint64_t totalCost = 0;   // sum of price * amount
        uint64_t totalAmount = 0; // sum of amounts

        // Add a new order
        void addOrder(uint64_t price, uint64_t amount) {
            totalCost += price * amount;
            totalAmount += amount;
        }

        // Remove an order (e.g., when closing a position)
        void removeOrder(uint64_t price, uint64_t amount) {
            totalCost -= price * amount;
            totalAmount -= amount;
            if (totalAmount < 0)
                totalAmount = 0;
            if (totalCost < 0)
                totalCost = 0;
        }

        // Compute current average price
        double getAveragePrice() const {
            if (totalAmount == 0)
                return 0;
            return totalCost / totalAmount;
        }
    };

    BatchedOrders batchedOrders;
    GlobalAverage globalAverage;

    // ---- Core function: update filled orders based on current market price ----
    inline void updateFilledOrders(uint64_t currentPrice, OpenPositions &open, FilledPositions &filled, Parameters &params) {

        pruneOldTrades(); // Remove trades older than 30 days from rolling volume

        if (printOutput) {
            render.pushLine(">> Banking", Align::LEFT);
        }

        fillBuys(currentPrice, open, filled, params);
        fillSells(currentPrice, open, filled, params);
    }

    inline void logSale(bool isBuy, int positionCount, const Parameters &order) {
        std::string side = isBuy ? "[BUY]  " : "[SELL] ";

        tradeLogger.log(side, params.ladderOrderPurposeToString(order.purpose) + " Position: " + std::to_string(positionCount));
        tradeLogger.log(side, "  UUID:  " + order.uuid);
        tradeLogger.log(side, "    Trade:       " + params.tradeTypeToString(order.type));
        tradeLogger.log(side, "    Price:       " + std::to_string(order.price));
        tradeLogger.log(side, "    Avg Price:   " + std::to_string(order.averagePrice));
        tradeLogger.log(side, "    amount:      " + std::to_string(order.amount));
        tradeLogger.log(side, "    Value:       " + std::to_string(order.usdValue));
        tradeLogger.log(side, "    Pair:        " + params.tradingPairToString(order.pairSymbol));
        tradeLogger.log(side, "    Order:       " + params.orderTypeToString(order.orderType));
        tradeLogger.log(side, "    leverage:    " + params.leverageToString(order.leverage));
        tradeLogger.log(side, "    Num Orders:  " + std::to_string(order.numOrders));
        tradeLogger.log(side, "    Open Time:   " + std::to_string(order.openTime) + " ms");
        tradeLogger.log(side, "    Filled:      " + std::string(order.filled ? "Yes" : "No"));
        tradeLogger.log(side, "    Filled Time: " + (order.filled ? std::to_string(order.filledTime) + " ms" : "N/A"));
        tradeLogger.log(side, "    Fee:         " + std::to_string(order.fee));
        tradeLogger.log(side, "    Deposit:     " + std::to_string(order.deposit));
        tradeLogger.log(side, "    Withdraw:    " + std::to_string(order.withdraw));
        if (!order.filledUuids.empty()) {
            std::ostringstream uuids;
            for (size_t i = 0; i < order.filledUuids.size(); ++i) {
                uuids << order.filledUuids[i];
                if (i + 1 < order.filledUuids.size())
                    uuids << ", ";
            }
            tradeLogger.log(side, "    Filled UUID's: " + uuids.str());
        } else {
            tradeLogger.log(side, "    Filled UUID's: None");
        }
        tradeLogger.log(side, "-------------------------------------------------------------------------------------");
    }

  private:
    Banking &bank;
    bool printOutput;
    bool tweetOutput;

    Parameters params;

    TwitterClient twitter;
    TradeBroadcaster broadcaster;
    Render &render;

    int buyCount = 0;
    int sellCount = 0;

    uint64_t volumeUSD = 0;      // rolling 30-day volume in cents
    uint64_t totalVolumeUSD = 0; // cumulative volume in cents
    uint64_t totalFeesUSD = 0;   // in cents

    int buyIndex = 0;
    int sellIndex = 0;

    uint64_t buyBatchTotalAmount = 0;
    uint64_t buyBatchWeightedPriceSum = 0;
    int buyBatchOrdersCount = 0;

    uint64_t sellBatchTotalAmount = 0;
    uint64_t sellBatchWeightedPriceSum = 0;
    int sellBatchOrdersCount = 0;

    int batchedCount = 0;

    struct TradeRecord {
        uint64_t usdValue; // in cents
        std::chrono::system_clock::time_point timestamp;
    };

    std::deque<TradeRecord> tradeHistory;
    static constexpr int DAYS_WINDOW = 30;

    inline void fillBuys(uint64_t currentPrice, OpenPositions &open, FilledPositions &filled, Parameters &params) {
        // --- BUY ORDERS ---
        auto it = open.buys.begin();
        while (it != open.buys.end()) {
            // Skip non-normal orders
            if (it->purpose == LadderOrderPurpose::CLOSE || it->purpose == LadderOrderPurpose::REBALANCE || it->purpose == LadderOrderPurpose::BATCH) {
                ++it;
                continue;
            }

            // Check if fill condition met
            if (!it->filled && currentPrice <= it->price) {
                // Mark as filled (original)
                it->filled = true;
                it->filledTime = systemClock.getMilliseconds();

                // --- 1. Create filled copy ---
                Parameters filledOrder = *it; // copy the whole struct

                // --- 2. Update filled-specific fields ---
                filledOrder.filled = true;
                filledOrder.filledTime = it->filledTime;
                // filledOrder.purpose = LadderOrderPurpose::FILLED;

                // Compute cost & fee
                uint64_t price = it->price;
                uint64_t btcAmount = it->amount;
                uint64_t usdCost = price * btcAmount / SATOSHIS;
                uint64_t feeUSD = (usdCost * params.makerFeeRate) / 10000ULL;
                uint64_t tradeCost = usdCost + feeUSD;

                filledOrder.fee = feeUSD;         // store fee in USD cents
                filledOrder.deposit = btcAmount;  // BTC received
                filledOrder.withdraw = tradeCost; // USD spent

                // --- 3. Add to filled positions ---
                filled.buys.emplace_back(filledOrder);

                double pnlUSD = 0.00;
                double pnlBTC = 0.00000000;
                double volumeBTC = static_cast<double>(btcAmount) / SATOSHIS;
                int trades = 1;

                calendar.setCalendarTrades(pnlUSD, pnlBTC, volumeBTC, trades);

                // --- 4. Update averages, volume, etc. ---
                addBuyOrder(filled, params, currentPrice, btcAmount, price);

                bank.withdraw("USD", tradeCost); // withdraw USD to pay for the buy
                bank.deposit("BTC", btcAmount);  // deposit BTC into wallet

                recordTrade(tradeCost, feeUSD);

                // --- 5. Log from the FILLED copy (not the open one) ---
                logSale(true, buyCount, filledOrder); // true = buy

                // Optional: tweet, render, etc.
                if (printOutput) {
                    render.pushLine(" - Filled Buy Order: Withdrawing USD: " + functions.formatIntUSD(usdCost + feeUSD), Align::LEFT);
                    render.pushLine(" - Filled Buy Order: Depositing BTC: " + functions.formatIntBTC(btcAmount), Align::LEFT);
                }

                if (tweetOutput) {
                    // FILLED (with tile)
                    TradeBroadcaster::PositionFilledInfo filledOrder;
                    filledOrder.pair = "BTC/USD";
                    filledOrder.entry = price;
                    filledOrder.amount = btcAmount;
                    filledOrder.direction = TradeBroadcaster::Direction::Long;

                    broadcaster.postFilled(filledOrder);
                }

                buyCount++; // increment filled buy count

                // --- 6. Remove from open (safe swap-and-pop) ---
                std::swap(*it, open.buys.back());
                open.buys.pop_back();
            } else {
                ++it;
            }
        }

        // Update fee tier...
        params.updateFeesByVolume(params, volumeUSD, true);
    }

    inline void fillSells(uint64_t currentPrice, OpenPositions &open, FilledPositions &filled, Parameters &params) {
        // --- SELL ORDERS ---
        auto it = open.sells.begin();
        while (it != open.sells.end()) {
            // Skip close/rebalance orders
            if (it->purpose == LadderOrderPurpose::CLOSE || it->purpose == LadderOrderPurpose::REBALANCE || it->purpose == LadderOrderPurpose::BATCH) {
                ++it;
                continue;
            }

            // Check if this sell order can be filled (market price >= limit price)
            if (!it->filled && currentPrice >= it->price) {
                // Mark as filled (original)
                it->filled = true;
                it->filledTime = systemClock.getMilliseconds();

                // --- 1. Create filled copy ---
                Parameters filledOrder = *it; // copy the whole struct

                // --- 2. Update filled-specific fields ---
                filledOrder.filled = true;
                filledOrder.filledTime = it->filledTime;

                // Compute cost & fee
                uint64_t price = it->price;
                uint64_t btcAmount = it->amount;
                uint64_t usdCost = price * btcAmount / SATOSHIS;
                uint64_t feeUSD = (usdCost * params.makerFeeRate) / 10000ULL;
                uint64_t tradeCost = usdCost + feeUSD;

                filledOrder.fee = feeUSD;         // store fee in USD cents
                filledOrder.deposit = btcAmount;  // BTC received
                filledOrder.withdraw = tradeCost; // USD spent

                // --- 3. Add to filled positions ---
                filled.sells.emplace_back(filledOrder);

                double pnlUSD = 0.00;
                double pnlBTC = 0.00000000;
                double volumeBTC = static_cast<double>(btcAmount) / SATOSHIS;
                int trades = 1;

                calendar.setCalendarTrades(pnlUSD, pnlBTC, volumeBTC, trades);

                // --- 4. Update averages, volume, etc. ---
                addSellOrder(filled, params, currentPrice, btcAmount, price);

                bank.withdraw("BTC", btcAmount); // remove BTC
                bank.deposit("USD", tradeCost);  // add USD after fees

                recordTrade(tradeCost, feeUSD);

                // --- 5. Log from the FILLED copy (not the open one) ---
                logSale(false, sellCount, filledOrder); // true = buy

                // Optional: tweet, render, etc.
                if (printOutput) {
                    render.pushLine(" - Filled Sell Order: Withdrawing BTC: " + functions.formatIntBTC(btcAmount), Align::LEFT);
                    render.pushLine(" - Filled Sell Order: Depositing USD: " + functions.formatIntUSD(tradeCost), Align::LEFT);
                }

                if (tweetOutput) {
                    // FILLED (with tile)
                    TradeBroadcaster::PositionFilledInfo filledOrder;
                    filledOrder.pair = "BTC/USD";
                    filledOrder.entry = price;
                    filledOrder.amount = btcAmount;
                    filledOrder.direction = TradeBroadcaster::Direction::Long;

                    broadcaster.postFilled(filledOrder);
                }

                sellCount++; // increment filled sell count

                // --- 6. Remove from open (safe swap-and-pop) ---
                std::swap(*it, open.sells.back());
                open.sells.pop_back();
            } else {
                ++it;
            }
        }

        // Update fee tier based on rolling 30-day volume
        params.updateFeesByVolume(params, volumeUSD, true);
    }

    inline void addBuyOrder(FilledPositions &filled, Parameters &params, uint64_t currentPrice, uint64_t amount, uint64_t price) {
        // Accumulate batch totals
        buyBatchTotalAmount += amount;
        buyBatchWeightedPriceSum += amount * price;
        buyBatchOrdersCount++;

        // Accumulates price and amount for global average (used to Rebalance orders)
        globalAverage.addOrder(price, amount);

        // Check if we reached batch size
        uint64_t batchStep = params.increment * params.BATCH_SIZE; // $1,000 batch increment
        uint64_t batchFloor = ((currentPrice - 1) / batchStep) * batchStep;

        // Set precondition before aggregating orders into 1 order
        bool batchByCount = (buyBatchOrdersCount >= params.BATCH_SIZE);
        bool batchByPrice = (price <= batchFloor);

        if (batchByCount || batchByPrice) {
            Parameters aggregatedOrder;
            aggregatedOrder.totalAmount = buyBatchTotalAmount;
            aggregatedOrder.weightedPriceSum = buyBatchWeightedPriceSum;
            aggregatedOrder.averagePrice = buyBatchWeightedPriceSum / buyBatchTotalAmount; // average price
            aggregatedOrder.ordersInBatch = buyBatchOrdersCount;
            aggregatedOrder.buyIndex = buyIndex;

            // Create index so as to be erased later
            buyIndex++;

            // Add number of batched orders to total
            batchedOrders.addOrder(buyBatchOrdersCount);

            // Push the vector into batchedBuys
            filled.batchedBuys.push_back(std::move(aggregatedOrder));

            // Clear previous vector values
            filled.buys.clear();

            // Reset accumulators
            resetBuys();
        }
    }

    inline void addSellOrder(FilledPositions &filled, Parameters &params, uint64_t currentPrice, uint64_t amount, uint64_t price) {
        // Accumulate batch totals
        sellBatchTotalAmount += amount;
        sellBatchWeightedPriceSum += amount * price;
        sellBatchOrdersCount++;

        // Accumulates price and amount for global average (used for Rebalance orders)
        globalAverage.addOrder(price, amount);

        // Check if we reached batch size
        uint64_t batchStep = params.increment * params.BATCH_SIZE;                        // e.g., $1,000 batch
        uint64_t batchCeiling = ((currentPrice + batchStep - 1) / batchStep) * batchStep; // ceiling aligned

        // Set precondition before aggregating orders into 1 order
        bool batchByCount = (sellBatchOrdersCount >= params.BATCH_SIZE);
        bool batchByPrice = (price >= batchCeiling); // if order is above ceiling, start new batch

        if (batchByCount || batchByPrice) {
            Parameters aggregatedOrder;
            aggregatedOrder.totalAmount = sellBatchTotalAmount;
            aggregatedOrder.weightedPriceSum = sellBatchWeightedPriceSum;
            aggregatedOrder.averagePrice = sellBatchWeightedPriceSum / sellBatchTotalAmount; // average price
            aggregatedOrder.ordersInBatch = sellBatchOrdersCount;
            aggregatedOrder.sellIndex = sellIndex;

            // Create index so as to be erased later
            sellIndex++;

            // Add number of batched orders to total
            batchedOrders.addOrder(sellBatchOrdersCount);

            // Push the vector into batchedSells
            filled.batchedSells.push_back(std::move(aggregatedOrder));

            // Clear previous vector values
            filled.sells.clear();

            // Reset accumulators
            resetSells();
        }
    }

    void resetBuys() {
        buyBatchTotalAmount = 0;
        buyBatchWeightedPriceSum = 0;
        buyBatchOrdersCount = 0;
    }

    void resetSells() {
        sellBatchTotalAmount = 0;
        sellBatchWeightedPriceSum = 0;
        sellBatchOrdersCount = 0;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class TradeLogic {
  public:
    // Constructor: initializes the TradeLogic with references to key components
    TradeLogic(Banking &bank,
               Parameters &params,
               FillOrderLogic &fillOrderLogic,
               Render &render,
               bool print = true,
               bool tweet = true)
        : bank(bank) // reference to the bank, used for depositing/withdrawing funds
          ,
          params(params) // Reference to trading parameters (fees, leverage, increments, etc.)
          ,
          fillOrderLogic(fillOrderLogic) // Reference to FillOrderLogic (tracks filled orders and volume)
          ,
          render(render), printOutput(print) // Enable/disable printing to console
          ,
          tweetOutput(tweet), broadcaster(twitter) {
        LOG_INFO("Class: TradeLogic");
    }

    // Enable or disable console output
    void setPrintOutput(bool value) { printOutput = value; }

    // Toggle whether tweets should be sent or not
    void setTweetOutput(bool value) { tweetOutput = value; }

    // Returns total number of closed orders (both buys and sells)
    inline int getClosedBuyCount(const ClosedPositions &closed) const { return static_cast<int>(closed.buys.size()); }
    inline int getClosedSellCount(const ClosedPositions &closed) const { return static_cast<int>(closed.sells.size()); }

    // Realized profit in USD (cents)
    inline int64_t getProfitUSD() const {
        return profitUSD; // e.g., 500 cents = $5 profit
    }

    // Realized profit in BTC (satoshis)
    inline int64_t getProfitBTC() const {
        return profitBTC; // e.g., 100000 satoshis = 0.001 BTC profit
    }

    // Returns total realized profit in USD including profit from BTC converted at current price
    inline int64_t getTotalRealizedProfitUSD(uint64_t currentPrice) const {
        if (currentPrice == 0)
            return profitUSD; // avoid division by zero

        // Example: profitBTC = 100000 sats, currentPrice = 30000 USD/BTC
        // btcAsUsd = 100000 * 30000 / 100000000 = 30 cents
        int64_t btcAsUsd = (profitBTC * static_cast<int64_t>(currentPrice)) / static_cast<int64_t>(SATOSHIS);
        return profitUSD + btcAsUsd;
    }

    // Returns total realized profit in BTC including profit from USD converted at current price
    inline int64_t getTotalRealizedProfitBTC(uint64_t currentPrice) const {
        if (currentPrice == 0)
            return profitBTC; // avoid division by zero

        // Example: profitUSD = 500 cents, currentPrice = 30000 USD/BTC
        // usdAsBtc = 500 * 100000000 / 30000 ≈ 1666 satoshis
        int64_t usdAsBtc = (profitUSD * static_cast<int64_t>(SATOSHIS)) / static_cast<int64_t>(currentPrice);
        return profitBTC + usdAsBtc;
    }

    // Average profit per closed order in USD
    inline double getProfitPerOrderUSD(uint64_t currentPrice) const {
        int totalOrders = getTotalClosedOrders();
        if (totalOrders == 0)
            return 0.0; // avoid division by zero

        int64_t totalProfitUSD = getTotalRealizedProfitUSD(currentPrice);
        return static_cast<double>(totalProfitUSD) / static_cast<double>(totalOrders);
        // Example: totalProfitUSD = 500 cents, totalOrders = 2 -> returns 250 cents per order
    }

    // --- Closed orders stats ---
    inline int getClosedLong() const {
        return closedLong; // number of long trades closed
    }
    inline int getClosedShort() const {
        return closedShort; // number of short trades closed
    }
    inline int getStopLossLong() const {
        return stoplossLong; // number of long trades closed via stop-loss
    }
    inline int getStopLossShort() const {
        return stoplossShort; // number of short trades closed via stop-loss
    }

    // Total closed orders (long + short)
    inline int getTotalClosedOrders() const { return closedLong + closedShort; }

    // Calculates the liquidation price for a leveraged position
    inline double calculateLiquidationPrice(uint64_t entryPrice, uint64_t leverage, bool isLong) {
        if (leverage <= 1)
            return 0; // no leverage -> no liquidation

        if (isLong)
            // e.g., entry = 10000, leverage = 2x -> $5000
            return entryPrice * (1 - (1 / leverage));
        else
            // e.g., entry = 10000, leverage = 2x -> $15000
            return entryPrice * (1 + (1 / leverage));
    }

    inline double calculateUnrealizedProfitBTC(uint64_t price) {
        double averagePrice = static_cast<double>(fillOrderLogic.globalAverage.getAveragePrice()) / CENTS;
        double totalAmount = static_cast<double>(fillOrderLogic.globalAverage.totalAmount) / SATOSHIS;
        double currentPrice = static_cast<double>(price) / CENTS;

        // If we have no BTC or no average, unrealized profit = 0
        if (totalAmount <= 0 || averagePrice <= 0)
            return 0;
        double unrealisedBTC = totalAmount * (currentPrice - averagePrice);

        return unrealisedBTC;
    }

    // Main function that executes trading logic for a given price update
    inline void placeOrderLogic(double currentPrice, OpenPositions &open, FilledPositions &filled, ClosedPositions &closed) {
        if (filled.buys.empty() && filled.sells.empty())
            return; // nothing to do if no filled orders
        if (params.orderType != Parameters::OrderType::LIMIT)
            return; // only process limit/ladder orders

        fillOrderLogic.pruneOldTrades(); // remove trades older than 30 days from rolling volume

        rebalanceBuyOrders(currentPrice, open, closed, bank);  // adjust/rebalance open buy ladder orders
        rebalanceSellOrders(currentPrice, open, closed, bank); // adjust/rebalance open sell ladder orders

        boughtBatchOrders(currentPrice, open, filled, closed, bank);

        stopLossBuy(currentPrice, filled, closed);  // check stop-loss or liquidation triggers
        stopLossSell(currentPrice, filled, closed); // check stop-loss or liquidation triggers

        buyLowSellHighOrders(currentPrice, open, filled, closed, bank); // close buy orders if profit target hit
        sellHighBuyLowOrders(currentPrice, open, filled, closed, bank); // close sell orders if profit target hit
    }

  private:
    Banking &bank;
    Parameters &params;
    FillOrderLogic &fillOrderLogic;
    bool printOutput;
    bool tweetOutput;

    ReinforcementLearning rl;
    TwitterClient twitter;
    TradeBroadcaster broadcaster;
    Render &render;

    // realized profit tracked here (USD + BTC)
    int64_t profitUSD = 0; // cents
    int64_t profitBTC = 0; // satoshis

    // stats counters
    int closedLong = 0;
    int closedShort = 0;
    int stoplossLong = 0;
    int stoplossShort = 0;

    void removeFilledOrders(FilledPositions &filled, TradeType tradeType, int numOrders) {
        if (tradeType == TradeType::BUY) {
            if (numOrders > static_cast<int>(filled.buys.size()))
                numOrders = static_cast<int>(filled.buys.size());

            filled.buys.erase(filled.buys.begin(), filled.buys.begin() + numOrders);
        } else if (tradeType == TradeType::SELL) {
            if (numOrders > static_cast<int>(filled.sells.size()))
                numOrders = static_cast<int>(filled.sells.size());

            filled.sells.erase(filled.sells.begin(), filled.sells.begin() + numOrders);
        }
    }

    void removeAllFilledOrders(FilledPositions &filled, TradeType tradeType) {
        if (tradeType == TradeType::BUY) {
            // Simply clear all filled buy orders
            filled.buys.clear();
        } else if (tradeType == TradeType::SELL) {
            // Simply clear all filled sell orders
            filled.sells.clear();
        }
    }

    void removeFilledBatchedOrders(FilledPositions &filled, TradeType tradeType, int batchIndex) {
        if (tradeType == TradeType::BUY) {
            auto &vec = filled.batchedBuys;
            for (auto it = vec.begin(); it != vec.end();) { // no ++it here
                if (it->buyIndex == batchIndex) {
                    *it = std::move(vec.back()); // swap-and-pop (move is slightly nicer)
                    vec.pop_back();
                    // do NOT increment – the new element that was swapped in is now at 'it'
                    // so we check it next iteration in case it also matches
                } else {
                    ++it; // only move forward when we keep the element
                }
            }
        } else if (tradeType == TradeType::SELL) {
            auto &vec = filled.batchedSells;
            for (auto it = vec.begin(); it != vec.end();) {
                if (it->sellIndex == batchIndex) {
                    *it = std::move(vec.back());
                    vec.pop_back();
                    // stay at the same position – check the newly swapped element
                } else {
                    ++it;
                }
            }
        }
    }

    void boughtBatchOrders(uint64_t currentPrice, OpenPositions &open, FilledPositions &filled, ClosedPositions &closed, Banking &bank) {

        // Iterate over all open Sell orders to check Sell condition
        for (auto it = open.sells.begin(); it != open.sells.end();) {
            // if the current market price is equal to or more than the exit price
            if (it->purpose == LadderOrderPurpose::BATCH && currentPrice >= it->price) {
                // Extract basic order info for readability
                int numOrders = it->numOrders;          // number of ladder orders being closed
                uint64_t entryPrice = it->averagePrice; // price at which the position was opened
                uint64_t exitPrice = it->price;         // target price for closing
                uint64_t amountBTC = it->amount;        // amount of BTC in satoshis
                int buyIndex = it->buyIndex;

                // Convert the exit price * BTC amount into USD cents
                uint64_t amountUSD = (exitPrice * amountBTC) / SATOSHIS;

                // Calculate trading fee in USD cents (maker fee)
                uint64_t feeUSD = (amountUSD * params.makerFeeRate) / 10000ULL;

                // Profit in USD cents
                int64_t grossProfitUSD = static_cast<int64_t>(exitPrice - entryPrice) * static_cast<int64_t>(amountBTC) / SATOSHIS;
                int64_t netProfitUSD = grossProfitUSD - static_cast<int64_t>(feeUSD);
                uint64_t netProfitBTC = (exitPrice > 0) ? (netProfitUSD * SATOSHIS / exitPrice) : 0;

                // Banking operations
                bank.withdraw("BTC", amountBTC);
                bank.deposit("USD", amountUSD);

                // Optional logging to output buffer
                if (printOutput) {
                    render.pushLine(" - Closed Batched Buy Order: Withdrawing USD: " + functions.formatIntBTC(amountUSD + feeUSD), Align::LEFT);
                    render.pushLine(" - Closed Batched Buy Order: Depositing BTC: " + functions.formatIntUSD(netProfitBTC), Align::LEFT);
                }

                if (tweetOutput) {
                    // CLOSED (NO TILE)
                    TradeBroadcaster::PositionCloseInfo closedOrders;
                    closedOrders.pair = "BTC/USD";
                    closedOrders.positionsClosed = numOrders;
                    closedOrders.avgEntry = entryPrice;
                    closedOrders.exit = exitPrice;
                    // closed.pnlPercent = 1.76;

                    broadcaster.postClosed(closedOrders);
                }

                // Remove the closed orders from the filled buy positions
                removeFilledBatchedOrders(filled, TradeType::BUY, buyIndex);

                // Record the trade in FillOrderLogic for tracking rolling volume & fees
                fillOrderLogic.recordTrade(amountUSD, feeUSD);

                // Record trade for average price and total orders tracking
                fillOrderLogic.globalAverage.removeOrder(exitPrice, amountUSD);

                fillOrderLogic.batchedOrders.removeOrder(numOrders);

                // Update overall profit counters
                profitUSD += netProfitUSD; // track USD profit
                profitBTC += netProfitBTC; // track BTC prifit
                closedShort += numOrders;  // track how many short orders were closed (selling the top)

                // Move the open order to the closed.sells list
                closed.sells.emplace_back(*it);
                closed.sells.back().closed = true;
                closed.sells.back().closedTime = systemClock.getMilliseconds();

                // Remove the order via swap-and-pop to avoid iterator invalidation
                if (it != open.sells.end()) {
                    std::swap(*it, open.sells.back());
                    open.sells.pop_back();
                }
            } else {
                ++it; // move to the next order if this one is not ready to close
            }
        }

        // Update fee tier
        uint64_t volumeUSD = fillOrderLogic.getRollingVolume();
        params.updateFeesByVolume(params, volumeUSD, true);
    }

    // Only process orders that are intended to CLOSE (profit-taking orders)
    void buyLowSellHighOrders(uint64_t currentPrice, OpenPositions &open, FilledPositions &filled, ClosedPositions &closed, Banking &bank) {

        // Iterate over all open Sell orders to check Sell condition
        for (auto it = open.sells.begin(); it != open.sells.end();) {
            // if the current market price is equal to or more than the exit price
            if (it->purpose == LadderOrderPurpose::CLOSE && currentPrice >= it->price) {

                // Extract basic order info for readability
                int numOrders = it->numOrders;          // number of ladder orders being closed
                uint64_t entryPrice = it->averagePrice; // price at which the position was opened
                uint64_t exitPrice = it->price;         // target price for closing
                uint64_t amountBTC = it->amount;        // amount of BTC in satoshis

                // Convert the exit price * BTC amount into USD cents
                uint64_t amountUSD = (exitPrice * amountBTC) / SATOSHIS;

                // Calculate trading fee in USD cents (maker fee)
                uint64_t feeUSD = (amountUSD * params.makerFeeRate) / 10000ULL;

                // Profit in USD cents
                int64_t grossProfitUSD = static_cast<int64_t>(exitPrice - entryPrice) * static_cast<int64_t>(amountBTC) / SATOSHIS;
                int64_t netProfitUSD = grossProfitUSD - static_cast<int64_t>(feeUSD);
                uint64_t netProfitBTC = (exitPrice > 0) ? (netProfitUSD * SATOSHIS / exitPrice) : 0;

                // Banking operations: withdraw USD from our account, deposit BTC profit
                bank.withdraw("USD", amountUSD + feeUSD);
                bank.deposit("BTC", netProfitBTC);

                double pnlUSD = static_cast<double>(netProfitUSD);
                double pnlBTC = static_cast<double>(netProfitBTC);
                double volumeBTC = static_cast<double>(amountBTC) / SATOSHIS;
                int trades = 1;

                calendar.setCalendarTrades(pnlUSD, pnlBTC, volumeBTC, trades);

                // Optional logging to output buffer
                if (printOutput) {
                    render.pushLine(" - Closed Buy Order: Withdrawing USD: " + functions.formatIntBTC(amountUSD + feeUSD), Align::LEFT);
                    render.pushLine(" - Closed Buy Order: Depositing BTC: " + functions.formatIntUSD(netProfitBTC), Align::LEFT);
                }

                if (tweetOutput) {
                    // CLOSED (NO TILE)
                    TradeBroadcaster::PositionCloseInfo closedOrders;
                    closedOrders.pair = "BTC/USD";
                    closedOrders.positionsClosed = numOrders;
                    closedOrders.avgEntry = entryPrice;
                    closedOrders.exit = exitPrice;
                    // closed.pnlPercent = 1.76;

                    broadcaster.postClosed(closedOrders);
                }

                // Remove the closed orders from the filled buy positions
                // removeFilledOrders(filled, TradeType::BUY, numOrders);
                removeAllFilledOrders(filled, TradeType::BUY);

                // Record the trade in FillOrderLogic for tracking rolling volume & fees
                fillOrderLogic.recordTrade(amountUSD, feeUSD);

                // Record trade for average price and total orders tracking
                fillOrderLogic.globalAverage.removeOrder(exitPrice, amountUSD);

                // Update overall profit counters
                profitUSD += netProfitUSD; // track USD profit
                profitBTC += netProfitBTC; // track BTC prifit
                closedShort += numOrders;  // track how many short orders were closed (selling the top)

                // Move the open order to the closed.sells list
                closed.sells.emplace_back(*it);
                closed.sells.back().closed = true;
                closed.sells.back().closedTime = systemClock.getMilliseconds();

                // Remove the order from open via swap-and-pop to avoid iterator invalidation
                if (it != open.sells.end()) {
                    std::swap(*it, open.sells.back());
                    open.sells.pop_back();
                }
            } else {
                ++it; // move to the next open sell order if this one is not ready to close
            }
        }

        // Update fee tier based on rolling 30-day USD volume
        uint64_t volumeUSD = fillOrderLogic.getRollingVolume();
        params.updateFeesByVolume(params, volumeUSD, true);
    }

    // Only process orders that are intended to CLOSE (profit-taking orders)
    void sellHighBuyLowOrders(uint64_t currentPrice, OpenPositions &open, FilledPositions &filled, ClosedPositions &closed, Banking &bank) {

        // Iterate over all open Sell orders to check Buy condition
        for (auto it = open.buys.begin(); it != open.buys.end();) {
            // if the current market price is equal to or less than the exit price
            if (it->purpose == LadderOrderPurpose::CLOSE && currentPrice <= it->price) {

                // Extract basic order info for readability
                int numOrders = it->numOrders;          // number of ladder orders being closed
                uint64_t entryPrice = it->averagePrice; // price at which the position was opened
                uint64_t exitPrice = it->price;         // target price for closing
                uint64_t amountBTC = it->amount;        // amount of BTC in satoshis

                // USD value in cents: (price in cents * satoshis) / SATS_PER_BTC
                uint64_t amountUSD = (exitPrice * amountBTC) / SATOSHIS;

                // Fee in USD cents (basis points)
                uint64_t feeUSD = amountUSD * params.makerFeeRate / 10000ULL;

                // Profit in USD cents (signed)
                int64_t grossProfitUSD = static_cast<int64_t>(entryPrice - exitPrice) * static_cast<int64_t>(amountBTC) / SATOSHIS;
                int64_t netProfitUSD = grossProfitUSD - static_cast<int64_t>(feeUSD);
                int64_t netProfitBTC = (exitPrice > 0) ? (netProfitUSD * SATOSHIS / exitPrice) : 0;

                // Banking operations: withdraw BTC from our account (we sold it), deposit USD profit
                bank.withdraw("BTC", amountBTC);
                bank.deposit("USD", netProfitUSD - feeUSD);

                // Use the public setter
                double pnlUSD = static_cast<double>(netProfitUSD);
                double pnlBTC = static_cast<double>(netProfitBTC);
                double volumeBTC = static_cast<double>(amountBTC) / SATOSHIS;
                int trades = 1;

                calendar.setCalendarTrades(pnlUSD, pnlBTC, volumeBTC, trades);

                if (printOutput) {
                    render.pushLine(" - Closed Sell Order: Withdrawing BTC: " + functions.formatIntBTC(amountBTC), Align::LEFT);
                    render.pushLine(" - Closed Sell Order: Depositing USD: " + functions.formatIntUSD(netProfitUSD - feeUSD), Align::LEFT);
                }

                if (tweetOutput) {
                    // CLOSED (NO TILE)
                    TradeBroadcaster::PositionCloseInfo closedOrders;
                    closedOrders.pair = "BTC/USD";
                    closedOrders.positionsClosed = numOrders;
                    closedOrders.avgEntry = entryPrice;
                    closedOrders.exit = exitPrice;
                    // closed.pnlPercent = 1.76;

                    broadcaster.postClosed(closedOrders);
                }

                // Remove filled sell orders
                // removeFilledOrders(filled, TradeType::SELL, numOrders);
                removeAllFilledOrders(filled, TradeType::BUY);

                // Record trade volume and fees
                fillOrderLogic.recordTrade(amountUSD, feeUSD);

                // Record trade for average price and total orders tracking
                fillOrderLogic.globalAverage.removeOrder(exitPrice, amountUSD);

                // Update overall profit counters
                profitUSD += netProfitUSD; // track USD profit
                profitBTC += netProfitBTC; // track BTC prifit
                closedLong += numOrders;   // track how many long orders were closed (buying the bottom)

                // Move open order to closed positions
                closed.buys.emplace_back(*it);
                closed.buys.back().closed = true;
                closed.buys.back().closedTime = systemClock.getMilliseconds();

                // Remove from open via swap-and-pop
                if (it != open.buys.end()) {
                    std::swap(*it, open.buys.back());
                    open.buys.pop_back();
                }
            } else {
                ++it; // move to next open order
            }
        }

        // Update fees based on rolling volume
        uint64_t volumeUSD = fillOrderLogic.getRollingVolume();
        params.updateFeesByVolume(params, volumeUSD, true);
    }

    void rebalanceBuyOrders(uint64_t currentPrice, OpenPositions &open, ClosedPositions &closed, Banking &bank) {
        // BUY BITCOIN
        for (auto it = open.buys.begin(); it != open.buys.end();) {
            if (it->purpose == LadderOrderPurpose::REBALANCE && it->orderType == OrderType::MARKET) {
                uint64_t price = it->price;
                uint64_t amountBTC = it->amount;
                uint64_t amountUSD = (price * amountBTC) / SATOSHIS;
                uint64_t feeUSD = amountUSD * params.takerFeeRate / 10000ULL;

                bank.withdraw("USD", amountUSD + feeUSD);
                bank.deposit("BTC", amountBTC);

                double pnlUSD = static_cast<double>(0);
                double pnlBTC = static_cast<double>(0);
                double volumeBTC = static_cast<double>(amountBTC) / SATOSHIS;
                int trades = 1;

                calendar.setCalendarTrades(pnlUSD, pnlBTC, volumeBTC, trades);

                if (printOutput) {
                    render.pushLine(" - Rebalanced Buy Order: Withdrawing USD: " + functions.formatIntUSD(amountUSD + feeUSD), Align::LEFT);
                    render.pushLine(" - Rebalanced Buy Order: Depositing BTC: " + functions.formatIntBTC(amountBTC), Align::LEFT);
                }

                // Record trade volume and fees
                fillOrderLogic.recordTrade(amountUSD, feeUSD);

                // Record trade for average price and total orders tracking
                fillOrderLogic.globalAverage.removeOrder(price, amountUSD);

                closed.buys.emplace_back(*it);
                closed.buys.back().closed = true;
                closed.buys.back().closedTime = systemClock.getMilliseconds();

                // Swap-and-pop safely
                std::swap(*it, open.buys.back());
                open.buys.pop_back();
            } else {
                ++it; // increment only if we did NOT remove it
            }
        }

        // Update fee tier based on rolling 30-day USD volume
        uint64_t volumeUSD = fillOrderLogic.getRollingVolume();
        params.updateFeesByVolume(params, volumeUSD, false);
    }

    void rebalanceSellOrders(uint64_t currentPrice, OpenPositions &open, ClosedPositions &closed, Banking &bank) {
        // SELL BITCOIN
        for (auto it = open.sells.begin(); it != open.sells.end();) {
            // Only process REBALANCE orders
            if (it->purpose == LadderOrderPurpose::REBALANCE && it->orderType == OrderType::MARKET) {
                uint64_t price = it->price;
                uint64_t amountBTC = it->amount;
                uint64_t amountUSD = (price * amountBTC) / SATOSHIS;
                uint64_t feeUSD = (amountUSD * params.takerFeeRate) / 10000ULL;

                // Banking: withdraw USD, deposit BTC
                bank.withdraw("BTC", amountBTC);
                bank.deposit("USD", amountUSD - feeUSD);

                double pnlUSD = static_cast<double>(0);
                double pnlBTC = static_cast<double>(0);
                double volumeBTC = static_cast<double>(amountBTC) / SATOSHIS;
                int trades = 1;

                calendar.setCalendarTrades(pnlUSD, pnlBTC, volumeBTC, trades);

                if (printOutput) {
                    render.pushLine(" - Rebalanced Sell Order: Withdrawing BTC: " + functions.formatIntBTC(amountBTC), Align::LEFT);
                    render.pushLine(" - Rebalanced Sell Order: Depositing USD: " + functions.formatIntUSD(amountUSD - feeUSD), Align::LEFT);
                }

                // Record trade volume and fees
                fillOrderLogic.recordTrade(amountUSD, feeUSD);

                // Record trade for average price and total orders tracking
                fillOrderLogic.globalAverage.removeOrder(price, amountUSD);

                // Move to closed positions
                closed.sells.emplace_back(*it);
                closed.sells.back().closed = true;
                closed.sells.back().closedTime = systemClock.getMilliseconds();

                // Swap-and-pop safely
                std::swap(*it, open.sells.back());
                open.sells.pop_back();
            } else {
                ++it; // increment only if we did NOT remove it
            }
        }

        // Update fee tier based on rolling 30-day USD volume
        uint64_t volumeUSD = fillOrderLogic.getRollingVolume();
        params.updateFeesByVolume(params, volumeUSD, false);
    }

    void stopLossBuy(double currentPrice, FilledPositions &filled, ClosedPositions &closed) {

        for (auto it = filled.buys.begin(); it != filled.buys.end();) {

            uint64_t entryPrice = it->price;
            double leverage = static_cast<double>(it->leverage);
            uint64_t triggerPrice = 0;
            std::string triggerReason;

            // 1. Check stop-loss first
            if (it->stopLossPercent > 0.0) {
                triggerPrice = static_cast<uint64_t>(entryPrice * (1.0 - it->stopLossPercent / 100.0));
                triggerReason = "Stop-Loss";
            }
            // 2. If no stop-loss, fallback to liquidation price
            else if (calculateLiquidationPrice(entryPrice, static_cast<uint64_t>(leverage), true) > 0) {
                triggerPrice = calculateLiquidationPrice(entryPrice, static_cast<uint64_t>(leverage), true);
                triggerReason = "Liquidation";
            }
            // 3. Default ladder bottom
            else {
                uint64_t buffer = params.increment * 2;
                triggerPrice = entryPrice + (params.increment * params.spotOrders) + buffer;
                triggerReason = "Ladder-Bottom";
            }

            // Execute if current price hits the trigger and leverage is used
            if (currentPrice <= triggerPrice && params.isLeverage) {
                it->isLiquidated = true;
                uint64_t amountBTC = it->amount;

                // Convert to USD (cents) using integer math
                uint64_t amountUSD = triggerPrice * amountBTC;
                uint64_t feeUSD = (amountUSD * params.makerFeeRate) / 10000ULL;

                // --- Use signed integers for net profit ---
                int64_t netProfitUSD = static_cast<int64_t>(triggerPrice - entryPrice) * static_cast<int64_t>(amountBTC) - static_cast<int64_t>(feeUSD);
                int64_t netProfitBTC = (triggerPrice != 0) ? (netProfitUSD * static_cast<int64_t>(SATOSHIS) / static_cast<int64_t>(triggerPrice)) : 0;

                // Banking operations
                bank.withdraw("BTC", amountBTC);
                bank.deposit("USD", amountUSD - feeUSD);

                if (printOutput) {
                    render.pushLine(" - Stop-Loss Buy Order: Triggered by: " + triggerReason, Align::LEFT);
                    render.pushLine(" - Stop-Loss Buy Order: Withdrawing BTC: " + functions.formatIntBTC(amountBTC), Align::LEFT);
                    render.pushLine(" - Stop-Loss Buy Order: Depositing USD: " + functions.formatIntUSD(amountUSD - feeUSD), Align::LEFT);
                }

                // Record trade volume and fees
                fillOrderLogic.recordTrade(amountUSD, feeUSD);

                // Record trade for average price and total orders tracking
                fillOrderLogic.globalAverage.removeOrder(triggerPrice, amountUSD);

                // Update overall realized profit
                profitUSD += netProfitUSD;
                profitBTC += netProfitBTC;
                stoplossLong++;

                // Mark as closed and move to closed positions
                it->closed = true;
                it->closedTime = systemClock.getMilliseconds();
                closed.buys.emplace_back(std::move(*it));

                // Remove from filled via swap-and-pop
                if (it != filled.buys.end()) {
                    std::swap(*it, filled.buys.back());
                    filled.buys.pop_back();
                }
            } else {
                ++it;
            }
        }

        // Update fee tier based on rolling 30-day USD volume
        uint64_t volumeUSD = fillOrderLogic.getRollingVolume();
        params.updateFeesByVolume(params, volumeUSD, true);
    }

    void stopLossSell(double currentPrice, FilledPositions &filled, ClosedPositions &closed) {

        for (auto it = filled.sells.begin(); it != filled.sells.end();) {

            uint64_t entryPrice = it->price;
            double leverage = static_cast<double>(it->leverage);
            uint64_t triggerPrice = 0;
            std::string triggerReason;

            // 1. Check stop-loss first
            if (it->stopLossPercent > 0.0) {
                triggerPrice = static_cast<uint64_t>(entryPrice * (1.0 - it->stopLossPercent / 100.0));
                triggerReason = "Stop-Loss";
            }
            // 2. If no stop-loss, fallback to liquidation price
            else if (calculateLiquidationPrice(entryPrice, static_cast<uint64_t>(leverage), false) > 0) {
                triggerPrice = calculateLiquidationPrice(entryPrice, static_cast<uint64_t>(leverage), false);
                triggerReason = "Liquidation";
            }
            // 3. Default ladder top (for short positions)
            else {
                uint64_t buffer = params.increment * 2;
                triggerPrice = entryPrice - (params.increment * params.spotOrders) - buffer;
                triggerReason = "Ladder-Bottom";
            }

            // Execute stop-loss if current price hits or exceeds trigger price
            if (currentPrice >= triggerPrice && params.isLeverage) {

                it->isLiquidated = true;
                uint64_t amountBTC = it->amount;

                // Convert to USD (cents)
                uint64_t amountUSD = triggerPrice * amountBTC;
                uint64_t feeUSD = (amountUSD * params.makerFeeRate) / 10000ULL;

                // --- Use signed integers for net profit to allow losses ---
                int64_t netProfitUSD = static_cast<int64_t>(entryPrice - triggerPrice) * static_cast<int64_t>(amountBTC) - static_cast<int64_t>(feeUSD);
                int64_t netProfitBTC = (triggerPrice != 0) ? (netProfitUSD * static_cast<int64_t>(SATOSHIS) / static_cast<int64_t>(triggerPrice)) : 0;

                // Closing a short: withdraw USD and deposit BTC
                bank.withdraw("USD", amountUSD + feeUSD);
                bank.deposit("BTC", amountBTC);

                if (printOutput) {
                    render.pushLine(" - Stop-Loss Sell Order: Triggered by: " + triggerReason, Align::LEFT);
                    render.pushLine(" - Stop-Loss Sell Order: Stop Loss: Withdrawing USD: " + functions.formatIntUSD(amountUSD + feeUSD), Align::LEFT);
                    render.pushLine(" - Stop-Loss Sell Order: Stop Loss: Depositing BTC: " + functions.formatIntBTC(amountBTC), Align::LEFT);
                }

                // Record trade volume and fees
                fillOrderLogic.recordTrade(amountUSD, feeUSD);

                // Record trade for average price and total orders tracking
                fillOrderLogic.globalAverage.removeOrder(triggerPrice, amountUSD);

                // Update overall realized profit
                profitUSD += netProfitUSD;
                profitBTC += netProfitBTC;

                // Mark as closed and move to closed positions
                it->closed = true;
                it->closedTime = systemClock.getMilliseconds();
                closed.sells.emplace_back(std::move(*it));

                // Remove from filled via swap-and-pop
                std::swap(*it, filled.sells.back());
                filled.sells.pop_back();

                stoplossShort++;
            } else {
                ++it;
            }
        }

        // Update fee tier based on rolling 30-day USD volume
        uint64_t volumeUSD = fillOrderLogic.getRollingVolume();
        params.updateFeesByVolume(params, volumeUSD, true);
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class ClearOpenOrders {
  public:
    ClearOpenOrders(Parameters &params, FillOrderLogic &fillOrderLogic, Render &render, bool print = true)
        : params(params) // Reference to trading parameters (fees, leverage, increments, etc.)
          ,
          fillOrderLogic(fillOrderLogic) // Reference to FillOrderLogic (tracks filled orders and volume)
          ,
          render(render), printOutput(print) // Enable/disable printing to console
    {
        LOG_INFO("Class: ClearOpenOrders");
    }

    // Setter to enable/disable console output
    void setPrintOutput(bool value) { printOutput = value; }

    // Main function: removes open orders that are outside allowed price range
    void remove(uint64_t currentPrice, OpenPositions &open, const FilledPositions &filled) {
        // Count of currently filled orders
        int filledCount = fillOrderLogic.getFilledCount(filled);

        // Compute the allowed price range based on current price and remaining spot orders
        uint64_t minAllowedPrice = getMinAllowedPrice(currentPrice, filledCount);
        uint64_t maxAllowedPrice = getMaxAllowedPrice(currentPrice, filledCount);

        int removed = 0; // counter for how many orders are removed

        if (printOutput) {
            std::string dash = std::string(80, '-');
            render.pushLine(dash, Align::LEFT);
            render.pushLine(">> Removed Orders", Align::LEFT);
        }

        // Remove open BUY orders outside allowed range (faster swap-and-pop)
        for (size_t i = 0; i < open.buys.size();) {
            Parameters &order = open.buys[i];

            if (order.purpose == LadderOrderPurpose::OPEN && (order.price < minAllowedPrice || order.price > maxAllowedPrice)) {

                if (printOutput) {
                    render.pushLine(" - Removed BUY Order: $" + functions.formatIntUSD(order.price) + " for " + functions.formatIntBTC(order.amount) + " BTC", Align::LEFT);
                }

                // Swap with last element and pop
                if (i != open.buys.size() - 1) {
                    std::swap(open.buys[i], open.buys.back());
                }
                open.buys.pop_back();
                removed++;
                // Do not increment i because we need to check the swapped-in element
            } else {
                ++i;
            }
        }

        // Remove open SELL orders outside allowed range (faster swap-and-pop)
        for (size_t i = 0; i < open.sells.size();) {
            Parameters &order = open.sells[i];

            if (order.purpose == LadderOrderPurpose::OPEN && (order.price < minAllowedPrice || order.price > maxAllowedPrice)) {

                if (printOutput) {
                    render.pushLine(" - Removed SELL order: $" + functions.formatIntUSD(order.price) + " for " + functions.formatIntBTC(order.amount) + " BTC", Align::LEFT);
                }

                // Swap with last element and pop
                if (i != open.sells.size() - 1) {
                    std::swap(open.sells[i], open.sells.back());
                }
                open.sells.pop_back();
                removed++;
                // Do not increment i because we need to check the swapped-in element
            } else {
                ++i;
            }
        }

        // Print summary of removed orders
        if (printOutput && removed > 0) {
            render.pushLine(" - Cleared " + std::to_string(removed) + " Open Orders outside $" + functions.formatIntUSD(minAllowedPrice) + " - $" +
                                functions.formatIntUSD(maxAllowedPrice),
                            Align::LEFT);
        }
    }

    // Compute minimum allowed price for new open orders
    inline uint64_t getMinAllowedPrice(uint64_t currentPrice, int filledCount) {
        // Round current price down to nearest increment
        uint64_t basePrice = (currentPrice / params.increment) * params.increment;
        int remaining = params.spotOrders - filledCount;
        // Minimum price is base price minus increments for remaining spots
        return basePrice - (params.increment * (remaining - 1));
    }

    // Compute maximum allowed price for new open orders
    inline uint64_t getMaxAllowedPrice(uint64_t currentPrice, int filledCount) {
        // Round current price up to nearest increment
        uint64_t basePrice = ((currentPrice + params.increment - 1) / params.increment) * params.increment;
        int remaining = params.spotOrders - filledCount;
        // Maximum price is base price plus increments for remaining spots
        return basePrice + (params.increment * (remaining - 1));
    }

  private:
    Parameters &params;             // Trading configuration (increments, spotOrders, etc.)
    FillOrderLogic &fillOrderLogic; // Used to check number of filled orders
    bool printOutput;               // Whether to print console messages
    Render &render;
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class PlaceNewOrders {
  public:
    PlaceNewOrders(Banking &bank, Parameters &params, FillOrderLogic &fillOrderLogic, TradeLogic &tradeLogic, Render &render, bool print = true)
        : bank(bank), params(params), fillOrderLogic(fillOrderLogic), tradeLogic(tradeLogic), render(render), printOutput(print), output(params, render) {
        LOG_INFO("Class: PlaceNewOrders");
    }

    void setPrintOutput(bool value) { printOutput = value; }

    struct RebalanceStats {
        uint64_t globalAverage;
        double startPrice;
        double endPrice;
        double percentReturned;
        double gain;
        double targetUSDfraction;
        double targetBTCfraction;
    };

    RebalanceStats rebalanceStats;

    inline void newOrders(
        uint64_t currentPrice, TradeType &currentState, OpenPositions &openPositions, FilledPositions &filledPositions, const Parameters &config, CandleCollector &collector) {

        auto countOpenPurpose = [](const auto &orders) { return std::count_if(orders.begin(), orders.end(), [](const auto &o) { return o.purpose == LadderOrderPurpose::OPEN; }); };

        int activeOrders =
            countOpenPurpose(openPositions.buys) + countOpenPurpose(openPositions.sells) + countOpenPurpose(filledPositions.buys) + countOpenPurpose(filledPositions.sells);

        bool isLeverage = (config.leverage != Parameters::Leverage::NONE);
        int remainingOrders = 0;

        if (isLeverage) {
            remainingOrders = params.leveragedOrders - activeOrders; // limit leveraged orders
        } else {
            remainingOrders = params.spotOrders - activeOrders; // limit spot orders if you want a soft cap
        }

        if (printOutput) {
            output.titleRebalanced();
        }
        rebalancePortfolio(bank, currentPrice, openPositions, filledPositions, config, collector);

        if (printOutput) {
            output.titleLadder();
        }
        if (remainingOrders > 0) {
            // Only place new ladder orders if there’s room
            placeLadderOrders(currentPrice, remainingOrders, currentState, openPositions, filledPositions, config);
        }
        if (remainingOrders <= 0 && printOutput) {
            render.pushLine(" - Max spot orders reached (" + std::to_string(params.spotOrders) + "), not placing more.", Align::LEFT);
        }

        if (printOutput) {
            output.titleAdjusting();
        }
        refreshCloseOrder(currentPrice, currentState, openPositions, filledPositions, config);

        if (printOutput) {
            output.titleBatched();
        }
        placeCloseBatchOrder(currentState, openPositions, filledPositions, config);
    }

  private:
    FillOrderLogic &fillOrderLogic;
    TradeLogic &tradeLogic;
    Banking &bank;
    Parameters &params;
    bool printOutput;

    GenerateUUID uuidGenerator;
    Render &render;

    Output output;

    std::string apiKey;
    std::string apiSecret;

    uint64_t lastProfitBTC = 0;

    int openPositionCount = 0;

    enum class OrderStatus { OK, AlreadyOpen, RecentlyFilled };

    inline void refreshCloseOrder(uint64_t currentPrice, TradeType currentState, OpenPositions &openPositions, FilledPositions &filledPositions, const Parameters &config) {

        uint64_t averagePrice = 0;
        uint64_t closePrice = 0;

        // Determine which positions to close
        if (currentState == TradeType::BUY && !filledPositions.buys.empty()) {
            averagePrice = fillOrderLogic.calculateAverageBuyPrice(params);
            closePrice = averagePrice * (1.0 + params.threshold / CENTS);
            closePrice = roundUpTo100(closePrice); // round up for selling
            currentState = TradeType::SELL;        // opposite
        } else if (currentState == TradeType::SELL && !filledPositions.sells.empty()) {
            averagePrice = fillOrderLogic.calculateAverageSellPrice(params);
            closePrice = averagePrice * (1.0 - params.threshold / CENTS);
            closePrice = roundDownTo100(closePrice); // round down for buying
            currentState = TradeType::BUY;           // opposite
        } else {
            if (printOutput) {
                render.pushLine(" - Nothing to Close...", Align::LEFT);
            }
            return;
        }

        // Check if CLOSE already exists in open positions
        auto existsInOpen = [&](const std::vector<Parameters> &orders) {
            return std::any_of(orders.begin(), orders.end(), [](const auto &o) { return o.purpose == LadderOrderPurpose::CLOSE; });
        };

        bool closeExists = existsInOpen(openPositions.buys) || existsInOpen(openPositions.sells);

        if (!closeExists) {
            placeCloseOrder(closePrice, currentState, openPositions, filledPositions, config);
        } else {
            adjustCloseOrder(closePrice, openPositions, filledPositions);
        }
    }

    inline void adjustCloseOrder(uint64_t closePrice, OpenPositions &openPositions, FilledPositions &filledPositions) {

        auto adjustInVector = [&](std::vector<Parameters> &orders) {
            for (size_t i = 0; i < orders.size(); ++i) {
                if (orders[i].purpose == LadderOrderPurpose::CLOSE) {
                    uint64_t existingPrice = orders[i].price;
                    if (existingPrice != closePrice) {
                        if (printOutput) {
                            render.pushLine(" - Adjusting Closed Order: existing $" + functions.formatIntUSD(existingPrice) + " → new $" + functions.formatIntUSD(closePrice),
                                            Align::LEFT);
                        }

                        TradeType orderType = orders[i].type;
                        orders[i] = std::move(orders.back());
                        orders.pop_back();

                        // Place new close order
                        placeCloseOrder(closePrice, orderType, openPositions, filledPositions, params);
                    }

                    return true; // handled
                }
            }
            return false;
        };

        // Try adjusting BUY CLOSE first
        if (adjustInVector(openPositions.buys))
            return;

        // Then try SELL CLOSE
        if (adjustInVector(openPositions.sells))
            return;
    }

    void placeLadderOrders(uint64_t currentPrice, int numOrders, TradeType currentState, OpenPositions &openPositions, FilledPositions &filledPositions, const Parameters &config) {

        int placed = 0;
        uint64_t basePrice;

        if (currentState == TradeType::BUY) {
            // floor(89414 / 100) * 100 = 894 * 100 = **89,400**
            basePrice = std::floor(currentPrice / params.increment) * params.increment;
        } else {
            // floor(89414 / 100) * 100 = 894 * 100 + 100 = **89,500**
            // basePrice = std::ceil(currentPrice / params.increment) * params.increment - params.increment;
            basePrice = std::floor(currentPrice / params.increment) * params.increment + params.increment;
        }

        TradeType activeDirection = getActiveLadderDirection(filledPositions, currentState);

        // Only trade in the active ladder direction if one exists
        if ((activeDirection == TradeType::BUY && currentState == TradeType::SELL) || (activeDirection == TradeType::SELL && currentState == TradeType::BUY)) {
            if (printOutput) {
                render.pushLine(" - Skipping ladder orders: active ladder direction is " + std::string(activeDirection == TradeType::BUY ? "BUY" : "SELL"), Align::LEFT);
            }
            return;
        }

        for (int i = 0; i < numOrders; ++i) {
            uint64_t price = (currentState == TradeType::BUY) ? basePrice - params.increment * i  // ladder down
                                                              : basePrice + params.increment * i; // ladder up

            OrderStatus status = checkOrderStatusAtPrice(price, openPositions, filledPositions, params);

            switch (status) {
            case OrderStatus::AlreadyOpen:
                if (printOutput) {
                    render.pushLine(" - Skipping Order at $" + functions.formatIntUSD(price) + " - Already Open.", Align::LEFT);
                }
                continue;
            case OrderStatus::RecentlyFilled:
                if (printOutput) {
                    render.pushLine(" - Skipping Order at $" + functions.formatIntUSD(price) + " - Recently Filled.", Align::LEFT);
                }
                continue;
            case OrderStatus::OK:
                break;
            }

            placeOpenOrder(price, currentPrice, currentState, openPositions, filledPositions, config);
            ++placed;
        }

        if (printOutput) {
            if (placed > 0) {
                render.pushLine(" - Placed " + std::to_string(placed) + " new ladder orders.", Align::LEFT);
            } else {
                render.pushLine(" - No new ladder orders placed.", Align::LEFT);
            }
        }
    }

    inline OrderStatus checkOrderStatusAtPrice(uint64_t currentPrice, const OpenPositions &openPositions, FilledPositions &filledPositions, const Parameters &params) {

        // --- 1. Check open orders ---
        for (const auto &order : openPositions.buys)
            if (order.price == currentPrice)
                return OrderStatus::AlreadyOpen;

        for (const auto &order : openPositions.sells)
            if (order.price == currentPrice)
                return OrderStatus::AlreadyOpen;

        // --- 2. Current time in milliseconds since epoch ---
        uint64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

        // --- 3. Check recently filled orders ---
        auto recentlyFilled = [&](const auto &filledOrders) {
            for (const auto &order : filledOrders) {
                if (order.price == currentPrice) {
                    uint64_t hoursSinceFilled = (nowMs - order.filledTime) / (1000 * 60 * 60);
                    if (hoursSinceFilled < static_cast<uint64_t>(params.delayHours))
                        return true;
                }
            }
            return false;
        };

        if (recentlyFilled(filledPositions.buys) || recentlyFilled(filledPositions.sells))
            return OrderStatus::RecentlyFilled;

        return OrderStatus::OK;
    }

    void rebalancePortfolio(
        Banking &bank, uint64_t currentPrice, OpenPositions &openPositions, FilledPositions &filledPositions, const Parameters &config, const CandleCollector &collector) {

        const std::vector<double> &closesD = collector.getCloses();

        // Need at least 14 candles for 2-week rebalance logic
        if (closesD.size() < 14) {
            if (printOutput) {
                render.pushLine(" - Not enough data for rebalance (need 14 candles)", Align::LEFT);
            }
            return; // Skip rebalance — not enough history
        }

        // Now safe to access
        std::vector<uint64_t> closes;
        closes.reserve(closesD.size());
        for (double price : closesD) {
            closes.push_back(static_cast<uint64_t>(price * 100));
        }

        uint64_t start = closes[closes.size() - 14];
        uint64_t end = closes.back();

        double startPrice = static_cast<double>(start) / CENTS;
        double endPrice = static_cast<double>(end) / CENTS;
        double percentReturned = (endPrice - startPrice) / startPrice * 100.0;

        // Map to target BTC allocation (25% -> 75%)
        // Linear mapping with clamping at ±20%
        double normalized = std::clamp((percentReturned + 20.0) / 40.0, 0.0, 1.0); // -20% → 0, +20% → 1
        double targetBTCfraction = 0.25 + normalized * 0.5;                        // scale to 25%-75%
        double targetUSDfraction = 1.0 - targetBTCfraction;

        // 2. Current balances as doubles
        double usdBalance = static_cast<double>(bank.getBalance("USD")) / CENTS;    // cents → dollars
        double btcBalance = static_cast<double>(bank.getBalance("BTC")) / SATOSHIS; // satoshis → BTC

        // 3. Total portfolio value
        double totalValue = usdBalance + btcBalance * static_cast<double>(currentPrice) / CENTS;

        // 4. Convert fraction to BTC amount
        double targetBTCvalueUSD = totalValue * targetBTCfraction;
        double targetBTC = targetBTCvalueUSD / currentPrice * CENTS;
        double targetUSD = totalValue * targetUSDfraction;

        // 5. Compute BTC deviation
        double btcDeviation = btcBalance - targetBTC;

        // 6. Threshold should be grater than 0.0001 Satoshi
        double thresholdBTC = (params.amount * 5.0) / SATOSHIS;

        // Get the current average price for rebalancing checks:
        uint64_t globalAverage = fillOrderLogic.globalAverage.getAveragePrice();

        // 7. Rebalance if deviation exceeds threshold
        if (btcDeviation > thresholdBTC) {
            double selling = btcDeviation;
            uint64_t btcToSell = static_cast<uint64_t>(std::round(selling * SATOSHIS));
            if (currentPrice >= globalAverage && globalAverage != 0 && !filledPositions.buys.empty()) {
                placeRebalanceOrder(currentPrice, TradeType::SELL, btcToSell, openPositions, filledPositions, config);
                if (printOutput) {
                    render.pushLine(" - Rebalanced Sell of " + functions.formatIntBTC(btcToSell) + " BTC @ $" + functions.formatIntUSD(currentPrice), Align::LEFT);
                }
            } else { // currentPrice < globalAverage
                if (printOutput) {
                    render.pushLine(" - Skipping Rebalanced Sell - current price is below or the global average is 0", Align::LEFT);
                }
            }
        } else if (btcDeviation < -thresholdBTC) {
            double buying = -btcDeviation;
            uint64_t btcToBuy = static_cast<uint64_t>(std::round(buying * SATOSHIS));
            if (currentPrice <= globalAverage && globalAverage != 0 && !filledPositions.sells.empty()) {
                placeRebalanceOrder(currentPrice, TradeType::BUY, btcToBuy, openPositions, filledPositions, config);
                if (printOutput) {
                    render.pushLine(" - Rebalanced Buy of " + functions.formatIntBTC(btcToBuy) + " BTC @ $" + functions.formatIntUSD(currentPrice), Align::LEFT);
                }
            } else { // currentPrice > globalAverage
                if (printOutput) {
                    render.pushLine(" - Skipping Rebalanced Buy - current price is above or the global average is 0", Align::LEFT);
                }
            }
        } else {
            if (printOutput) {
                render.pushLine(" - Portfolio on target - no rebalance needed.", Align::LEFT);
            }
        }

        // 8. Hedging profit calculation in doubles
        double balanceUSD50 = totalValue / 2.0;
        double balanceBTC50 = (totalValue / 2.0) / static_cast<double>(currentPrice);

        double unhedgedValue = balanceUSD50 + balanceBTC50 * endPrice;
        double hedgedValue = targetUSD + targetBTC / 100 * endPrice;
        double gain = hedgedValue - unhedgedValue;

        rebalanceStats.globalAverage = globalAverage;
        rebalanceStats.startPrice = startPrice;
        rebalanceStats.endPrice = endPrice;
        rebalanceStats.percentReturned = percentReturned;
        rebalanceStats.gain = gain;
        rebalanceStats.targetUSDfraction = targetUSDfraction;
        rebalanceStats.targetBTCfraction = targetBTCfraction;
    }

    void placeRebalanceOrder(uint64_t currentPrice, TradeType type, uint64_t amount, OpenPositions &openPositions, FilledPositions &filledPositions, const Parameters &config) {
        // Check if a rebalance order already exists
        if (hasExistingRebalanceOrder(type, openPositions, filledPositions)) {
            if (printOutput) {
                render.pushLine(" - Skipping new Rebalanced order - one already exists.", Align::LEFT);
            }
            return; // Do not create another REBALANCE order
        }

        Parameters order;
        auto [_, uuid] = uuidGenerator.generateUUID();
        order.uuid = uuid;
        order.type = type;
        order.price = currentPrice;                          // in cents
        order.amount = amount;                               // in satoshis
        order.usdValue = (currentPrice * amount) / SATOSHIS; // integer-safe USD value in cents
        order.pairSymbol = config.pairSymbol;
        order.orderType = Parameters::OrderType::MARKET;
        order.leverage = Parameters::Leverage::NONE;
        order.purpose = LadderOrderPurpose::REBALANCE;
        order.openTime = systemClock.getMilliseconds();
        order.filled = false;
        order.filledTime = systemClock.getMilliseconds();
        order.fee = 0;
        order.deposit = 0;
        order.withdraw = 0;

        // Push into the correct container
        if (type == TradeType::BUY) {
            openPositions.buys.push_back(order);
            fillOrderLogic.logSale(true, openPositionCount, order);
        } else {
            openPositions.sells.push_back(order);
            fillOrderLogic.logSale(false, openPositionCount, order);
        }

        if (printOutput) {
            render.pushLine(std::string(" - Placed ") + (type == TradeType::BUY ? "BUY" : "SELL") + " Rebalanced order of " + functions.formatIntBTC(amount) + " BTC @ $" +
                                functions.formatIntUSD(currentPrice),
                            Align::LEFT);
        }
    }

    void placeOpenOrder(uint64_t price, uint64_t currentPrice, TradeType type, OpenPositions &openPositions, FilledPositions &filledPositions, const Parameters &config) {

        // Calculate order size in satoshis
        uint64_t newOrderSize = calculateNewOrderAmount(price);

        // Apply leverage safely (integer multiplication)
        switch (config.leverage) {
        case Parameters::Leverage::NONE:
            break; // *1
        case Parameters::Leverage::TWO_X:
            newOrderSize *= 2;
            break;
        case Parameters::Leverage::THREE_X:
            newOrderSize *= 3;
            break;
        case Parameters::Leverage::FIVE_X:
            newOrderSize *= 5;
            break;
        default:
            break;
        }

        uint64_t totalUSDNeeded = 0;
        uint64_t totalBTCNeeded = 0;
        uint64_t basePrice = 0;

        // Compute required USD in cents (integer math)
        uint64_t usdRequired = (newOrderSize * price * config.makerFeeRate) / (SATOSHIS * config.makerFeeRate);

        // BTC required is just the satoshis including fee
        uint64_t btcRequired = (newOrderSize * config.makerFeeRate) / config.makerFeeRate;

        if (type == TradeType::BUY) {
            basePrice = std::floor(currentPrice / params.increment) * params.increment;
        } else {
            basePrice = std::ceil(currentPrice / params.increment) * params.increment;
        }

        bool rebalancePortfolio = true;

        if (rebalancePortfolio) {
            if (type == TradeType::BUY) {
                if (bank.getBalance("USD") < usdRequired) {
                    if (printOutput) {
                        render.pushLine(" - Insufficient USD to BUY order - Selling Bitcoin", Align::LEFT);
                    }
                    for (int i = 0; i < params.spotOrders; ++i) {
                        uint64_t ladderPrice = basePrice - params.increment * i; // ladder down
                        totalUSDNeeded += ladderPrice * usdRequired;             // USD = price * BTC
                    }
                    type = TradeType::SELL;
                    placeRebalanceOrder(currentPrice, type, totalUSDNeeded, openPositions, filledPositions, config);
                    type = TradeType::BUY;
                    // return; // skip order
                }
            } else { // SELL
                if (bank.getBalance("BTC") < btcRequired) {
                    if (printOutput) {
                        render.pushLine(" - Insufficient BTC for SELL order - Buying Bitcoin", Align::LEFT);
                    }
                    for (int i = 0; i < params.spotOrders; ++i) {
                        uint64_t ladderPrice = basePrice + params.increment * i; // ladder up
                        totalBTCNeeded += btcRequired;                           // BTC per order
                    }
                    type = TradeType::BUY;
                    placeRebalanceOrder(currentPrice, type, totalBTCNeeded, openPositions, filledPositions, config);
                    type = TradeType::SELL;
                    // return; // skip order
                }
            }
        } else {
            if (type == TradeType::BUY) {
                if (bank.getBalance("USD") < usdRequired) {
                    if (printOutput) {
                        render.pushLine(" - Insufficient USD to BUY order of " + functions.formatIntBTC(newOrderSize) + " BTC @ $" + functions.formatIntUSD(price), Align::LEFT);
                    }
                    return; // skip order
                }
            } else { // SELL
                if (bank.getBalance("BTC") < btcRequired) {
                    if (printOutput) {
                        render.pushLine(" - Insufficient BTC to SELL order of " + functions.formatIntBTC(newOrderSize) + " BTC @ $" + functions.formatIntUSD(price), Align::LEFT);
                    }
                    return; // skip order
                }
            }
        }

        // Prepare OPEN order
        Parameters openOrder;
        auto [_, uuid] = uuidGenerator.generateUUID();
        openOrder.uuid = uuid;
        openOrder.type = type;
        openOrder.price = price;                                // in cents
        openOrder.amount = newOrderSize;                        // in satoshis
        openOrder.usdValue = (price * newOrderSize) / SATOSHIS; // in cents
        openOrder.pairSymbol = config.pairSymbol;
        openOrder.orderType = Parameters::OrderType::LIMIT;
        openOrder.leverage = config.leverage;
        openOrder.purpose = LadderOrderPurpose::OPEN;
        openOrder.openTime = systemClock.getMilliseconds();
        openOrder.filled = false;
        openOrder.filledTime = 0;
        openOrder.fee = 0;
        openOrder.deposit = 0;
        openOrder.withdraw = 0;

        openPositionCount++;

        if (type == TradeType::BUY) {
            openPositions.buys.push_back(openOrder);
            fillOrderLogic.logSale(true, openPositionCount, openOrder);
        } else {
            openPositions.sells.push_back(openOrder);
            fillOrderLogic.logSale(false, openPositionCount, openOrder);
        }

        if (printOutput) {
            render.pushLine(" - Placed " + std::string(type == TradeType::BUY ? "BUY" : "SELL") + " Open order of " + functions.formatIntBTC(newOrderSize) + " BTC @ $" +
                                functions.formatIntUSD(price),
                            Align::LEFT);
        }
    }

    void placeCloseBatchOrder(TradeType type, OpenPositions &openPositions, FilledPositions &filledPositions, const Parameters &config) {

        auto &batches = (type == TradeType::BUY) ? filledPositions.batchedBuys : filledPositions.batchedSells;
        if (batches.empty())
            return;

        for (auto &batch : batches) {
            // Skip if we've already created a close order for this batch
            if (batch.isBatched)
                continue;
            batch.isBatched = true; // mark this batch as processed

            uint64_t sumTotalAmount = batch.totalAmount;
            uint64_t sumWeightedPrice = batch.weightedPriceSum;
            uint64_t averagePrice = batch.averagePrice;

            if (sumTotalAmount == 0) {
                if (printOutput) {
                    render.pushLine(" - No batched orders to close in this batch...", Align::LEFT);
                }
                continue;
            }

            double multiplier;
            if (type == TradeType::BUY) {
                // Long: sell higher → add profit threshold
                multiplier = 1.0 + (config.threshold / 100.0);
            } else {
                // Short: buy back lower → subtract profit threshold
                multiplier = 1.0 - (config.threshold / 100.0);
            }

            uint64_t close = static_cast<uint64_t>(averagePrice * multiplier);
            uint64_t closePrice = (type == TradeType::BUY) ? roundUpTo100(close) : roundDownTo100(close);

            // Create the close order
            Parameters closeOrder;
            auto [_, uuid] = uuidGenerator.generateUUID();
            closeOrder.uuid = uuid;
            closeOrder.type = type;
            closeOrder.price = closePrice;
            closeOrder.averagePrice = averagePrice;
            closeOrder.amount = sumTotalAmount;
            closeOrder.usdValue = (sumTotalAmount * closePrice) / SATOSHIS;
            closeOrder.pairSymbol = config.pairSymbol;
            closeOrder.orderType = Parameters::OrderType::LIMIT;
            closeOrder.leverage = config.leverage;
            closeOrder.purpose = LadderOrderPurpose::BATCH;
            closeOrder.numOrders = batch.ordersInBatch;
            closeOrder.openTime = systemClock.getMilliseconds();
            closeOrder.filled = false;
            closeOrder.filledTime = 0;
            closeOrder.fee = 0;
            closeOrder.deposit = 0;
            closeOrder.withdraw = 0;

            // Push into opposite open position
            if (type == TradeType::BUY) {
                openPositions.sells.push_back(closeOrder);
                fillOrderLogic.logSale(false, openPositionCount, closeOrder);
            } else {
                openPositions.buys.push_back(closeOrder);
                fillOrderLogic.logSale(false, openPositionCount, closeOrder);
            }

            if (printOutput) {
                render.pushLine(" - Placed " + std::string(type == TradeType::BUY ? "BUY" : "SELL") + " Close Batch order of " + functions.formatIntBTC(sumTotalAmount) +
                                    " BTC @ $" + functions.formatIntUSD(closePrice),
                                Align::LEFT);
            }
        }
    }

    void placeCloseOrder(uint64_t closePrice, TradeType type, OpenPositions &openPositions, FilledPositions &filledPositions, const Parameters &config) {
        // Sum filled positions in satoshis
        uint64_t sumFilledAmount = 0;
        int numOrders = 0;
        uint64_t averagePrice = 0;
        std::vector<std::string> filledUuids;

        if (type == TradeType::SELL) { // closing BUY positions
            for (const auto &filledOrder : filledPositions.buys) {
                sumFilledAmount += filledOrder.amount; // amount in satoshis
                filledUuids.push_back(filledOrder.uuid);
            }
            numOrders = static_cast<int>(filledPositions.buys.size());
            averagePrice = fillOrderLogic.calculateAverageBuyPrice(params);
        } else { // type == BUY, closing SELL positions
            for (const auto &filledOrder : filledPositions.sells) {
                sumFilledAmount += filledOrder.amount;
                filledUuids.push_back(filledOrder.uuid);
            }
            numOrders = static_cast<int>(filledPositions.sells.size());
            averagePrice = fillOrderLogic.calculateAverageSellPrice(params);
        }

        // Skip if amount is zero
        if (sumFilledAmount == 0) {
            if (printOutput) {
                render.pushLine(" - Skipping CLOSE order — zero amount.", Align::LEFT);
            }
            return;
        }

        if (hasExistingCloseOrder(type, openPositions)) {
            if (printOutput) {
                render.pushLine(" - Skipping new Close order — one already exists.", Align::LEFT);
            }
            return;
        }

        Parameters closeOrder;
        auto [_, uuid] = uuidGenerator.generateUUID();
        closeOrder.uuid = uuid;
        closeOrder.type = type;
        closeOrder.price = closePrice; // in cents
        closeOrder.averagePrice = averagePrice;
        closeOrder.amount = sumFilledAmount;                             // in satoshis
        closeOrder.usdValue = (sumFilledAmount * closePrice) / SATOSHIS; // cents
        closeOrder.pairSymbol = config.pairSymbol;
        closeOrder.orderType = Parameters::OrderType::LIMIT;
        closeOrder.leverage = config.leverage;
        closeOrder.purpose = LadderOrderPurpose::CLOSE;
        closeOrder.numOrders = numOrders;
        closeOrder.openTime = systemClock.getMilliseconds();
        closeOrder.filled = false;
        closeOrder.filledTime = 0;
        closeOrder.fee = 0;
        closeOrder.deposit = 0;
        closeOrder.withdraw = 0;
        closeOrder.filledUuids = filledUuids;

        if (type == TradeType::BUY) {
            openPositions.buys.push_back(closeOrder);
            fillOrderLogic.logSale(false, openPositionCount, closeOrder);
        } else {
            openPositions.sells.push_back(closeOrder);
            fillOrderLogic.logSale(false, openPositionCount, closeOrder);
        }

        if (printOutput) {
            render.pushLine(" - Placed " + std::string(type == TradeType::BUY ? "BUY" : "SELL") + " Close order of " + functions.formatIntBTC(sumFilledAmount) + " BTC @ $" +
                                functions.formatIntUSD(closePrice),
                            Align::LEFT);
        }
    }

    inline TradeType getActiveLadderDirection(FilledPositions &filledPositions, TradeType currentState) {
        // If there are any buys, the active direction is BUY
        if (!filledPositions.buys.empty())
            return TradeType::BUY;

        // If there are any sells, the active direction is SELL
        if (!filledPositions.sells.empty())
            return TradeType::SELL;

        return currentState; // no active ladder, stick with current state
    }

    inline uint64_t calculateNewOrderAmount(uint64_t currentPrice) {
        uint64_t profitBTC = tradeLogic.getTotalRealizedProfitBTC(currentPrice);

        if (profitBTC > lastProfitBTC) {
            // Total realized profit in satoshis
            uint64_t perOrderBonus = (params.spotOrders > 0) ? profitBTC / params.spotOrders : 0;
            uint64_t newOrderAmountBTC = params.amount + perOrderBonus;
            return newOrderAmountBTC;
        } else {
            uint64_t newOrderAmountBTC = params.amount;
            return newOrderAmountBTC;
        }

        lastProfitBTC = profitBTC;
    }

    inline bool hasExistingCloseOrder(TradeType type, const OpenPositions &openPositions) {
        const auto &orders = (type == TradeType::BUY) ? openPositions.buys : openPositions.sells;
        return std::any_of(orders.begin(), orders.end(), [](const auto &o) { return o.purpose == LadderOrderPurpose::CLOSE; });
    }

    inline bool hasExistingRebalanceOrder(TradeType type, const OpenPositions &openPositions, FilledPositions &filledPositions) {

        auto checkVector = [](const std::vector<Parameters> &orders) {
            return std::any_of(orders.begin(), orders.end(), [](const Parameters &o) { return o.purpose == LadderOrderPurpose::REBALANCE; });
        };

        if (type == TradeType::BUY) {
            return checkVector(openPositions.buys) || checkVector(filledPositions.buys);
        } else { // TradeType::SELL
            return checkVector(openPositions.sells) || checkVector(filledPositions.sells);
        }
    }

    void setAPICredentials(const std::string &key, const std::string &secret) {
        apiKey = key;
        apiSecret = secret;
    }

    inline void addOrderToExchange(const Parameters &order) {
        if (printOutput) {
            std::cout << std::fixed << std::setprecision(8) << order.orderTypeToString(order.orderType) << " " << order.tradeTypeToString(order.type) << " " << order.amount
                      << " of " << order.tradingPairToString(order.pairSymbol) << " @ $" << order.price << "\n";
        }
        /*
                kraken.placeOrder(order.tradingPairToString(order.pairSymbol),
                          order.amount,
                          order.price,
                          order.tradeTypeToString(order.type)); */
    }

    inline uint64_t roundUpTo100(double value) { return std::ceil(value / 10000) * 10000; }

    inline uint64_t roundDownTo100(double value) { return std::floor(value / 10000) * 10000; }
};

class KrakenAPI {
  public:
    KrakenAPI(const std::string &apiKey, const std::string &apiSecret) : apiKey(apiKey), apiSecret(apiSecret) {}

    void placeOrder(const std::string &pair, double volume, double price, const std::string &type) {
        // TODO: implement POST /0/private/AddOrder
    }

  private:
    std::string apiKey;
    std::string apiSecret;
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class OrderOutput {
  public:
    OrderOutput(Banking &bank,
                Parameters &params,
                FillOrderLogic &fillOrderLogic,
                TradeLogic &tradeLogic,
                PlaceNewOrders &placeNewOrders,
                CandleCollector &collector,
                OutputBuffer &outputBuffer,
                Render &render,
                bool print = true)
        : bank(bank), params(params), fillOrderLogic(fillOrderLogic), tradeLogic(tradeLogic), placeNewOrders(placeNewOrders), collector(collector), outputBuffer(outputBuffer),
          render(render), printOutput(print), chart(params), output(params, render) {
        LOG_INFO("Class: OrderOutput");
    }

    void setPrintOutput(bool value) { printOutput = value; }

    void consoleOutput(uint64_t currentPrice,
                       double currentVolume,
                       uint64_t timestamp,
                       int tradeCount,
                       int iterationCount,
                       TradeType currentState,
                       const OpenPositions &open,
                       const FilledPositions &filled,
                       const ClosedPositions &closed,
                       SpeedReporter &speedReporter) {

        update(currentPrice, iterationCount, currentState, filled, closed);

        output.printHeader(currentPrice, iterationCount);

        printCalendar();

        output.titleStatistics();
        output.titleInformation();

        printChart(currentPrice, currentVolume, timestamp, tradeCount);

        buildBodyColumns(currentPrice, iterationCount, open, filled, closed);

        render.flushToColumn(bodyCol1);

        speedReporter.setSpeed();

        std::vector<std::vector<Line>> columns = {bodyCol1, bodyCol2, bodyCol3};

        std::cout << render.printBodyColumns(columns);

        output.printFooter(currentState);
    }

  private:
    FillOrderLogic &fillOrderLogic;
    TradeLogic &tradeLogic;
    PlaceNewOrders &placeNewOrders;
    Banking &bank;
    Parameters &params;
    CandleCollector &collector;
    OutputBuffer &outputBuffer;
    bool printOutput;

    Render &render;
    Output output;
    Chart chart;

    MovingAverage ma;
    RelativeStrengthIndex rsi;
    MACD macd;
    BollingerBands bb;
    VolumeIndicators vi;
    AverageTrueRange atr;
    StochasticOscillator so;
    FibonacciRetracement fr;
    IchimokuCloud ic;
    AverageDirectionalIndex adi;

    // fill / batch / order counts
    int filledCount = 0;
    int batchedCount = 0;
    int buyCount = 0;
    int sellCount = 0;

    // fees + volumes
    double totalFeesPaid = 0.0;
    double totalVolume = 0.0;
    double rollingVolume = 0.0;
    double currentMakerFeeRate = 0.0;
    double currentTakerFeeRate = 0.0;

    // closed orders
    int closedCount = 0;
    int closedLong = 0;
    int closedShort = 0;
    int stoplossLong = 0;
    int stoplossShort = 0;

    // profit metrics
    double totalRealizedProfit = 0.0;
    double profitPerOrder = 0.0;
    double btcProfit = 0.0;
    double usdProfit = 0.0;

    // average prices
    double averageBuyPrice = 0.0;
    double averageSellPrice = 0.0;

    // rebalancing stats
    double globalAverage = 0.0;
    double startPrice = 0.0;
    double endPrice = 0.0;
    double percentReturned = 0.0;
    double gain = 0.0;
    double targetUSDfraction = 0.0;
    double targetBTCfraction = 0.0;

    // unrealized
    double unrealisedProfit = 0.0;

    // deltas and percentages
    int64_t deltaBuy = 0;
    int64_t deltaSell = 0;
    double percentageAboveBuy = 0.0;
    double percentageBelowSell = 0.0;

    // leverage
    double leverage = 1.0;

    // liquidation prices
    double liquidatedBuy = 0.0;
    double liquidatedSell = 0.0;

    // fee info
    double fee = 0.0;
    double currentFeeRate = 0.0;

    // wallet info
    double usdAmount = 0.0;
    double btcAmount = 0.0;
    double totalValue = 0.0;

    // timestamp
    std::string time = "";

    void buildBodyColumns(uint64_t currentPrice, int iterationCount, const OpenPositions &open, const FilledPositions &filled, const ClosedPositions &closed) {
        auto lines0 = buildLeftColumn();
        bodyCol1.insert(bodyCol1.end(), lines0.begin(), lines0.end());
        bodyCol1.push_back({"", Align::LEFT});

        auto lines1 = buildHeaderLines(currentPrice, iterationCount, open, filled, closed);
        bodyCol1.insert(bodyCol1.end(), lines1.begin(), lines1.end());
        bodyCol1.push_back({"", Align::LEFT});

        auto lines2 = buildBodyLines(open, filled, closed);
        bodyCol2.insert(bodyCol2.end(), lines2.begin(), lines2.end());
        bodyCol2.push_back({"", Align::LEFT});

        auto lines3 = buildIndicatorLines();
        bodyCol3.insert(bodyCol3.end(), lines3.begin(), lines3.end());
        bodyCol3.push_back({"", Align::CENTER});

        bodyCol3.emplace_back("", Align::LEFT);
    }

    void printCalendar() {
        std::vector<Line> calendarCol;

        auto lines = calendar.generate();
        calendarCol.insert(calendarCol.end(), lines.begin(), lines.end());

        std::vector<std::vector<Line>> calendarColumn = {calendarCol};
        std::cout << render.printCalendar(calendarColumn);
    }

    void printChart(uint64_t currentPrice, double currentVolume, uint64_t timestamp, int tradeCount) {
        params.chartInterval = Parameters::KrakenInterval::M1;

        bodyCol3.push_back({"", Align::LEFT});
        bodyCol3.emplace_back("--- " + params.currentPair + " Chart: " + params.getIntervalString() + " ---", Align::CENTER);
        bodyCol3.emplace_back("", Align::LEFT);

        chart.addCandle(currentPrice, currentVolume, timestamp, tradeCount);

        std::vector<std::string> chartLines = chart.getChartLines();

        for (const auto &line : chartLines) {
            bodyCol3.push_back({line, Align::CENTER});
        }
    }

    inline void update(uint64_t currentPrice, int iterationCount, TradeType currentState, const FilledPositions &filled, const ClosedPositions &closed) {
        filledCount = fillOrderLogic.getFilledCount(filled);
        batchedCount = fillOrderLogic.getBatchedCount();
        buyCount = fillOrderLogic.getBuyCount();
        sellCount = fillOrderLogic.getSellCount();
        totalFeesPaid = fillOrderLogic.getTotalFeesPaid();
        totalVolume = fillOrderLogic.getTotalVolume();
        rollingVolume = fillOrderLogic.getRollingVolume();
        averageBuyPrice = fillOrderLogic.calculateAverageBuyPrice(params);
        averageSellPrice = fillOrderLogic.calculateAverageSellPrice(params);

        closedCount = tradeLogic.getTotalClosedOrders();
        closedLong = tradeLogic.getClosedLong();
        closedShort = tradeLogic.getClosedShort();
        stoplossLong = tradeLogic.getStopLossLong();
        stoplossShort = tradeLogic.getStopLossShort();
        totalRealizedProfit = tradeLogic.getTotalRealizedProfitUSD(currentPrice);
        profitPerOrder = tradeLogic.getProfitPerOrderUSD(currentPrice);
        btcProfit = tradeLogic.getTotalRealizedProfitBTC(currentPrice);
        usdProfit = tradeLogic.getTotalRealizedProfitUSD(currentPrice);
        unrealisedProfit = tradeLogic.calculateUnrealizedProfitBTC(currentPrice);

        globalAverage = placeNewOrders.rebalanceStats.globalAverage;
        startPrice = placeNewOrders.rebalanceStats.startPrice;
        endPrice = placeNewOrders.rebalanceStats.endPrice;
        percentReturned = placeNewOrders.rebalanceStats.percentReturned;
        gain = placeNewOrders.rebalanceStats.gain;
        targetUSDfraction = placeNewOrders.rebalanceStats.targetUSDfraction;
        targetBTCfraction = placeNewOrders.rebalanceStats.targetBTCfraction;

        deltaBuy = static_cast<int64_t>(currentPrice) - static_cast<int64_t>(averageBuyPrice);
        deltaSell = static_cast<int64_t>(currentPrice) - static_cast<int64_t>(averageSellPrice);
        percentageAboveBuy = averageBuyPrice > 0 ? (double(deltaBuy) / averageBuyPrice) * 100.0 : 0.0;
        percentageBelowSell = averageSellPrice > 0 ? (double(deltaSell) / averageSellPrice) * 100.0 : 0.0;

        // leverage
        leverage = 1.0;
        switch (params.leverage) {
        case Parameters::Leverage::TWO_X:
            leverage = 2.0;
            break;
        case Parameters::Leverage::THREE_X:
            leverage = 3.0;
            break;
        case Parameters::Leverage::FIVE_X:
            leverage = 5.0;
            break;
        default:
            break;
        }

        liquidatedBuy = tradeLogic.calculateLiquidationPrice(averageBuyPrice, leverage, true);
        liquidatedSell = tradeLogic.calculateLiquidationPrice(averageSellPrice, leverage, false);

        // fees
        currentMakerFeeRate = static_cast<double>(params.makerFeeRate / 10000.0);
        currentTakerFeeRate = static_cast<double>(params.takerFeeRate / 10000.0);

        // balances
        uint64_t usdBalance = bank.getBalance("USD");
        uint64_t btcBalance = bank.getBalance("BTC");
        usdAmount = static_cast<double>(usdBalance) / CENTS;
        btcAmount = static_cast<double>(btcBalance) / SATOSHIS;
        totalValue = usdAmount + (btcAmount * (static_cast<double>(currentPrice) / CENTS));

        time = functions.getTodayDate();
    }

    std::vector<Line> buildLeftColumn() {
        std::vector<Line> result;

        const int BODY_WIDTH = 80;

        // Three columns: 26 chars wide each, with 1-space gaps
        const int COL_WIDTH = 26;
        const int COL1_START = 0;  // 0–25
        const int COL2_START = 26; // 27–52 (1 space gap)
        const int COL3_START = 55; // 54–79 (1 space gap)

        // === Column 1 (Left): Core trend & momentum ===
        std::vector<std::string> col1 = {
            ">> Open:    " + std::to_string(params.spotOrders - filledCount),
            ">> Filled:  " + std::to_string(filledCount),
            ">> Batched: " + std::to_string(batchedCount),
            ">> Closed:  " + std::to_string(closedCount),
            ">> Profit:",
            " - Per Order: $" + functions.formatIntUSD(profitPerOrder),
            " - USD: $" + functions.formatIntUSD(usdProfit),
            " - BTC: " + functions.formatIntBTC(btcProfit),
            ">> Total Volume:",
            " - $" + functions.formatIntUSD(totalVolume),
            ">> Total Value:",
            " - $" + functions.formatDoubleUSD(totalValue),
        };

        // === Column 2 (Center): Volatility & Strength ===
        std::vector<std::string> col2 = {
            ">> Buy/Sell:   " + std::to_string(buyCount) + " / " + std::to_string(sellCount),
            ">> Long/Short: " + std::to_string(closedShort) + " / " + std::to_string(closedLong),
            ">> Stoploss:   " + std::to_string(stoplossLong) + " L / " + std::to_string(stoplossShort) + " S",
            ">> Total Fees Paid:",
            " - $" + functions.formatIntUSD(totalFeesPaid),
            ">> Fee Rate:",
            " - Maker: " + functions.formatFeeRate(currentMakerFeeRate),
            " - Taker: " + functions.formatFeeRate(currentTakerFeeRate),
            ">> 30-Day Volume:",
            " - $" + functions.formatIntUSD(rollingVolume),
            ">> BTC Value:",
            " - " + functions.formatDoubleBTC(btcAmount),
        };

        // === Column 3 (Right): Complex oscillators ===
        std::vector<std::string> col3 = {
            ">> Previous Price:",
            " - " + functions.formatDoubleUSD(startPrice),
            ">> Market Change: " + functions.formatDoubleUSD(percentReturned) + "%",
            ">> Target Allocation: ",
            " - USD: " + functions.formatDoubleUSD(targetUSDfraction * 100.0) + "%",
            " - BTC: " + functions.formatDoubleUSD(targetBTCfraction * 100.0) + "%",
            ">> Global Average Price:",
            " - $" + functions.formatIntUSD(globalAverage),
            ">> Dynamic Hedging:",
            " - Gain $" + functions.formatDoubleUSD(gain),
            ">> USD Value:",
            " - " + functions.formatDoubleUSD(usdAmount),
        };

        // === Max height across all three columns ===
        size_t maxLines = std::max({col1.size(), col2.size(), col3.size()});

        // === Build three-column lines ===
        for (size_t i = 0; i < maxLines; ++i) {
            std::string fullLine(BODY_WIDTH, ' ');

            // Column 1
            if (i < col1.size()) {
                std::string text = col1[i];
                if (text.length() > COL_WIDTH)
                    text = text.substr(0, COL_WIDTH);
                std::copy(text.begin(), text.end(), fullLine.begin() + COL1_START);
            }

            // Column 2
            if (i < col2.size()) {
                std::string text = col2[i];
                if (text.length() > COL_WIDTH)
                    text = text.substr(0, COL_WIDTH);
                std::copy(text.begin(), text.end(), fullLine.begin() + COL2_START);
            }

            // Column 3
            if (i < col3.size()) {
                std::string text = col3[i];
                if (text.length() > COL_WIDTH)
                    text = text.substr(0, COL_WIDTH);
                std::copy(text.begin(), text.end(), fullLine.begin() + COL3_START);
            }

            result.push_back({fullLine, Align::LEFT});
        }

        return result;
    }

    std::vector<Line> buildHeaderLines(uint64_t currentPrice, int iterationCount, const OpenPositions &open, const FilledPositions &filled, const ClosedPositions &closed) {

        std::vector<Line> lines;
        auto add = [&](const std::string &s) { lines.push_back(Line{s, Align::CENTER}); };

        add("Unrealised Profit: $" + functions.formatDoubleBTC(unrealisedProfit));

        add("Avg Fill (Buy): $" + functions.formatIntUSD(averageBuyPrice) + "    Avg Fill (Sell): $" + functions.formatIntUSD(averageSellPrice));

        if (averageBuyPrice > 0.0) {
            std::string statusBuy = (deltaBuy > 0) ? "ABOVE AVERAGE BUY" : "BELOW AVERAGE BUY";
            char sellSign = (deltaBuy >= 0) ? '+' : '-';
            add("Status (Buy): " + statusBuy + " (" + sellSign + functions.formatDelta(deltaBuy) + " / " + sellSign + functions.formatPercentage(percentageAboveBuy) + ")");
        } else {
            add("Status (Buy): No Orders");
        }

        if (averageSellPrice > 0.0) {
            std::string statusSell = (deltaSell < 0) ? "BELOW AVERAGE SELL" : "ABOVE AVERAGE SELL";
            char buySign = (deltaSell >= 0) ? '+' : '-';
            add("Status (Sell): " + statusSell + " (" + buySign + functions.formatDelta(deltaSell) + " / " + buySign + functions.formatPercentage(percentageBelowSell) + ")");
        } else {
            add("Status (Sell): No Orders");
        }

        if (averageBuyPrice > 0.0 && leverage > 1.0) {
            add("Entry (Buy): $" + functions.formatDoubleUSD(averageBuyPrice) + "    Limit: $" + functions.formatIntUSD(liquidatedBuy) +
                "    Leverage: " + functions.formatLeverage(leverage));
        } else {
            add("No Current Leveraved Buy Positions");
        }

        if (averageSellPrice > 0.0 && leverage > 1.0) {
            add("Entry (Sell): $" + functions.formatDoubleUSD(averageSellPrice) + "    Limit: $" + functions.formatIntUSD(liquidatedSell) +
                "    Leverage: " + functions.formatLeverage(leverage));
        } else {
            add("No Current Leveraved Sell Positions");
        }

        return lines;
    }

    std::vector<Line> buildBodyLines(const OpenPositions &open, const FilledPositions &filled, const ClosedPositions &closed) {

        std::vector<Line> lines;

        auto add = [&](const std::string &s) { lines.push_back(Line{s, Align::LEFT}); };

        // Separator helper
        auto sep = [&]() { lines.push_back(Line{functions.separatorBuffer(), Align::CENTER}); };

        // --- Closed Orders ---
        add(">> Closed Buy Orders");
        {
            std::vector<Line> summary = printCloseOrdersSummary(closed.buys, "BUY");
            lines.insert(lines.end(), summary.begin(), summary.end());
        }
        sep();

        add(">> Closed Sell Orders");
        {
            std::vector<Line> summary = printCloseOrdersSummary(closed.sells, "SELL");
            lines.insert(lines.end(), summary.begin(), summary.end());
        }
        sep();

        // --- Filled Batched Orders ---
        add(">> Filled Batched Buy Orders");
        {
            std::vector<Line> summary = printBatchedOrdersSummary(filled.batchedBuys, "BUY");
            lines.insert(lines.end(), summary.begin(), summary.end());
        }
        sep();

        add(">> Filled Batched Sell Orders");
        {
            std::vector<Line> summary = printBatchedOrdersSummary(filled.batchedSells, "SELL");
            lines.insert(lines.end(), summary.begin(), summary.end());
        }
        sep();

        // --- Filled Orders ---
        add(">> Filled Buy Orders");
        {
            std::vector<Line> summary = printOrders(filled.buys, "BUY");
            lines.insert(lines.end(), summary.begin(), summary.end());
        }
        sep();

        add(">> Filled Sell Orders");
        {
            std::vector<Line> summary = printOrders(filled.sells, "SELL");
            lines.insert(lines.end(), summary.begin(), summary.end());
        }
        sep();

        // --- Open Orders ---
        add(">> Open Buy Orders");
        {
            std::vector<Line> summary = printOrders(open.buys, "BUY");
            lines.insert(lines.end(), summary.begin(), summary.end());
        }
        sep();

        add(">> Open Sell Orders");
        {
            std::vector<Line> summary = printOrders(open.sells, "SELL");
            lines.insert(lines.end(), summary.begin(), summary.end());
        }
        sep();

        return lines;
    }

    std::vector<Line> printOrders(const std::vector<Parameters> &orders, const std::string &orderTypeLabel) {

        std::vector<Line> lines;

        auto add = [&](const std::string &s) { lines.push_back(Line{s, Align::LEFT}); };

        std::vector<Parameters> sortedOrders = orders;

        std::sort(sortedOrders.begin(), sortedOrders.end(), [](const Parameters &a, const Parameters &b) {
            if (a.closed && b.closed)
                return a.closedTime < b.closedTime;
            return a.price > b.price;
        });

        for (const auto &order : sortedOrders) {
            if (order.purpose == LadderOrderPurpose::REBALANCE)
                continue;

            std::string orderType = params.orderTypeToString(order.orderType);
            std::string purpose = params.ladderOrderPurposeToString(order.purpose);

            std::string line;
            if (order.isLiquidated) {
                line = " - " + orderTypeLabel + " LIQUIDATED-" + orderType + " " + functions.formatIntBTC(order.amount) + " BTC" + " @ $" + functions.formatIntUSD(order.price);
            } else {
                line =
                    " - " + orderTypeLabel + " " + purpose + "-" + orderType + " " + functions.formatIntBTC(order.amount) + " BTC" + " @ $" + functions.formatIntUSD(order.price);
            }

            // Optional timestamps
            if (order.purpose == LadderOrderPurpose::CLOSE && order.closedTime > 0) {
                line += functions.formatTimestamp(order.closedTime);
            } else if (order.purpose == LadderOrderPurpose::OPEN && order.filledTime > 0) {
                line += functions.formatTimestamp(order.filledTime);
            }

            // Center the line using the lambda
            add(line);
        }

        return lines; // Now returns vector<Line> instead of vector<string>
    }

    std::vector<Line> printBatchedOrdersSummary(const std::vector<Parameters> &batchedOrders, const std::string &orderTypeLabel) {

        std::vector<Line> lines;

        auto add = [&](const std::string &s) { lines.push_back(Line{s, Align::LEFT}); };

        int batchIndex = 1;

        for (const auto &batch : batchedOrders) {
            double totalAmount = batch.totalAmount;
            double avgPrice = (totalAmount > 0.0) ? static_cast<double>(batch.weightedPriceSum) / totalAmount : 0.0;

            // Build the line directly
            std::string line = " - " + orderTypeLabel + " #" + std::to_string(batchIndex) + ": Orders: " + std::to_string(batch.ordersInBatch) +
                               " Total: " + functions.formatIntBTC(totalAmount) + " BTC" + " Buy Index=" + std::to_string(batch.buyIndex);

            // Add as centered line
            add(line);

            batchIndex++;
        }

        return lines;
    }

    std::vector<Line> printCloseOrdersSummary(const std::vector<Parameters> &orders, const std::string &orderTypeLabel) {

        std::vector<Line> lines;

        auto add = [&](const std::string &s) { lines.push_back(Line{s, Align::LEFT}); };

        struct Summary {
            int count = 0;
            double totalAmount = 0.0;
            double totalPrice = 0.0;
        };

        Summary closeSummary, rebalanceSummary, batchSummary;

        for (const auto &order : orders) {
            switch (order.purpose) {
            case LadderOrderPurpose::CLOSE:
                closeSummary.count++;
                closeSummary.totalAmount += order.amount;
                closeSummary.totalPrice += order.price;
                break;
            case LadderOrderPurpose::BATCH:
                batchSummary.count++;
                batchSummary.totalAmount += order.amount;
                batchSummary.totalPrice += order.price;
                break;
            case LadderOrderPurpose::REBALANCE:
                rebalanceSummary.count++;
                rebalanceSummary.totalAmount += order.amount;
                rebalanceSummary.totalPrice += order.price;
                break;
            default:
                break;
            }
        }

        auto appendSummary = [&](const Summary &s, const std::string &label) {
            if (s.count == 0)
                return;
            std::string line = " - " + orderTypeLabel + " " + label + ": Orders: " + std::to_string(s.count) + " Total: " + functions.formatIntBTC(s.totalAmount) + " BTC";
            add(line);
        };

        appendSummary(closeSummary, "CLOSE");
        appendSummary(batchSummary, "BATCH");
        appendSummary(rebalanceSummary, "REBALANCE");

        return lines;
    }

    std::vector<Line> buildIndicatorLines() {
        std::vector<Line> result;

        const int BODY_WIDTH = 80;

        // Three columns: 26 chars wide each, with 1-space gaps
        const int COL_WIDTH = 26;
        const int COL1_START = 0;  // 0–25
        const int COL2_START = 30; // 27–52 (1 space gap)
        const int COL3_START = 57; // 54–79 (1 space gap)

        // --- Calculate all indicators ---
        double sma = ma.SMA(collector, 20);
        double ema = ma.EMA(collector, 50);
        double rsiValue = rsi.calculateRSI(collector, 14);
        double vwap = vi.calculateVWAP(collector, 1);
        auto obvVec = vi.calculateOBV(collector, 20);
        std::string obvStr = obvVec.empty() ? "N/A" : functions.formatDouble(obvVec.back());
        double atr14 = atr.calculateATR(collector, 14);
        auto MACD = macd.calculate(collector, 12, 26, 9);
        auto BB = bb.calculate(collector);
        auto stoch = so.calculate(collector, 14, 3);
        auto fib = fr.calculate(collector);
        auto ichimoku = ic.calculate(collector);
        auto adx = adi.calculate(collector, 14);

        // === Column 1 (Left): Core trend & momentum ===
        std::vector<std::string> col1 = {
            ">> SMA(20): " + functions.formatDouble(sma),
            ">> EMA(50): " + functions.formatDouble(ema),
            ">> RSI(14): " + functions.formatDouble(rsiValue),
            ">> VWAP:    " + functions.formatDouble(vwap),
            ">> OBV:     " + obvStr,
            ">> ATR(14): " + functions.formatDouble(atr14),
            "",
            ">> MACD:",
            " - Line:      " + functions.formatDouble(MACD.macdLine),
            " - Signal:    " + functions.formatDouble(MACD.signalLine),
            " - Hist:      " + functions.formatDouble(MACD.histogram),
            " - Trend: (" + MACD.trend + ")",
        };

        // === Column 2 (Center): Volatility & Strength ===
        std::vector<std::string> col2 = {
            ">> Bollinger Bands:",
            " - Middle: " + functions.formatDouble(BB.middle),
            " - Upper:  " + functions.formatDouble(BB.upper),
            " - Lower:  " + functions.formatDouble(BB.lower),
            " - Trend: (" + BB.trend + ")",
            "",
            ">> ADX:",
            " - +DI: " + functions.formatDouble(adx.plusDI),
            " - -DI: " + functions.formatDouble(adx.minusDI),
            " - ADX: " + functions.formatDouble(adx.adx),
            " - Trend: (" + adx.trendStrength + ")",
        };

        // === Column 3 (Right): Complex oscillators ===
        std::vector<std::string> col3 = {
            ">> Ichimoku Cloud:",
            " - Tenkan:   " + functions.formatDouble(ichimoku.tenkanSen),
            " - Kijun:    " + functions.formatDouble(ichimoku.kijunSen),
            " - Senkou A: " + functions.formatDouble(ichimoku.senkouSpanA),
            " - Senkou B: " + functions.formatDouble(ichimoku.senkouSpanB),
            " - Chikou:   " + functions.formatDouble(ichimoku.chikouSpan),
            " - Trend: (" + ichimoku.trend + ")",
            "",
            ">> Stochastic:",
            " - %K: " + functions.formatDouble(stoch.percentK),
            " - %D: " + functions.formatDouble(stoch.percentD),
            " - Trend: (" + stoch.trend + ")",
        };

        // === Max height across all three columns ===
        size_t maxLines = std::max({col1.size(), col2.size(), col3.size()});

        // === Header ===
        result.push_back({"", Align::LEFT});
        result.push_back({"--- Indicators ---", Align::CENTER});
        result.push_back({"", Align::LEFT});

        // === Build three-column lines ===
        for (size_t i = 0; i < maxLines; ++i) {
            std::string fullLine(BODY_WIDTH, ' ');

            // Column 1
            if (i < col1.size()) {
                std::string text = col1[i];
                if (text.length() > COL_WIDTH)
                    text = text.substr(0, COL_WIDTH);
                std::copy(text.begin(), text.end(), fullLine.begin() + COL1_START);
            }

            // Column 2
            if (i < col2.size()) {
                std::string text = col2[i];
                if (text.length() > COL_WIDTH)
                    text = text.substr(0, COL_WIDTH);
                std::copy(text.begin(), text.end(), fullLine.begin() + COL2_START);
            }

            // Column 3
            if (i < col3.size()) {
                std::string text = col3[i];
                if (text.length() > COL_WIDTH)
                    text = text.substr(0, COL_WIDTH);
                std::copy(text.begin(), text.end(), fullLine.begin() + COL3_START);
            }

            result.push_back({fullLine, Align::LEFT});
        }

        result.push_back({"", Align::LEFT}); // final spacing

        return result;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class TradeFunctions {
  public:
    TradeFunctions(Banking &bank, OutputBuffer &outputBuffer, Parameters &params, CandleCollector &collector, Render &render, bool print = true, bool tweet = true)
        : speedReporter(outputBuffer, print), params(params), collector(collector), printOutput(print), fillOrderLogic(bank, render, print, tweet),
          tradeLogic(bank, params, fillOrderLogic, render, print, tweet), clearOpenOrders(params, fillOrderLogic, render, print),
          placeNewOrders(bank, params, fillOrderLogic, tradeLogic, render, print),
          orderOutput(bank, params, fillOrderLogic, tradeLogic, placeNewOrders, collector, outputBuffer, render, print) {
        LOG_INFO("Class: TradeFunctions");
    }

    void setPrintOutput(bool value) {
        printOutput = value;
        fillOrderLogic.setPrintOutput(value);
        tradeLogic.setPrintOutput(value);
        clearOpenOrders.setPrintOutput(value);
        placeNewOrders.setPrintOutput(value);
        orderOutput.setPrintOutput(value);
    }

    void setTweetOutput(bool value) {
        params.tweetOutput = value;
        fillOrderLogic.setTweetOutput(value);
        tradeLogic.setTweetOutput(value);
    }

    inline void step_1(double currentPrice, OpenPositions &open, FilledPositions &filled) {
        LOG_INFO("Class: TradeFunctions... Running step_1");
        fillOrderLogic.updateFilledOrders(currentPrice, open, filled, params);
    }

    inline void step_2(double currentPrice, OpenPositions &open, FilledPositions &filled, ClosedPositions &closed) {
        LOG_INFO("Class: TradeFunctions... Running step_2");
        tradeLogic.placeOrderLogic(currentPrice, open, filled, closed);
    }

    inline void step_3(double currentPrice, OpenPositions &open, FilledPositions &filled) {
        LOG_INFO("Class: TradeFunctions... Running step_3");
        clearOpenOrders.remove(currentPrice, open, filled);
    }

    inline void step_4(double currentPrice, TradeType currentState, OpenPositions &open, FilledPositions &filled, const Parameters &config) {
        LOG_INFO("Class: TradeFunctions... Running step_4");
        placeNewOrders.newOrders(currentPrice, currentState, open, filled, config, collector);
    }

    inline void step_5(double currentPrice,
                       double currentVolume,
                       uint64_t timestamp,
                       int tradeCount,
                       int iterationCount,
                       TradeType currentState,
                       const OpenPositions &open,
                       FilledPositions &filled,
                       ClosedPositions &closed,
                       SpeedReporter &speedReporter) {
        LOG_INFO("Class: TradeFunctions... Running step_5");
        orderOutput.consoleOutput(currentPrice, currentVolume, timestamp, tradeCount, iterationCount, currentState, open, filled, closed, speedReporter);
    }

  private:
    Parameters params;
    CandleCollector &collector;
    bool printOutput;
    FillOrderLogic fillOrderLogic;
    TradeLogic tradeLogic;
    ClearOpenOrders clearOpenOrders;
    PlaceNewOrders placeNewOrders;
    OrderOutput orderOutput;
    SpeedReporter speedReporter;
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Trader {
  public:
    Trader(Banking &bank, Parameters &params, bool print = true, bool tweet = true)
        : bank(bank), params(params), printOutput(print), render(), outputBuffer(), rl(), loader(), collector(loader), fillOrderLogic(bank, render, print, tweet),
          speedReporter(outputBuffer, print), tradeLogic(bank, params, fillOrderLogic, render, print, tweet),
          tradeFunctions(bank, outputBuffer, params, collector, render, print, tweet), fetcher(curl), trading(false) {
        LOG_INFO("Class: Trader");
        srand(static_cast<unsigned int>(time(nullptr)));
        refreshRateMs = params.refreshRateMs;
    }

    void setPrintOutput(bool value) {
        printOutput = value;
        tradeFunctions.setPrintOutput(value);
    }

    void setTweetOutput(bool value) { tradeFunctions.setTweetOutput(value); }
    void setTrading(bool value) { trading = value; }
    void setPairSymbol(Parameters::TradingPair pair) { params.pairSymbol = pair; }
    void setOrderAmount(double amt) { params.amount = amt; }
    void setOrderType(Parameters::OrderType type) { params.orderType = type; }
    void setLeverage(Parameters::Leverage lev) { params.leverage = lev; }
    void setIncrement(int inc) { params.increment = inc; }
    void setDelayHours(int hours) { params.delayHours = hours; }
    void setSpotOrders(int spotCount) { params.spotOrders = spotCount; }
    void setRefreshRateMs(int refreshRateMs) {
        if (refreshRateMs >= 100)
            params.refreshRateMs = refreshRateMs;
    }
    void setStopLossPercent(double percent) { params.stopLossPercent = percent; }
    void setThreshold(double newThreshold) { params.threshold = newThreshold; }

    double getThreshold() const { return params.threshold; }
    double getStopLossPercent() const { return params.stopLossPercent; }
    int getRefreshRateMs() const { return params.refreshRateMs; }
    bool getTweetOutput() const { return params.tweetOutput; }

    void run() {
        LOG_INFO("Class: Trader... Running run logic");
        static bool initialized = false;
        if (!initialized) {
            initialize();
            initialized = true;
        }

        while (trading) {
            LOG_INFO("Class: Trader... Running Trading logic, iteration: " + iterationCount);
            functions.clearBodyColumns();
            functions.clearConsole();

            // Fetch latest (current incomplete candle)
            auto latest = fetcher.getOHLC("XXBTZUSD", 1, false, recentLastTs);

            double currentPriceDouble = 0.0;
            uint64_t currentPrice = 0;
            double currentVolume;
            int tradeCount;
            uint64_t timestamp;

            if (!latest.empty()) {
                const Candle &newest = latest.back();

                // Update RECENT file (for fast trading/indicators)
                if (newest.timestamp > recentLastTs) {
                    priceFile.appendCandle(fileSystem.file_1.string(), newest);
                    recentLastTs = newest.timestamp;
                }

                // Live price and volume for trading
                currentPriceDouble = newest.close;
                currentPrice = static_cast<uint64_t>(std::round(currentPriceDouble * 100.0));
                currentVolume = newest.volume;
                tradeCount = newest.count;
                timestamp = newest.timestamp;
            }

            // RL selects action
            ReinforcementLearning::ActionType action = rl.trainMarket(currentPrice);

            // convert RL action to trading engine's decision
            TradeType tradeDecision = (action == ReinforcementLearning::ActionType::Buy ? TradeType::BUY : TradeType::SELL);

            auto start1 = Clock::now();
            tradeFunctions.step_1(currentPrice, open, filled);
            auto end1 = Clock::now();

            auto start2 = Clock::now();
            tradeFunctions.step_2(currentPrice, open, filled, closed);
            auto end2 = Clock::now();

            auto start3 = Clock::now();
            tradeFunctions.step_3(currentPrice, open, filled);
            auto end3 = Clock::now();

            auto start4 = Clock::now();
            tradeFunctions.step_4(currentPrice, tradeDecision, open, filled, params);
            auto end4 = Clock::now();

            auto start5 = Clock::now();
            tradeFunctions.step_5(currentPrice, currentVolume, timestamp, tradeCount, iterationCount, tradeDecision, open, filled, closed, speedReporter);
            auto end5 = Clock::now();

            // durations (ns)
            totalStep1 += ns(end1 - start1);
            totalStep2 += ns(end2 - start2);
            totalStep3 += ns(end3 - start3);
            totalStep4 += ns(end4 - start4);
            totalStep5 += ns(end5 - start5);

            ++iterationCount;

            SpeedReporter::SpeedInfo info;
            info.avgStep1 = totalStep1 / iterationCount;
            info.avgStep2 = totalStep2 / iterationCount;
            info.avgStep3 = totalStep3 / iterationCount;
            info.avgStep4 = totalStep4 / iterationCount;
            info.avgStep5 = totalStep5 / iterationCount;
            info.totalAlgo = (totalStep1 + totalStep2 + totalStep3 + totalStep4 + totalStep5) / iterationCount;
            info.iterationCount = iterationCount;

            // This is the only place you touch the SpeedReporter now
            speedReporter.updateLatest(info);

            saveTradeState.saveOpenPositions(fileSystem.file_2.string(), filled, params);
            calendar.saveToFile(fileSystem.file_3.string());

            std::this_thread::sleep_for(std::chrono::milliseconds(refreshRateMs));
        }

        LOG_INFO("Class: Trader... Stopped Running Trading logic");
    }

  private:
    Banking &bank;
    Parameters &params;
    bool printOutput;
    OutputBuffer outputBuffer;
    SpeedReporter speedReporter;
    ReinforcementLearning rl;
    Loader loader;
    CandleCollector collector;
    FillOrderLogic fillOrderLogic;
    TradeLogic tradeLogic;
    TradeFunctions tradeFunctions;
    BinaryEntropyPool entropyPool;
    CurlClient curl;
    KrakenOHLCFetcher fetcher;
    Render render;
    CreatePriceFile priceFile;

    OpenPositions open;
    FilledPositions filled;
    ClosedPositions closed;

    using Clock = std::chrono::high_resolution_clock;

    // Accumulate total durations for each step
    long double totalStep1 = 0.0L;
    long double totalStep2 = 0.0L;
    long double totalStep3 = 0.0L;
    long double totalStep4 = 0.0L;
    long double totalStep5 = 0.0L;

    uint64_t recentLastTs = 0;
    uint64_t historyLastTs = 0;
    uint64_t iterationCount = 0;
    int refreshRateMs;
    bool trading;

    std::vector<Line> col1, col2, col3;

    TradeType currentState = TradeType::SELL;

    static long double ns(std::chrono::high_resolution_clock::duration d) { return static_cast<long double>(std::chrono::duration_cast<std::chrono::nanoseconds>(d).count()); }

    inline void initialize() {
        bank.deposit("USD", params.balanceUSD);
        bank.deposit("BTC", params.balanceBTC);
        std::string bits = entropyPool.get(32);
        params.pairSymbol = Parameters::TradingPair::BTC_GBP;

        priceFile.initializeRecentHistory(fileSystem.file_1.string(), fetcher);
        saveTradeState.loadOpenPositions(fileSystem.file_2.string(), filled, params);
        calendar.loadFromFile(fileSystem.file_3.string());
        setTweetOutput(params.tweetOutput);
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Interface_Setup {
  public:
    Interface_Setup(SetUUID &setUUID, SetMnemonic &setMnemonic) : setUUID(setUUID), setMnemonic(setMnemonic) { LOG_INFO("Class: Interface_Setup"); }

    void setup() {
        LOG_INFO("Class: Interface_Setup... Running setup logic");
        int choice = -1;
        while (choice != 0) {
            home();
            menu();

            std::cin >> choice;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            switch (choice) {
            case 1:
                LOG_INFO("Class: Interface_Setup... Menu: selected Set UUID");
                col2.push_back({"Running Set UUID Menu...", Align::LEFT});
                std::this_thread::sleep_for(std::chrono::seconds(1));
                functions.clearScreen();
                // setUUID.run();
                functions.pause();
                break;

            case 2:
                LOG_INFO("Class: Interface_Setup... Menu: selected Set Mnemonic Seed Phrase");
                col2.push_back({"Running Set Mnemonic Menu...", Align::LEFT});
                std::this_thread::sleep_for(std::chrono::seconds(1));
                functions.clearScreen();
                setMnemonic.run();
                functions.pause();
                break;

            case 0:
                LOG_INFO("Class: Interface_Setup... Menu: selected Back to Home");
                col2.push_back({"Returning to Home Page...", Align::LEFT});
                std::this_thread::sleep_for(std::chrono::seconds(1));
                break;

            default:
                LOG_INFO("Class: Interface_Setup... Menu: selected Invalid choice");
                col2.push_back({"Invalid choice. Try again", Align::LEFT});
                functions.pause();
                break;
            }
        }
    }

    void home() {
        functions.clearScreen();
        render.addEmptyLines(col2, 10);
        col2.push_back({dash, Align::LEFT});
        render.addEmptyLines(col2, 1);
        col2.push_back({"--- SETUP TERMINAL ---", Align::LEFT});
        render.addEmptyLines(col2, 1);
        col2.push_back({dash, Align::LEFT});
    }

    void menu() {
        col2.push_back({"1. Set UUID", Align::LEFT});
        col2.push_back({"2. Set Mnemonic Seed Phrase", Align::LEFT});
        col2.push_back({"0. Back to Home", Align::LEFT});
        col2.push_back({dash, Align::LEFT});
        col2.push_back({"Select an option: ", Align::LEFT});
    }

  private:
    SetUUID &setUUID;
    SetMnemonic &setMnemonic;
    Render render;

    std::string dash = std::string(80, '-');
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Interface_Trade_Settings {
  public:
    Interface_Trade_Settings(Trader &trader, Parameters &params) : trader(trader), params(params) { LOG_INFO("Class: Interface_Trade_Settings"); }

    void trade_settings() {
        int choice = -1;

        while (choice != 0) {
            functions.clearColumns();
            header();
            terminalTradeSettings();

            std::cin >> choice;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Clear input buffer

            std::vector<std::vector<Line>> columns = {col1, col2, col3};

            switch (choice) {
            case 1:
                functions.clearColumns();
                header();
                selectThreshold();
                break;
            case 2:
                functions.clearColumns();
                header();
                setStopLossPercent();
                break;
            case 3:
                functions.clearColumns();
                header();
                selectTradeType();
                break;
            case 4:
                functions.clearColumns();
                header();
                selectIncrement();
                break;
            case 5:
                functions.clearColumns();
                header();
                setDelayHours();
                break;
            case 6:
                functions.clearColumns();
                header();
                setSpotOrders();
                break;
            case 7:
                functions.clearColumns();
                header();
                setOrderAmount();
                break;
            case 8:
                functions.clearColumns();
                header();
                selectLeverage();
                break;
            case 9:
                functions.clearColumns();
                header();
                toggleTweetOutput();
                break;
            case 0:
                col2.push_back({"Returning to Trade menu...", Align::LEFT});
                std::cout << render.printColumns(columns, 80, 4);
                std::this_thread::sleep_for(std::chrono::seconds(1));
                functions.clearScreen();
                return;
            default:
                col2.push_back({"Invalid choice", Align::LEFT});
                std::cout << render.printColumns(columns, 80, 4);
                functions.pause();
                break;
            }
        }
    }

  private:
    Trader &trader;
    Parameters &params;
    Render render;

    int refreshRateMs;

    std::string dash = std::string(80, '-');

    void header() {
        render.addEmptyLines(col2, 10);
        col2.push_back({dash, Align::LEFT});
        render.addEmptyLines(col2, 1);
        col2.push_back({"--- TRADE SETTINGS TERMINAL poo face---", Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({dash, Align::LEFT});
        std::vector<std::vector<Line>> columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4);
    }

    void terminalTradeSettings() {
        col2.push_back({"1. Set Trade Threshold   (current: " + std::to_string(params.threshold) + ")", Align::LEFT});
        col2.push_back({"2. Set Stop-Loss         (current: " + std::to_string(params.stopLossPercent) + "%)", Align::LEFT});
        col2.push_back({"3. Set Buy/Sell          (current: " + params.tradeTypeToString(params.type) + ")", Align::LEFT});
        col2.push_back({"4. Set Increment         (current: " + std::to_string(params.increment) + ")", Align::LEFT});
        col2.push_back({"5. Set Delay Hours       (current: " + std::to_string(params.delayHours) + ")", Align::LEFT});
        col2.push_back({"6. Set Spot Orders       (current: " + std::to_string(params.spotOrders) + ")", Align::LEFT});
        col2.push_back({"7. Set Order Amount      (current: " + std::to_string(params.amount) + ")", Align::LEFT});
        col2.push_back({"8. Set Leverage          (current: " + params.leverageToString(params.leverage) + ")", Align::LEFT});
        col2.push_back({"9. Set Tweet Output      (current: " + std::string(trader.getTweetOutput() ? "ON" : "OFF") + ")", Align::LEFT});

        col2.push_back({"0. Back to Trade Menu", Align::LEFT});
        col2.push_back({dash, Align::CENTER});
        col2.push_back({"Select an option: ", Align::LEFT});

        col2.push_back({dash, Align::LEFT});
        std::vector<std::vector<Line>> columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4);
    }

    void toggleTweetOutput() {
        char input;

        col2.push_back({"Enable tweet output? (y/n)", Align::LEFT});
        std::vector<std::vector<Line>> columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4);

        std::cin >> input;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        bool enableTweets = (input == 'y' || input == 'Y');

        trader.setTweetOutput(enableTweets);

        col2.clear();
        col2.push_back({std::string("Tweet output is now ") + (enableTweets ? "ENABLED" : "DISABLED"), Align::LEFT});

        std::cout << render.printColumns({col1, col2, col3}, 80, 4);

        // 🔑 Only prompt for credentials if enabled
        if (enableTweets) {
            functions.pause();

            TwitterClient twitterClient;
            twitterClient.enableTwitter(fileSystem.file_twitter.string());

            col2.clear();
            col2.push_back({"Twitter credentials saved successfully.", Align::LEFT});
            std::cout << render.printColumns({col1, col2, col3}, 80, 4);
        }

        functions.pause();
    }

    void selectTradeType() {
        int typeChoice = -1;
        while (typeChoice != 0) {
            col2.push_back({"1. Buy (Long)", Align::LEFT});
            col2.push_back({"2. Sell (Short)", Align::LEFT});
            col2.push_back({"0. Back", Align::LEFT});
            col2.push_back({dash, Align::LEFT});

            std::cin >> typeChoice;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            if (typeChoice == 1) {
                params.type = TradeType::BUY;
                break;
            } else if (typeChoice == 2) {
                params.type = TradeType::SELL;
                break;
            } else if (typeChoice == 0) {
                break;
            } else {
                col2.push_back({"Invalid choice. Try again", Align::LEFT});
                functions.pause();
            }
        }
    }

    void selectThreshold() {
        double newThreshold = 0.0;
        bool validInput = false;

        while (!validInput) {
            col2.push_back({"Current Threshold: " + std::to_string(params.threshold) + "%\n", Align::LEFT});
            col2.push_back({dash, Align::CENTER});
            col2.push_back({"Enter new threshold percentage (e.g. 1.5 for 1.5%)", Align::LEFT});
            col2.push_back({"Enter 0 to cancel", Align::LEFT});
            col2.push_back({"→ ", Align::LEFT});

            std::string input;
            std::getline(std::cin, input);

            // Handle cancel
            if (input == "0") {
                col2.push_back({"Threshold change cancelled", Align::LEFT});
                functions.pause();
                return;
            }

            try {
                newThreshold = std::stod(input);

                if (newThreshold < 0.01) {
                    col2.push_back({"Threshold must be at least 0.01%", Align::LEFT});
                } else if (newThreshold > 100.0) {
                    col2.push_back({"Threshold cannot exceed 100%", Align::LEFT});
                } else {
                    validInput = true;
                }
            } catch (...) {
                col2.push_back({"Invalid input - please enter a number", Align::LEFT});
            }

            if (!validInput) {
                functions.pause();
            }
        }

        // Apply the new threshold
        trader.setThreshold(newThreshold);

        col2.push_back({"Threshold successfully updated to " + std::to_string(newThreshold) + "%", Align::LEFT});
        std::vector<std::vector<Line>> columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4);
    }

    void selectIncrement() {
        int newIncrement = 0;
        bool validInput = false;

        while (!validInput) {
            col2.push_back({"Current Increment: $" + std::to_string(params.increment), Align::LEFT});
            col2.push_back({dash, Align::CENTER});
            col2.push_back({"Enter new increment in dollars (1 to 1000)", Align::LEFT});
            col2.push_back({"Enter 0 to cancel", Align::LEFT});
            col2.push_back({"→ ", Align::LEFT});

            std::vector<std::vector<Line>> columns = {col1, col2, col3};
            std::cout << render.printColumns(columns, 80, 4);

            std::string input;
            std::getline(std::cin, input);

            // Handle cancel
            if (input == "0") {
                col2.push_back({"Increment change cancelled.", Align::LEFT});
                std::cout << render.printColumns({col1, col2, col3}, 80, 4);
                functions.pause();
                return;
            }

            try {
                newIncrement = std::stoi(input);

                if (newIncrement < 1) {
                    col2.push_back({"Increment must be at least $1", Align::LEFT});
                } else if (newIncrement > 1000) {
                    col2.push_back({"Increment cannot exceed $1000", Align::LEFT});
                } else {
                    validInput = true;
                }
            } catch (...) {
                col2.push_back({"Invalid input — please enter a whole number", Align::LEFT});
            }

            if (!validInput) {
                std::cout << render.printColumns({col1, col2, col3}, 80, 4);
                functions.pause();
                col2.clear(); // Optional: clear error messages for next loop
            }
        }

        // Apply the new increment
        trader.setIncrement(newIncrement);

        col2.push_back({"Increment successfully set to $" + std::to_string(newIncrement), Align::LEFT});
        std::cout << render.printColumns({col1, col2, col3}, 80, 4);
        functions.pause();
    }

    void setDelayHours() {
        int newDelay = 0;
        bool validInput = false;

        while (!validInput) {
            col2.push_back({"Current Delay Hours: " + std::to_string(params.delayHours), Align::LEFT});
            col2.push_back({dash, Align::CENTER});
            col2.push_back({"Enter new delay in hours (0 to 100)", Align::LEFT});
            col2.push_back({"Enter 0 to cancel", Align::LEFT});
            col2.push_back({"→ ", Align::LEFT});

            std::vector<std::vector<Line>> columns = {col1, col2, col3};
            std::cout << render.printColumns(columns, 80, 4);

            std::string input;
            std::getline(std::cin, input);

            // Handle cancel
            if (input == "0") {
                col2.push_back({"Delay hours change cancelled.", Align::LEFT});
                std::cout << render.printColumns({col1, col2, col3}, 80, 4);
                functions.pause();
                return;
            }

            try {
                newDelay = std::stoi(input);

                if (newDelay < 0) {
                    col2.push_back({"Delay cannot be negative", Align::LEFT});
                } else if (newDelay > 100) {
                    col2.push_back({"Delay cannot exceed 100 hours", Align::LEFT});
                } else {
                    validInput = true;
                }
            } catch (...) {
                col2.push_back({"Invalid input — please enter a whole number", Align::LEFT});
            }

            if (!validInput) {
                std::cout << render.printColumns({col1, col2, col3}, 80, 4);
                functions.pause();
                col2.clear(); // Clean up error messages for next attempt
            }
        }

        // Apply the change
        trader.setDelayHours(newDelay);

        col2.push_back({"Delay hours successfully set to " + std::to_string(newDelay), Align::LEFT});
        std::cout << render.printColumns({col1, col2, col3}, 80, 4);
        functions.pause();
    }

    void setSpotOrders() {
        int newSpotOrders = 0;
        bool validInput = false;

        while (!validInput) {
            col2.push_back({"Current Max Spot Orders: " + std::to_string(params.spotOrders), Align::LEFT});
            col2.push_back({dash, Align::CENTER});
            col2.push_back({"Enter new maximum spot orders (1 to 60)", Align::LEFT});
            col2.push_back({"The maximum number of orders at any one time is 60.", Align::LEFT});
            col2.push_back({"Enter 0 to cancel", Align::LEFT});
            col2.push_back({"→ ", Align::LEFT});

            std::vector<std::vector<Line>> columns = {col1, col2, col3};
            std::cout << render.printColumns(columns, 80, 4);

            std::string input;
            std::getline(std::cin, input);

            // Handle cancel
            if (input == "0") {
                col2.push_back({"Spot orders change cancelled.", Align::LEFT});
                std::cout << render.printColumns({col1, col2, col3}, 80, 4);
                functions.pause();
                return;
            }

            try {
                newSpotOrders = std::stoi(input);

                if (newSpotOrders < 1) {
                    col2.push_back({"Must be at least 1", Align::LEFT});
                } else if (newSpotOrders > 60) {
                    col2.push_back({"Cannot exceed 60", Align::LEFT});
                } else {
                    validInput = true;
                }
            } catch (...) {
                col2.push_back({"Invalid input — please enter a whole number", Align::LEFT});
            }

            if (!validInput) {
                std::cout << render.printColumns({col1, col2, col3}, 80, 4);
                functions.pause();
                col2.clear(); // Clean up error messages for next try
            }
        }

        // Apply the change
        trader.setSpotOrders(newSpotOrders);

        col2.push_back({"Max spot orders successfully set to " + std::to_string(newSpotOrders), Align::LEFT});
        std::cout << render.printColumns({col1, col2, col3}, 80, 4);
        functions.pause();
    }

    void setOrderAmount() {
        double newAmountBTC = 0.0;
        bool validInput = false;

        while (!validInput) {
            col2.push_back({"Current Order Amount: " + std::to_string(params.amount) + " BTC", Align::LEFT});
            col2.push_back({dash, Align::CENTER});
            col2.push_back({"Enter new order amount in BTC", Align::LEFT});
            col2.push_back({"Minimum: 0.0001 BTC (10,000 sats)", Align::LEFT});
            col2.push_back({"Maximum: 100 BTC", Align::LEFT});
            col2.push_back({"Enter 0 to cancel", Align::LEFT});
            col2.push_back({"→ ", Align::LEFT});

            std::vector<std::vector<Line>> columns = {col1, col2, col3};
            std::cout << render.printColumns(columns, 80, 4);

            std::string input;
            std::getline(std::cin, input);

            // Cancel
            if (input == "0") {
                col2.push_back({"Order amount change cancelled.", Align::LEFT});
                std::cout << render.printColumns({col1, col2, col3}, 80, 4);
                functions.pause();
                return;
            }

            try {
                newAmountBTC = std::stod(input);

                uint64_t amountSats = static_cast<uint64_t>(std::round(newAmountBTC * SATOSHIS)); // BTC → sats

                if (newAmountBTC <= 0.0) {
                    col2.push_back({"Amount must be positive", Align::LEFT});
                } else if (amountSats < 10000) {
                    col2.push_back({"Minimum order: 0.0001 BTC (10,000 sats)", Align::LEFT});
                } else if (newAmountBTC > 100.0) {
                    col2.push_back({"Maximum order: 100 BTC", Align::LEFT});
                } else {
                    validInput = true;
                }
            } catch (...) {
                col2.push_back({"Invalid input — please enter a number (e.g. 0.5)", Align::LEFT});
            }

            if (!validInput) {
                std::cout << render.printColumns({col1, col2, col3}, 80, 4);
                functions.pause();
                col2.clear(); // Clean error messages for next try
            }
        }

        // Apply the new amount
        trader.setOrderAmount(newAmountBTC);

        col2.push_back({"Order amount successfully set to " + std::to_string(newAmountBTC) + " BTC", Align::LEFT});
        std::cout << render.printColumns({col1, col2, col3}, 80, 4);
        functions.pause();
    }

    void selectLeverage() {
        int newLeverage = 0;
        bool validInput = false;

        while (!validInput) {
            std::string currentLev;
            switch (params.leverage) {
            case Parameters::Leverage::NONE:
                currentLev = "None (1x)";
                break;
            case Parameters::Leverage::TWO_X:
                currentLev = "2x";
                break;
            case Parameters::Leverage::THREE_X:
                currentLev = "3x";
                break;
            case Parameters::Leverage::FIVE_X:
                currentLev = "5x";
                break;
            default:
                currentLev = "Unknown";
                break;
            }

            col2.push_back({"Current Leverage: " + currentLev, Align::LEFT});
            col2.push_back({dash, Align::CENTER});
            col2.push_back({"Enter new leverage:", Align::LEFT});
            col2.push_back({"  1 → None (1x)", Align::LEFT});
            col2.push_back({"  2 → 2x", Align::LEFT});
            col2.push_back({"  3 → 3x", Align::LEFT});
            col2.push_back({"  5 → 5x", Align::LEFT});
            col2.push_back({"Enter 0 to cancel", Align::LEFT});
            col2.push_back({"→ ", Align::LEFT});

            std::vector<std::vector<Line>> columns = {col1, col2, col3};
            std::cout << render.printColumns(columns, 80, 4);

            std::string input;
            std::getline(std::cin, input);

            // Cancel
            if (input == "0") {
                col2.push_back({"Leverage change cancelled.", Align::LEFT});
                std::cout << render.printColumns({col1, col2, col3}, 80, 4);
                functions.pause();
                return;
            }

            try {
                newLeverage = std::stoi(input);

                Parameters::Leverage selectedLev;
                std::string levName;

                switch (newLeverage) {
                case 1:
                    selectedLev = Parameters::Leverage::NONE;
                    levName = "None (1x)";
                    break;
                case 2:
                    selectedLev = Parameters::Leverage::TWO_X;
                    levName = "2x";
                    break;
                case 3:
                    selectedLev = Parameters::Leverage::THREE_X;
                    levName = "3x";
                    break;
                case 5:
                    selectedLev = Parameters::Leverage::FIVE_X;
                    levName = "5x";
                    break;
                default:
                    col2.push_back({"Invalid choice — must be 1, 2, 3, or 5", Align::LEFT});
                    validInput = false;
                    continue;
                }

                params.leverage = selectedLev; // or trader.setLeverage(selectedLev) if you have a setter
                col2.push_back({"Leverage successfully set to " + levName, Align::LEFT});
                validInput = true;

            } catch (...) {
                col2.push_back({"Invalid input — please enter 1, 2, 3, or 5", Align::LEFT});
            }

            if (!validInput) {
                std::cout << render.printColumns({col1, col2, col3}, 80, 4);
                functions.pause();
                col2.clear(); // Clean error messages
            }
        }

        // Final confirmation
        std::cout << render.printColumns({col1, col2, col3}, 80, 4);
        functions.pause();
    }

    void setStopLossPercent() {
        std::cout << "=== Stop Loss Settings ===\n\n";

        // Show current stop loss percentage
        std::cout << "Current stop loss: " << trader.getStopLossPercent() << "%\n\n";

        double percent;
        std::cout << "Enter new stop loss percentage: ";
        std::cin >> percent;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        trader.setStopLossPercent(percent);

        std::cout << "\nStop loss percentage set to " << percent << "%.\n";
        std::cout << "\nPress Enter to return to settings...";
        std::cin.get(); // waits for Enter
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Interface_Trade {
  public:
    Interface_Trade(Trader &trader,
                    Parameters &params,
                    TradeFunctions &tradeFunctions,
                    Banking &bank,
                    ReinforcementLearning &rl,
                    OutputBuffer &outputBuffer,
                    const std::string &apiKey,
                    const std::string &apiSecret)
        : trader(trader), params(params), tradeFunctions(tradeFunctions), bank(bank), rl(rl), outputBuffer(outputBuffer), apiKey(apiKey), apiSecret(apiSecret) {
        LOG_INFO("Class: Interface_Trade");
    }

    ~Interface_Trade() { stopTrading(); }

    void header() {
        render.addEmptyLines(col2, 10);
        col2.push_back({dash, Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({"--- TRADE TERMINAL ---", Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({dash, Align::CENTER});
    }

    void status(bool trading) {
        col2.push_back({"Trading Status: " + std::string(trading ? "ACTIVE" : "STOPPED"), Align::LEFT});
        col2.push_back({"Exchange: " + params.currentExchange, Align::LEFT});
        col2.push_back({"Pair: " + params.currentPair, Align::LEFT});
    }

    void run() {
        LOG_INFO("Class: Interface_Trade... Running run logic");
        int choice = -1;
        while (true) {
            col2.clear();
            functions.clearConsole();

            header();
            status(trading);
            col2.push_back({dash, Align::CENTER});
            col2.push_back({"1. Start Trading", Align::LEFT});
            col2.push_back({"2. Stop Trading", Align::LEFT});
            col2.push_back({"3. Enable Output", Align::LEFT});
            col2.push_back({"4. Disable Output", Align::LEFT});
            col2.push_back({"5. Trade Settings", Align::LEFT});
            col2.push_back({"0. Back to Home Menu", Align::LEFT});
            col2.push_back({dash, Align::CENTER});
            col2.push_back({"Select an option: ", Align::LEFT});

            std::vector<std::vector<Line>> columns = {col1, col2, col3};
            std::cout << render.printColumns(columns, 80, 4);

            std::cin >> choice;

            switch (choice) {
            case 1:
                LOG_INFO("Class: Interface_Trade... Menu: selected Start Trading");
                functions.clearColumns();
                startTrading();
                break;
            case 2:
                LOG_INFO("Class: Interface_Trade... Menu: selected Stop Trading");
                functions.clearColumns();
                stopTrading();
                break;
            case 3:
                LOG_INFO("Class: Interface_Trade... Menu: selected Enable Output");
                functions.clearColumns();
                enableOutput();
                break;
            case 4:
                LOG_INFO("Class: Interface_Trade... Menu: selected Disable Output");
                functions.clearColumns();
                disableOutput();
                break;
            case 5: {
                LOG_INFO("Class: Interface_Trade... Menu: selected ui_trade_settings");
                functions.clearColumns();
                functions.clearBodyColumns();
                disableOutput();
                Interface_Trade_Settings ui_trade_settings(trader, params);
                ui_trade_settings.trade_settings();
                break;
            }
            case 0:
                LOG_INFO("Class: Interface_Trade... Menu: selected Home Page");
                col2.push_back({"Returning to Home Page...", Align::LEFT});
                columns = {col1, col2, col3};
                std::cout << render.printColumns(columns, 80, 4, 0);
                std::this_thread::sleep_for(std::chrono::seconds(1));
                return;
            default:
                LOG_INFO("Class: Interface_Trade... Menu: selected Invalid selection");
                col2.push_back({"Invalid selection.", Align::LEFT});
                columns = {col1, col2, col3};
                std::cout << render.printColumns(columns, 80, 4, 0);
                std::this_thread::sleep_for(std::chrono::seconds(1));
                break;
            }
        }
    }

  private:
    Trader &trader;
    Parameters &params;
    TradeFunctions &tradeFunctions;
    Banking &bank;
    ReinforcementLearning &rl;
    OutputBuffer &outputBuffer;

    Render render;

    std::string apiKey;    // store API key
    std::string apiSecret; // store API secret

    std::string dash = std::string(80, '-');

    bool trading;

    std::thread tradingThread;
    bool outputEnabled = true;

    void startTrading() {
        if (trading) {
            col2.push_back({"Trading already running.", Align::LEFT});
            std::vector<std::vector<Line>> columns = {col1, col2, col3};
            std::cout << render.printColumns(columns, 80, 4, 0);
            return;
        }

        trader.setTrading(true);
        trading = true;
        tradingThread = std::thread(&Trader::run, &trader);
    }

    void stopTrading() {
        if (!trading) {
            col2.push_back({"Trading is not running.", Align::LEFT});
            std::vector<std::vector<Line>> columns = {col1, col2, col3};
            std::cout << render.printColumns(columns, 80, 4, 0);
            return;
        }

        trader.setTrading(false);
        trading = false;
        if (tradingThread.joinable()) {
            tradingThread.join();
        }
    }

    void enableOutput() {
        trader.setPrintOutput(true);
        outputBuffer.setEnabled(true);
    }

    void disableOutput() {
        trader.setPrintOutput(false);
        outputBuffer.setEnabled(false);
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class ExchangeCredentials {
  public:
    ExchangeCredentials() : file(fileSystem.file_kraken) { LOG_INFO("Class: ExchangeCredentials"); }

    void createCredentials() {
        LOG_INFO("Class: ExchangeCredentials... Running createCredentials logic");
        std::string apiKey, apiSecret;

        // Clear and setup UI
        col2.clear();
        functions.clearConsole();

        // Header
        render.addEmptyLines(col2, 10);
        col2.push_back({dash, Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({"--- KRAKEN API CREDENTIALS SETUP ---", Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({dash, Align::CENTER});
        render.addEmptyLines(col2, 2);

        // Instructions
        col2.push_back({"To get your Kraken API credentials:", Align::LEFT});
        render.addEmptyLines(col2, 1);
        col2.push_back({"1. Log in to your Kraken account at https://www.kraken.com/", Align::LEFT});
        col2.push_back({"2. Navigate to: Settings > API", Align::LEFT});
        col2.push_back({"3. Click 'Generate New Key'", Align::LEFT});
        col2.push_back({"4. Set permissions (Query Funds, Create & Modify Orders, etc.)", Align::LEFT});
        col2.push_back({"5. Copy your API Key and Private Key below", Align::LEFT});
        render.addEmptyLines(col2, 2);
        col2.push_back({dash, Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({"Enter API Key: ", Align::LEFT});

        std::vector<std::vector<Line>> columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4);

        std::getline(std::cin, apiKey);

        // Clear for secret input
        col2.clear();
        functions.clearConsole();

        render.addEmptyLines(col2, 10);
        col2.push_back({dash, Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({"--- KRAKEN API CREDENTIALS SETUP ---", Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({dash, Align::CENTER});
        render.addEmptyLines(col2, 2);
        col2.push_back({"Enter API Secret (Private Key): ", Align::LEFT});

        columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4);

        std::getline(std::cin, apiSecret);

        // Save to file with nice formatting
        std::ofstream out(file, std::ios::trunc);

        // Header
        out << "################################################################################\n";
        out << "#                           KRAKEN API CREDENTIALS                             #\n";
        out << "################################################################################\n";
        out << "#                                                                              #\n";
        out << "# To get your Kraken API credentials:                                          #\n";
        out << "# 1. Log in to https://www.kraken.com/                                         #\n";
        out << "# 2. Navigate to: Settings > API                                               #\n";
        out << "# 3. Click 'Generate New Key'                                                  #\n";
        out << "# 4. Set required permissions                                                  #\n";
        out << "# 5. Copy the API Key and Private Key                                          #\n";
        out << "#                                                                              #\n";
        out << "################################################################################\n";
        out << "\n";

        // API Key
        out << "# API Key (Public Key)\n";
        out << "# Identifies your application to Kraken\n";
        out << "API_KEY=" << apiKey << "\n";
        out << "\n";

        // API Secret
        out << "# API Secret (Private Key)\n";
        out << "# Used to sign requests - Keep this SECRET!\n";
        out << "# NEVER share this key with anyone\n";
        out << "API_SECRET=" << apiSecret << "\n";
        out << "\n";

        // Footer
        out << "################################################################################\n";
        out << "#                                                                              #\n";
        out << "# SECURITY WARNING: This file contains sensitive API credentials.              #\n";
        out << "# This file is encrypted when the application is not running.                  #\n";
        out << "# Never share these credentials with anyone!                                   #\n";
        out << "#                                                                              #\n";
        out << "################################################################################\n";

        out.close();

        // Success message
        col2.clear();
        functions.clearConsole();

        render.addEmptyLines(col2, 10);
        col2.push_back({dash, Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({"--- KRAKEN API CREDENTIALS SETUP ---", Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({dash, Align::CENTER});
        render.addEmptyLines(col2, 2);
        col2.push_back({"Credentials saved successfully!", Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({"File: " + file.string(), Align::LEFT});
        col2.push_back({"This file will be encrypted when you close the application.", Align::LEFT});
        render.addEmptyLines(col2, 2);

        columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4);

        std::this_thread::sleep_for(std::chrono::seconds(3));
    }

    bool loadCredentials(std::string &apiKey, std::string &apiSecret) const {
        LOG_INFO("Class: ExchangeCredentials... Running loadCredentials logic");
        std::ifstream in(file);
        if (!in.good())
            return false;

        std::string line;
        while (std::getline(in, line)) {
            // Skip comments and empty lines
            if (line.empty() || line[0] == '#') {
                continue;
            }

            if (line.rfind("API_KEY=", 0) == 0)
                apiKey = line.substr(8);
            else if (line.rfind("API_SECRET=", 0) == 0)
                apiSecret = line.substr(11);
        }
        return !apiKey.empty() && !apiSecret.empty();
    }

  private:
    std::filesystem::path file;
    Render render;
    std::string dash = std::string(80, '-');
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Interface_Exchange {
  public:
    Interface_Exchange(Trader &trader, Parameters &params, TradeFunctions &tradeFunctions, Banking &bank, ReinforcementLearning &rl, OutputBuffer &outputBuffer)
        : trader(trader), params(params), tradeFunctions(tradeFunctions), bank(bank), rl(rl), outputBuffer(outputBuffer), loader(), collector(loader) {
        LOG_INFO("Class: Interface_Exchange");
    }

    void header() {
        render.addEmptyLines(col2, 10);
        col2.push_back({dash, Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({"--- EXCHANGE TERMINAL ---", Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({dash, Align::CENTER});
    }

    void exchange() {
        LOG_INFO("Class: Interface_Exchange... Running exchange logic");
        int choice = -1;
        while (choice != 0) {
            functions.clearColumns();
            functions.clearConsole();
            header();
            col2.push_back({"Select Exchange", Align::LEFT});
            col2.push_back({"1. Kraken", Align::LEFT});
            col2.push_back({"0. Back", Align::LEFT});
            col2.push_back({dash, Align::CENTER});
            col2.push_back({"Select an option: ", Align::LEFT});

            std::vector<std::vector<Line>> columns = {col1, col2, col3};
            std::cout << render.printColumns(columns, 80, 4);

            std::cin >> choice;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            switch (choice) {

            case 1: { // Kraken
                promptKrakenCredentials();
                int pairChoice = -1;

                while (pairChoice != 0) {
                    col2.clear();
                    functions.clearConsole();
                    header();
                    col2.push_back({"Select Currency Pair", Align::LEFT});
                    col2.push_back({"1. BTC/USD", Align::LEFT});
                    col2.push_back({"0. Back", Align::LEFT});
                    col2.push_back({dash, Align::CENTER});
                    col2.push_back({"Select an option: ", Align::LEFT});

                    columns = {col1, col2, col3};
                    std::cout << render.printColumns(columns, 80, 4);

                    std::cin >> pairChoice;
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

                    switch (pairChoice) {

                    case 1: { // BTC/USD
                        col2.clear();
                        functions.clearConsole();
                        header();
                        col2.push_back({"You selected Kraken - BTC/USD\n", Align::LEFT});

                        columns = {col1, col2, col3};
                        std::cout << render.printColumns(columns, 80, 4);

                        std::string currentExchange = "KRAKEN";
                        std::string currentPair = "BTC/USD";

                        // Update Parameters so Header and other components see it
                        params.currentExchange = currentExchange;
                        params.currentPair = currentPair;

                        auto [apiKey, apiSecret] = promptKrakenCredentials();

                        Interface_Trade ui_trade(trader, params, tradeFunctions, bank, /*functions,*/ rl, outputBuffer, apiKey, apiSecret);

                        ui_trade.run();
                        return;
                    }
                    case 0:
                        break;

                    default:
                        col2.push_back({"Invalid choice. Try again.\n", Align::LEFT});

                        columns = {col1, col2, col3};
                        std::cout << render.printColumns(columns, 80, 4);

                        functions.pause();
                        break;
                    }
                }

                break;
            }

            case 0:
                return;

            default:
                col2.push_back({"Invalid choice. Try again.", Align::LEFT});

                columns = {col1, col2, col3};
                std::cout << render.printColumns(columns, 80, 4);

                functions.pause();
                break;
            }
        }
    }

  private:
    Trader &trader;
    Parameters &params;
    TradeFunctions &tradeFunctions;
    Banking &bank;
    ReinforcementLearning &rl;
    OutputBuffer &outputBuffer;
    Loader loader;
    CandleCollector collector;
    Render render;

    std::string dash = std::string(80, '-');

    std::pair<std::string, std::string> promptKrakenCredentials() {
        LOG_INFO("Class: Interface_Exchange... Running promptKrakenCredentials logic");

        ExchangeCredentials kraken;
        std::string apiKey, apiSecret;

        // Single source of truth: can we LOAD valid credentials?
        if (!kraken.loadCredentials(apiKey, apiSecret)) {
            kraken.createCredentials();

            // Try again after creation
            if (!kraken.loadCredentials(apiKey, apiSecret)) {
                functions.clearColumns();
                functions.clearConsole();
                header();
                col2.push_back({"Failed to load Kraken credentials after creation.", Align::LEFT});

                std::vector<std::vector<Line>> columns = {col1, col2, col3};
                std::cout << render.printColumns(columns, 80, 4);

                std::this_thread::sleep_for(std::chrono::seconds(5));
                return {"", ""};
            }
        }

        return {apiKey, apiSecret};
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Interface_Home {
  public:
    Interface_Home(Trader &trader,
                   Parameters &params,
                   TradeFunctions &tradeFunctions,
                   Banking &bank,
                   ReinforcementLearning &rl,
                   Blockchain &blockchain,
                   Wallet &wallet,
                   SetUUID &setUUID,
                   SetMnemonic &setMnemonic,
                   OrderOutput &orderOutput,
                   OutputBuffer &outputBuffer)
        : trader(trader), params(params), tradeFunctions(tradeFunctions), bank(bank), rl(rl), blockchain(blockchain), wallet(wallet), setUUID(setUUID), setMnemonic(setMnemonic),
          orderOutput(orderOutput), outputBuffer(outputBuffer) {
        LOG_INFO("Class: Interface_Home");
    }

    void header() {
        render.addEmptyLines(col2, 10);
        col2.push_back({dash, Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({"--- HOME TERMINAL ---", Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({dash, Align::CENTER});
    }

    void home() {
        LOG_INFO("Class: Interface_Home... Running home menu");
        int choice = -1;

        while (choice != 0) {
            col2.clear();
            functions.clearConsole();
            header();
            col2.push_back({"1. Setup", Align::LEFT});
            col2.push_back({"2. Trade", Align::LEFT});
            col2.push_back({"3. Blockchain", Align::LEFT});
            col2.push_back({"0. Exit", Align::LEFT});
            col2.push_back({dash, Align::CENTER});
            col2.push_back({"Select an option: ", Align::LEFT});

            std::vector<std::vector<Line>> columns = {col1, col2, col3};
            std::cout << render.printColumns(columns, 80, 4, 0);

            std::cin >> choice;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            switch (choice) {
            case 1: {
                LOG_INFO("Class: Interface_Home... Menu: selected Setup");
                Interface_Setup setup(setUUID, setMnemonic);
                setup.setup();
                break;
            }
            case 2: {
                LOG_INFO("Class: Interface_Home... Menu: selected Trade");
                functions.clearScreen();

                Interface_Exchange ui_exchange(trader, params, tradeFunctions, bank, rl, /*functions,*/ outputBuffer);

                ui_exchange.exchange();
                break;
            }
            case 3: {
                LOG_INFO("Class: Interface_Home... Menu: selected Blockchain");
                functions.clearScreen();
                Interface_Blockchain ui_blockchain(blockchain, wallet);
                ui_blockchain.run();
                functions.pause();
                break;
            }
            case 0: {
                LOG_INFO("Class: Interface_Home... Menu: selected Exit");
                std::vector<Line> col1, col2, col3;
                col2.push_back({"Goodbye!", Align::LEFT});
                std::vector<std::vector<Line>> columns = {col1, col2, col3};
                std::cout << render.printColumns(columns, 80, 4, 0);
                return;
            }
            default: {
                LOG_INFO("Class: Interface_Home... Menu: selected Invalid choice");
                std::vector<Line> col1, col2, col3;
                col2.push_back({"Invalid choice. Try again.", Align::LEFT});
                std::vector<std::vector<Line>> columns = {col1, col2, col3};
                std::cout << render.printColumns(columns, 80, 4, 0);
                functions.pause();
                break;
            }
            }
        }
    }

  private:
    Trader &trader;
    Parameters &params;
    TradeFunctions &tradeFunctions;
    Banking &bank;
    ReinforcementLearning &rl;
    Blockchain &blockchain;
    OrderOutput &orderOutput;
    Wallet &wallet;
    SetUUID &setUUID;
    SetMnemonic &setMnemonic;
    OutputBuffer &outputBuffer;
    Render render;

    std::string dash = std::string(80, '-');
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

/*
class PasswordAuthentication {
public:
    PasswordAuthentication()
        : passwordFile(file_password_hash.string()) {
        LOG_INFO("Class: PasswordAuthentication");
    }

    bool passwordExists() const {
        std::ifstream f(passwordFile);
        return f.good();
    }

    void createPassword() {
        std::string pass1, pass2;

        col2.clear();
        functions.clearConsole();
        header();
        col2.push_back({"Create a password to secure this action.", Align::CENTER});

        print();

        std::getline(std::cin, pass1);

        col2.clear();
        functions.clearConsole();
        header();
        col2.push_back({"Confirm password:", Align::CENTER});

        print();

        std::getline(std::cin, pass2);

        if (pass1 != pass2) {
            error("Passwords do not match.");
            return createPassword();
        }

        std::string hash = sha256(pass1);
        std::ofstream out(passwordFile);
        out << hash;
        out.close();

        success("Password created successfully.");
    }

    template<typename SecuredAction>
    void authenticate(SecuredAction toSecuredClass) {
        if (!passwordExists()) {
            createPassword();
        }

        while (true) {
            col2.clear();
            functions.clearConsole();
            header();
            col2.push_back({"Enter password:", Align::CENTER});
            print();

            std::string input;
            std::getline(std::cin, input);

            if (sha256(input) == loadStoredHash()) {
                success("Access granted.");
                toSecuredClass();   // 🔐 EXECUTE SECURED LOGIC
                return;
            }

            error("Incorrect password. Try again.");
        }
    }

private:
    std::string passwordFile;
    Render render;
    std::string dash = std::string(80, '-');

    void header() {
        render.addEmptyLines(col2, 10);
        col2.push_back({dash, Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({"--- PASSWORD VERIFICATION ---", Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({dash, Align::CENTER});
    }

    void print() {
        std::vector<std::vector<Line>> columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4);
    }

    std::string loadStoredHash() const {
        std::ifstream in(passwordFile);
        std::string hash;
        std::getline(in, hash);
        return hash;
    }

    void error(const std::string& msg) {
        col2.clear();
        functions.clearConsole();
        header();
        col2.push_back({msg, Align::CENTER});
        print();
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    void success(const std::string& msg) {
        col2.clear();
        functions.clearConsole();
        header();
        col2.push_back({msg, Align::CENTER});
        print();
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Authentication {
  public:
    Authentication(FileStorage &fs) : credentialsFile(file_auth.string()), fileStorage(fs) {} // Convert path to string

    bool credentialsExist() const {
        std::ifstream file(credentialsFile);
        bool exists = file.good();
        return exists && fs::exists(file_salt); // file_salt is already fs::path, this is fine
    }

    void header() {
        render.addEmptyLines(col2, 10);
        col2.push_back({dash, Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({"--- LOGIN TERMINAL ---", Align::CENTER});
        render.addEmptyLines(col2, 1);
        col2.push_back({dash, Align::CENTER});
    }

    bool createCredentials() {
        LOG_INFO("Class: FlowState... Running createCredentials logic");
        std::string pass1, pass2;

        col2.clear();
        functions.clearConsole();
        header();
        col2.push_back({"Create a password to secure the application.", Align::CENTER});
        std::vector<std::vector<Line>> columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4, 0);

        std::getline(std::cin, pass1);

        col2.clear();
        functions.clearConsole();
        header();
        col2.push_back({"Confirm password: \n", Align::CENTER});
        columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4, 0);

        std::getline(std::cin, pass2);

        if (pass1 != pass2) {
            functions.clearConsole();
            header();
            col2.push_back({"Passwords do not match.\n", Align::CENTER});

            columns = {col1, col2, col3};
            std::cout << render.printColumns(columns, 80, 4, 0);
            return false;
        }

        // Hash password for authentication
        std::string hash = sha256(pass1);
        std::ofstream out(credentialsFile);
        out << hash;
        out.close();

        // Initialize master key from password
        fileStorage.initializeMasterKeyFromPassword(pass1, true);

        col2.clear();
        functions.clearConsole();
        header();
        col2.push_back({"Password created successfully!\n", Align::CENTER});
        columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4, 0);

        // Wait for a second or two, or three...
        std::this_thread::sleep_for(std::chrono::seconds(5));

        return true;
    }

    bool verifyCredentials() {
        LOG_INFO("Class: Authentication... Running verifyCredentials logic");
        std::ifstream in(credentialsFile);
        std::string storedHash;
        std::getline(in, storedHash);
        in.close();

        col2.clear();
        functions.clearConsole();
        header();
        col2.push_back({"Please enter your password.", Align::CENTER});

        std::vector<std::vector<Line>> columns = {col1, col2, col3};
        std::cout << render.printColumns(columns, 80, 4);

        std::string input;
        std::getline(std::cin, input);

        std::string inputHash = sha256(input);

        if (inputHash == storedHash) {
            // Initialize master key from password
            fileStorage.initializeMasterKeyFromPassword(input, false);
            return true;
        }

        return false;
    }

  private:
    std::string credentialsFile; // Store as string
    FileStorage &fileStorage;
    Render render;

    std::string dash = std::string(80, '-');
};
*/

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class MnemonicAuthentication {
  public:
    explicit MnemonicAuthentication(FileStorage &fileSystem) : fileStorage(fileSystem), mnemonicHashFile("file_mnem") {}

    bool mnemonicExists() const { return std::ifstream(mnemonicHashFile).good(); }

    bool createMnemonic() {
        LOG_INFO("MnemonicAuthentication: Creating mnemonic");

        SetMnemonic setup;
        setup.run();

        std::string mnemonic = setup.getMnemonicString();
        std::string hash = sha256(mnemonic);

        std::ofstream out(mnemonicHashFile, std::ios::trunc);
        out << hash;
        out.close();

        fileStorage.initializeMasterKeyFromPassword(mnemonic, true);
        return true;
    }

    bool verifyMnemonic() {
        LOG_INFO("MnemonicAuthentication: Verifying mnemonic");

        std::ifstream in(mnemonicHashFile);
        std::string storedHash;
        std::getline(in, storedHash);
        in.close();

        std::string mnemonic = promptForMnemonic();
        std::string inputHash = sha256(mnemonic);

        if (inputHash != storedHash)
            return false;

        fileStorage.initializeMasterKeyFromPassword(mnemonic, false);
        return true;
    }

  private:
    FileStorage &fileStorage;
    std::string mnemonicHashFile;
    Render render;

    std::string promptForMnemonic() {
        col2.clear();
        functions.clearConsole();

        render.addEmptyLines(col2, 10);
        col2.push_back({"--- MNEMONIC LOGIN ---", Align::CENTER});
        col2.push_back({"Enter your 12-word recovery phrase:", Align::CENTER});

        std::cout << render.printColumns({col1, col2, col3}, 80, 4);

        std::string input;
        std::getline(std::cin, input);

        return normalizeMnemonic(input);
    }

    std::string normalizeMnemonic(const std::string &input) {
        std::stringstream ss(input);
        std::string word, result;

        while (ss >> word) {
            std::transform(word.begin(), word.end(), word.begin(), ::tolower);
            result += word; // ← NO SPACES
        }
        return result;
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class Interface_Login {
  public:
    Interface_Login(Interface_Home &home) : fileStorage(), auth(fileStorage), ui_home(home) { LOG_INFO("Class: Interface_Login"); }

    void run() {
        splash();

        if (!auth.mnemonicExists()) {
            auth.createMnemonic();
        }

        while (!auth.verifyMnemonic()) {
            errorScreen();
        }

        successScreen();

        fileStorage.decryptAppFiles();
        ui_home.home();
    }

    void shutdown() {
        fileStorage.encryptAppFiles();
        fileStorage.clearMasterKey();
    }

  private:
    FileStorage fileStorage;
    MnemonicAuthentication auth;
    Interface_Home &ui_home;
    Render render;

    std::string dash = std::string(80, '-');

    void splash() {
        col2.clear();
        functions.clearConsole();
        render.addEmptyLines(col2, 10);
        col2.push_back({dash, Align::CENTER});
        col2.push_back({"--- LOGIN TERMINAL ---", Align::CENTER});
        col2.push_back({dash, Align::CENTER});
        std::cout << render.printColumns({col1, col2, col3}, 80, 4);
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    void errorScreen() {
        col2.clear();
        functions.clearConsole();
        col2.push_back({"Incorrect mnemonic. Try again.", Align::CENTER});
        std::cout << render.printColumns({col1, col2, col3}, 80, 4);
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    void successScreen() {
        col2.clear();
        functions.clearConsole();
        col2.push_back({"Access granted.", Align::CENTER});
        std::cout << render.printColumns({col1, col2, col3}, 80, 4);
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

class FlowState {
  public:
    FlowState()
        : accounting(), bank(accounting), params(), rl(), outputBuffer(), render(), loader(), collector(loader),
          tradeFunctions(bank, outputBuffer, params, collector, render, true, true), setUUID(), setMnemonic(), wallet(), blockchain(wallet, false),
          trader(bank, params, true, true), fillOrderLogic(bank, render, true, true), tradeLogic(bank, params, fillOrderLogic, render, true, true),
          placeNewOrders(bank, params, fillOrderLogic, tradeLogic, render, true),
          orderOutput(bank, params, fillOrderLogic, tradeLogic, placeNewOrders, collector, outputBuffer, render, true), speedReporter(outputBuffer, true),
          ui_home(trader, params, tradeFunctions, bank, rl, blockchain, wallet, setUUID, setMnemonic, orderOutput, outputBuffer), ui_login(ui_home) {

        LOG_INFO("Class: FlowState");
    }

    void run() {
        LOG_INFO("Class: FlowState... Running UI logic");
        ui_login.run();
    }

  private:
    Accounting accounting;
    Banking bank;
    Parameters params;
    ReinforcementLearning rl;
    OutputBuffer outputBuffer;
    Loader loader;
    CandleCollector collector;
    TradeFunctions tradeFunctions;
    SetUUID setUUID;
    SetMnemonic setMnemonic;
    Wallet wallet;
    Blockchain blockchain;
    Trader trader;
    FillOrderLogic fillOrderLogic;
    TradeLogic tradeLogic;
    PlaceNewOrders placeNewOrders;
    OrderOutput orderOutput;
    SpeedReporter speedReporter;
    Interface_Home ui_home;
    Interface_Login ui_login;
    Render render;
};

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------

int main() {
    // Setup directory for all program files
    fileSystem.initialize();

    // User choice to run debugger
    logger.runDebugger();

    enableANSI();
    FileStorage storage;
    FlowState flowState;

    LOG_INFO("Program started - entering main logic...");

    // Running main program logic...
    flowState.run();

    LOG_INFO("Program finished - waiting to exit...");

    std::cout << "\nPress Enter to exit...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();

    // Re-encrypt (uses same master key, no password prompt)
    storage.encryptAppFiles();

    // Clear master key from memory on exit
    storage.clearMasterKey();

    std::cout << "\nGoodbye!";

    // Wait for a second or two, or three...
    std::this_thread::sleep_for(std::chrono::seconds(3));

    return 0;
}

//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
