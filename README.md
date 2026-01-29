# 🧵 Jacquard's Loom

**An Open-Source Automated Cryptocurrency Trading Application**

![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)
![C++](https://img.shields.io/badge/C%2B%2B-17%2B-orange.svg)

> ⚠️ **UNDER CONSTRUCTION** - This project is in active development and not production-ready.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Security Model](#security-model)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [API Integration](#api-integration)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## 🎯 Overview

**Jacquard's Loom** is a sophisticated cryptocurrency trading platform written in modern C++. Named after the revolutionary Jacquard loom that automated weaving patterns, this application weaves together multiple technologies to automate cryptocurrency trading strategies.

The platform features:
- **Algorithmic Trading** with reinforcement learning capabilities
- **Multi-Exchange Support** (Binance, Coinbase, Kraken, and more)
- **BIP-39 Mnemonic Authentication** for secure wallet recovery
- **Encrypted File Storage** using custom AES-256 implementation
- **Real-time Market Data** analysis and candlestick pattern recognition
- **Advanced Order Management** with multiple order types
- **Blockchain Integration** for on-chain wallet management

---

## ✨ Features

### Core Trading Capabilities
- **Multi-Exchange Trading**: Support for major cryptocurrency exchanges
  - Binance (Spot & Futures)
  - Coinbase Pro
  - Kraken
  - Bitfinex
  - And more...

- **Order Types**:
  - Market Orders
  - Limit Orders
  - Stop-Loss Orders
  - Trailing Stop Orders
  - OCO (One-Cancels-Other) Orders
  - Iceberg Orders

- **Technical Analysis**:
  - Real-time candlestick data collection
  - Multiple timeframe analysis (1m, 5m, 15m, 1h, 4h, 1d)
  - Pattern recognition
  - Volume analysis
  - Price action indicators

### Machine Learning & AI
- **Reinforcement Learning Engine**:
  - Q-Learning implementation
  - State-space modeling
  - Adaptive strategy optimization
  - Performance tracking and learning

### Security Features
- **BIP-39 Mnemonic System**:
  - 12-word recovery phrases (2048-word dictionary)
  - Deterministic wallet generation
  - Secure entropy collection

- **Encryption**:
  - AES-256 file encryption
  - Custom cryptographic primitives (educational implementation)
  - SHA-256 and HMAC for integrity
  - PBKDF2-based key derivation
  - Master key protection

- **Authentication**:
  - Mnemonic-based login system
  - Automatic file encryption on exit
  - Memory clearing for sensitive data

### Blockchain Integration
- **HD Wallet Support**:
  - Hierarchical Deterministic wallet generation
  - Multiple address derivation
  - Bitcoin address generation (P2PKH, P2SH, Bech32)
  - Balance tracking

- **Transaction Management**:
  - UTXO tracking
  - Transaction building and signing
  - Fee estimation
  - Blockchain explorers integration

### User Interface
- **Terminal-based UI**:
  - ANSI color support
  - Multi-column layouts
  - Real-time updates
  - Interactive menus
  - Progress indicators and loaders

- **Data Visualization**:
  - Candlestick charts (ASCII-based)
  - Portfolio performance metrics
  - Order book visualization
  - Trade history display

### Performance & Monitoring
- **Metrics Tracking**:
  - Loop speed monitoring
  - API latency tracking
  - Memory usage reporting
  - Trade performance analytics

- **Logging System**:
  - Multi-level logging (DEBUG, INFO, WARNING, ERROR)
  - File-based log persistence
  - Console output with color coding
  - Timestamp tracking

### Banking & Accounting
- **Portfolio Management**:
  - Multi-currency balance tracking
  - Profit/loss calculation
  - Transaction history
  - Position sizing

- **Risk Management**:
  - Configurable position limits
  - Stop-loss automation
  - Portfolio diversification tracking

---

## 🏗️ Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Jacquard's Loom                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Security   │  │   Trading    │  │  Blockchain  │     │
│  │   System     │  │   Engine     │  │  Integration │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│         │                  │                  │            │
│         ├─ Mnemonic Auth   ├─ Order Mgmt     ├─ Wallet    │
│         ├─ Encryption      ├─ Market Data    ├─ Tx Builder│
│         └─ Key Derivation  ├─ RL Engine      └─ UTXO Pool │
│                            └─ Multi-Exchange               │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Infrastructure Layer                    │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │  Logging │ File I/O │ HTTP Client │ JSON Parser     │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Key Classes

- **FlowState**: Main application orchestrator
- **Interface_Login**: Mnemonic-based authentication UI
- **Interface_Home**: Main trading interface and menu system
- **Trader**: Core trading logic and strategy execution
- **Banking**: Portfolio and balance management
- **Blockchain**: Blockchain interaction and wallet management
- **ReinforcementLearning**: Q-learning engine for strategy optimization
- **CandleCollector**: Market data aggregation
- **FileStorage**: Encrypted file persistence
- **MnemonicAuthentication**: BIP-39 implementation

---

## 🔐 Security Model

### ⚠️ CRITICAL SECURITY NOTICE

**This implementation contains custom cryptographic code for EDUCATIONAL PURPOSES ONLY.**

The following primitives have been re-implemented from scratch:
- AES-256 (Advanced Encryption Standard)
- SHA-256 (Secure Hash Algorithm)
- HMAC (Hash-based Message Authentication Code)
- PBKDF (Password-Based Key Derivation Function)

### Why This Matters

**DO NOT USE THIS FOR PRODUCTION/REAL FUNDS:**

1. **Not Audited**: These implementations have not undergone professional security audits
2. **No Side-Channel Protection**: Vulnerable to timing attacks and other side-channel exploits
3. **Educational Code**: Designed for learning, not battlefield-hardened security
4. **Potential Vulnerabilities**: May contain undiscovered bugs or weaknesses

### For Production Use

Use industry-standard, audited libraries:
- **OpenSSL** (already partially integrated)
- **libsodium**
- **Bouncy Castle**
- **Crypto++ (Crypto Plus Plus)**

### Security Features (Current Implementation)

- **BIP-39 Mnemonic**: Uses the standard 2048-word English dictionary
- **File Encryption**: AES-256 for all sensitive data at rest
- **Key Derivation**: PBKDF2-style key stretching
- **Memory Protection**: Explicit clearing of sensitive data
- **Auto-Encryption**: Files automatically encrypted on application exit

---

## 📦 Prerequisites

### System Requirements
- **OS**: Windows (ANSI terminal support required)
- **Compiler**: C++17 or later (MSVC, MinGW, or Clang)
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 1GB for application and data files

### Required Libraries

1. **libcurl** - HTTP client for API requests
   ```bash
   # Using vcpkg (recommended)
   vcpkg install curl
   ```

2. **nlohmann/json** - JSON parsing
   ```bash
   vcpkg install nlohmann-json
   ```

3. **OpenSSL** - Cryptographic functions (for API auth)
   ```bash
   vcpkg install openssl
   ```

4. **C++ Standard Library** - C++17 filesystem support

### Development Tools
- CMake 3.15+ (optional, for build automation)
- Git (for version control)
- Visual Studio 2019+ or compatible compiler

---

## 🚀 Installation

### Option 1: Build from Source

```bash
# Clone the repository
git clone https://github.com/oiko-nomikos/Jacquards-Loom.git
cd Jacquards-Loom

# Install dependencies (using vcpkg)
vcpkg install curl nlohmann-json openssl

# Compile
g++ -std=c++17 latest_edition.cpp \
    -o jacquards_loom \
    -lcurl \
    -lssl \
    -lcrypto \
    -lpthread \
    -I/path/to/vcpkg/installed/x64-windows/include \
    -L/path/to/vcpkg/installed/x64-windows/lib
```

### Option 2: Using CMake (if configured)

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

### Verify Installation

```bash
./jacquards_loom
```

You should see the login terminal splash screen.

---

## 💻 Usage

### First Run

1. **Launch the application**:
   ```bash
   ./jacquards_loom
   ```

2. **Mnemonic Creation**: On first launch, the system will generate a 12-word recovery phrase
   - **CRITICAL**: Write down your mnemonic phrase and store it securely
   - This phrase is your ONLY way to recover access to the application
   - Loss of the mnemonic means permanent loss of access

3. **Login**: Enter your 12-word mnemonic (spaces are optional)

4. **Main Menu**: Navigate through the interface using the menu system

### Basic Workflow

```
Launch → Authenticate → Main Menu
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   Trading Menu      Blockchain Menu    Settings Menu
        │                  │                  │
   Start/Stop        View Wallet         API Keys
   View Orders       Transactions        Parameters
   Strategies        Addresses           Preferences
```

### Running the Trader

1. Navigate to **Trading Menu**
2. Select **Start Automated Trading**
3. Configure trading parameters:
   - Trading pairs (e.g., BTC/USD, ETH/USD)
   - Position sizes
   - Risk limits
   - Strategy selection

4. Monitor performance through:
   - Real-time order updates
   - Portfolio balance changes
   - Trade history logs

### Blockchain Operations

1. Navigate to **Blockchain Menu**
2. Options include:
   - Generate new addresses
   - View wallet balances
   - Track UTXOs
   - Build and sign transactions

---

## ⚙️ Configuration

### Configuration Files

The application creates several files in the program directory:

```
Jacquards-Loom/
├── mnemonic_hash.enc          # Encrypted authentication hash
├── qtable.csv                 # Reinforcement learning Q-table
├── loop_layout.txt            # Trading loop configuration
├── debug.log                  # Application logs
└── [user_data]/              # Encrypted user files
    ├── wallet_data.enc
    ├── trade_history.enc
    └── api_keys.enc
```

### API Configuration

To enable exchange trading:

1. Navigate to **Settings → API Keys**
2. Enter credentials for each exchange:
   - API Key
   - API Secret
   - Passphrase (if required)
3. Test connection before trading

### Supported Exchanges

| Exchange | Spot Trading | Futures | WebSocket |
|----------|-------------|---------|-----------|
| Binance | ✅ | ✅ | ✅ |
| Coinbase Pro | ✅ | ❌ | ✅ |
| Kraken | ✅ | ✅ | ✅ |
| Bitfinex | ✅ | ✅ | ✅ |
| Bybit | ✅ | ✅ | ✅ |
| OKX | ✅ | ✅ | ✅ |

### Trading Parameters

Key configurable parameters:

```cpp
// Risk Management
maxPositionSize = 0.1;        // 10% of portfolio per trade
stopLossPercent = 0.02;       // 2% stop loss
takeProfitPercent = 0.05;     // 5% take profit

// Strategy
tradingMode = "RL";           // Reinforcement Learning
timeframe = "1h";             // 1-hour candles
lookbackPeriod = 100;         // Historical candles to analyze

// Execution
orderType = "LIMIT";          // Limit orders by default
slippage = 0.001;            // 0.1% max slippage
```

---

## 🔌 API Integration

### Exchange API Setup

Each exchange requires slightly different authentication:

#### Binance
```cpp
exchange = "BINANCE";
apiKey = "your_api_key";
apiSecret = "your_api_secret";
baseURL = "https://api.binance.com";
```

#### Coinbase Pro
```cpp
exchange = "COINBASE";
apiKey = "your_api_key";
apiSecret = "your_api_secret";
passphrase = "your_passphrase";
baseURL = "https://api.pro.coinbase.com";
```

### API Endpoints Used

- **Market Data**: `/api/v3/ticker/price`, `/api/v3/klines`
- **Account**: `/api/v3/account`
- **Orders**: `/api/v3/order`, `/api/v3/openOrders`
- **WebSocket**: Real-time market data streams

### Rate Limits

The application implements rate limiting to comply with exchange restrictions:
- Binance: 1200 requests/minute
- Coinbase: 10 requests/second public, 5 requests/second private
- Kraken: 15-20 requests/second (tier dependent)

---

## 📁 Project Structure

```
latest_edition.cpp (13,066 lines)
├── Headers & Includes (Lines 1-156)
│   ├── Standard Library
│   ├── Networking (libcurl)
│   ├── JSON (nlohmann)
│   └── Cryptography (OpenSSL)
│
├── Core Utilities (Lines 157-2500)
│   ├── ANSI Terminal Support
│   ├── Logging System
│   ├── File System Abstraction
│   ├── Render Engine (UI Components)
│   └── Utility Functions
│
├── Cryptography Layer (Lines 2501-5000)
│   ├── AES-256 Implementation
│   ├── SHA-256 Hashing
│   ├── HMAC
│   ├── PBKDF Key Derivation
│   ├── BIP-39 Mnemonic (2048 words)
│   └── File Encryption/Decryption
│
├── Blockchain System (Lines 5001-7500)
│   ├── Wallet Management
│   ├── HD Key Derivation (BIP-32/44)
│   ├── Address Generation
│   ├── UTXO Management
│   ├── Transaction Building
│   └── Blockchain API Integration
│
├── Trading Engine (Lines 7501-10000)
│   ├── Exchange Connectors
│   ├── Order Management
│   ├── Market Data Collection
│   ├── Candlestick Analysis
│   ├── Technical Indicators
│   └── Risk Management
│
├── Machine Learning (Lines 10001-11000)
│   ├── Q-Learning Implementation
│   ├── State Space Modeling
│   ├── Reward Functions
│   └── Strategy Optimization
│
├── Banking & Accounting (Lines 11001-12000)
│   ├── Portfolio Management
│   ├── Balance Tracking
│   ├── Transaction History
│   └── P&L Calculation
│
└── User Interface (Lines 12001-13066)
    ├── Login System
    ├── Main Menu
    ├── Trading Interface
    ├── Blockchain Interface
    └── Settings & Configuration
```

---

## 🗺️ Roadmap

### Version 0.2.0 (Q2 2026)
- [ ] Web-based dashboard (React frontend)
- [ ] RESTful API for external integrations
- [ ] Backtesting engine with historical data
- [ ] Advanced charting and visualization
- [ ] Multi-user support

### Version 0.3.0 (Q3 2026)
- [ ] Machine learning model improvements
- [ ] Sentiment analysis integration
- [ ] Telegram/Discord bot notifications
- [ ] Portfolio optimization algorithms
- [ ] Tax reporting features

### Version 1.0.0 (Q4 2026)
- [ ] Production-ready security audit
- [ ] Replace custom crypto with OpenSSL fully
- [ ] Linux and macOS support
- [ ] Docker containerization
- [ ] Comprehensive documentation
- [ ] Unit and integration tests (90%+ coverage)

### Future Considerations
- DeFi protocol integration (Uniswap, Aave)
- Options and derivatives trading
- Arbitrage detection and execution
- Social trading / copy trading features
- Mobile app (iOS/Android)

---

## 🤝 Contributing

Contributions are welcome! This project is open source and community-driven.

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/AmazingFeature`
3. **Commit your changes**: `git commit -m 'Add some AmazingFeature'`
4. **Push to the branch**: `git push origin feature/AmazingFeature`
5. **Open a Pull Request**

### Development Guidelines

- Follow existing code style (see `.clang-format`)
- Add comments for complex logic
- Update documentation for new features
- Test thoroughly before submitting PR

### Areas for Contribution

- **Security**: Help audit and improve cryptographic implementations
- **Testing**: Write unit tests and integration tests
- **Documentation**: Improve README, add code comments, create tutorials
- **Features**: Implement items from the roadmap
- **Bug Fixes**: Identify and fix issues
- **Optimization**: Improve performance and reduce latency

### Reporting Issues

Found a bug? Have a feature request?

1. Check existing issues first
2. Create a new issue with:
   - Clear description
   - Steps to reproduce (for bugs)
   - Expected vs actual behavior
   - System information
   - Relevant logs

---

## ⚠️ Disclaimer

### Financial Risk Warning

**CRYPTOCURRENCY TRADING CARRIES SUBSTANTIAL RISK OF LOSS.**

- This software is provided for **EDUCATIONAL AND EXPERIMENTAL PURPOSES ONLY**
- **DO NOT USE WITH REAL MONEY** until the codebase is production-ready
- Past performance does not guarantee future results
- Automated trading can lead to significant financial losses
- The developers assume **NO LIABILITY** for any losses incurred

### Legal Considerations

- Ensure cryptocurrency trading is legal in your jurisdiction
- Comply with all local regulations and tax requirements
- Some jurisdictions require licenses for automated trading
- You are solely responsible for legal compliance

### Technical Disclaimers

- **Alpha Software**: This is version 0.1.0 - expect bugs and breaking changes
- **No Warranty**: Provided "AS IS" without warranties of any kind
- **Security**: Custom cryptography is NOT production-grade
- **Data Loss**: Always backup your mnemonic phrase
- **API Changes**: Exchange APIs may change without notice

### Responsible Use

This tool is powerful. Use it responsibly:
- Start with small amounts for testing
- Understand the strategies you deploy
- Monitor the system regularly
- Have stop-loss measures in place
- Never invest more than you can afford to lose

---

## 📄 License

This project is licensed under the **MIT License** - see below for details.

```
MIT License

Copyright (c) 2026 oiko-nomikos

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Third-Party Licenses

- **BIP-39 Word List**: Copyright (c) 2013-2017 Marek Palatinus, Pavol Rusnak (MIT License)
- **nlohmann/json**: Copyright (c) 2013-2022 Niels Lohmann (MIT License)
- **libcurl**: Copyright (c) 1996-2024 Daniel Stenberg (curl License)
- **OpenSSL**: Licensed under Apache License 2.0

---

## 🙏 Acknowledgments

Special thanks to:

- **Bitcoin Core Developers**: For BIP-32, BIP-39, and BIP-44 specifications
- **Crypto Community**: For open-source cryptographic implementations
- **Exchange APIs**: Binance, Coinbase, Kraken for comprehensive API documentation
- **C++ Community**: For excellent libraries and tools

---

## 📞 Contact & Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/oiko-nomikos/Jacquards-Loom/issues)
- **Discussions**: [Community forum](https://github.com/oiko-nomikos/Jacquards-Loom/discussions)
- **Security**: For security vulnerabilities, please report responsibly via GitHub Security Advisories

---

## 📚 Additional Resources

### Learning Resources
- [Bitcoin BIPs](https://github.com/bitcoin/bips) - Bitcoin Improvement Proposals
- [Cryptocurrency Trading Basics](https://www.investopedia.com/cryptocurrency-4427699)
- [C++ Reference](https://en.cppreference.com/)
- [Modern Cryptography](https://crypto.stanford.edu/~dabo/cryptobook/)

### Related Projects
- [ccxt](https://github.com/ccxt/ccxt) - Cryptocurrency trading library
- [freqtrade](https://github.com/freqtrade/freqtrade) - Algorithmic trading bot
- [bitcoin-core](https://github.com/bitcoin/bitcoin) - Bitcoin reference implementation

---

<div align="center">

**Built with ❤️ by the Open Source Community**

⭐ **Star this repo if you find it useful!** ⭐

[Report Bug](https://github.com/oiko-nomikos/Jacquards-Loom/issues) · 
[Request Feature](https://github.com/oiko-nomikos/Jacquards-Loom/issues) · 
[Contribute](https://github.com/oiko-nomikos/Jacquards-Loom/pulls)

</div>
