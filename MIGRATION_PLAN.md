# Python 3 + asyncio Migration Plan

## Overview
Migrate SleepProxyServer from Python 2 + gevent to Python 3.8+ + asyncio for better maintainability, security, and performance.

## Phase 1: Dependencies & Setup
- [x] Update setup.py to use Python 3 dependencies
- [x] Replace py2-ipaddress with native ipaddress module
- [x] Remove gevent dependency

## Phase 2: Core Server Migration
- [x] Convert dnsserve.py from gevent.DatagramServer to asyncio
- [x] Replace gevent.spawn with asyncio.create_task
- [x] Update main sleepproxyd script to use asyncio.run()

## Phase 3: Python 3 Compatibility Fixes
- [x] Fix string/bytes handling throughout codebase
- [x] Replace .decode('hex') with bytes.fromhex()
- [x] Update string formatting and operations
- [x] Fix dictionary iteration (items() vs iteritems())

## Phase 4: Module Updates
- [x] Update remaining modules for async compatibility where needed
- [x] Ensure thread-safe operations are properly handled
- [x] Test all network operations

## Phase 5: Testing & Validation
- [ ] Test UDP server functionality
- [ ] Test mDNS registration handling  
- [ ] Test with actual sleep proxy clients
- [ ] Performance benchmarking vs original

## Benefits After Migration
- No external concurrency dependencies
- Better performance with native async/await
- Active Python 3 maintenance and security updates
- Modern development features (type hints, f-strings)
- Easier debugging and profiling

## Backwards Compatibility
- Network protocol remains identical
- Configuration and usage unchanged
- Same command-line interface