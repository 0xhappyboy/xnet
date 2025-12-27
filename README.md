<h1 align="center">
    🌐 xnet
</h1>
<h4 align="center">
an analysis and monitoring tool focused on the network domain.
</h4>
<p align="center">
  <a href="https://github.com/0xhappyboy/xnet/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-AGPL3.0-d1d1f6.svg?style=flat&labelColor=1C2C2E&color=BEC5C9&logo=googledocs&label=license&logoColor=BEC5C9" alt="License"></a>
</p>
<p align="center">
<a href="./README_zh-CN.md">简体中文</a> | <a href="./README.md">English</a>
</p>

# Demo

<img src="./assets/xnet.gif" alt="xnet demo" width="100%">

# Operation Guide

## Basic Operations

### Launch and Exit

- Launch program: Execute `cargo run`
- Exit program: Press `q` key

### UI Focus Navigation

- Next focus area: Press `Tab` key
- Previous focus area: Press `Shift + Tab` key

Focus area cycle order:

1. Network Interfaces List
2. Packets List
3. Details Panel
4. Hex View

### Operations in Each Focus Area

#### 1. Network Interfaces List (Focus on Interfaces)

- Move selection up: `↑` key
- Move selection down: `↓` key
- Select/Toggle interface: `Space` key
  - If no interface selected: Select and start capture
  - If another interface selected: Switch to new interface and restart capture
  - If current interface selected: Toggle capture state (start/stop)

#### 2. Packets List (Focus on Packets)

- Select previous packet: `↑` key
- Select next packet: `↓` key
- Start/Stop capture: `Space` key

#### 3. Details Panel (Focus on Details)

- Scroll up: `↑` key
- Scroll down: `↓` key

#### 4. Hex View (Focus on Hex)

- Scroll up: `↑` key
- Scroll down: `↓` key

### Other Function Keys

- Clear all packets: Press `r` key
- Refresh network interfaces list: Press `i` key

## Workflow Examples

1. **Start Monitoring**

   - After launching, press `i` to refresh interface list
   - Use `↑`/`↓` to select a network interface
   - Press `Space` to start capturing traffic on that interface

2. **Switch Interface**

   - Use `Tab` to switch to interfaces list
   - Select new interface and press `Space`
   - Program will automatically stop current capture and restart on new interface

3. **Analyze Packets**

   - Use `Tab` to navigate between packets list, details, and hex view
   - Select packets to view detailed information

4. **Pause/Resume Capture**
   - Press `Space` in any focus area to toggle capture state
   - Or select current interface and press `Space`

## Important Notes

- When switching interfaces during capture, there's a 100ms pause
- Clearing packets (`r` key) removes all captured packets
- No need to stop capture before exit - program cleans up automatically
