# Architecture Overview

This document describes the architectural design of the `net-ingress` subsystem.

The goal of this project is to model how network data enters an operating system kernel, beginning from raw bytes and ending at protocol-aware internal dispatch.

---

## Design Philosophy

The design follows four guiding principles:

1. **Determinism**
   - Fixed-size buffers
   - No dynamic memory allocation
   - Predictable behavior under load

2. **Separation of Concerns**
   - Buffering is independent of parsing
   - Parsing is independent of protocol logic
   - Dispatch is independent of packet representation

3. **OS-Oriented Interfaces**
   - All APIs are designed as if they were linked directly into a kernel
   - No reliance on user-space abstractions

4. **Observability**
   - System behavior is measurable through explicit statistics
   - Errors are returned as data, not hidden or printed

---

## High-Level Data Flow

Incoming bytes -> Ingress buffer (netbuf) -> Packet abstraction -> Protocol parsing (IPv4 / ICMP / TCP) -> Internal dispatch -> Statistics collection

Each stage is implemented as a separate module with a clear interface.

---

## Scope Control

This subsystem intentionally stops before:

- Device drivers
- Packet transmission
- Full protocol state machines
- Concurrency and interrupts

These concerns belong to higher layers or future extensions.

---

## Intended Extensions

Future work may include:

- Integration with a RISC-V kernel
- Interrupt-driven ingress
- Lock-free buffer designs
- Formal verification of parsing logic