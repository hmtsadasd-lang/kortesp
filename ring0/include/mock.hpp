#pragma once

// Driverless self-test for the ring0 stack.
//
// Builds a synthetic physical memory image containing page tables and a
// synthetic Fortnite object graph, installs it as the r0 backend, and runs the
// real vmm/esp code against it. This exercises the page walk, the PEB/LDR
// module walk, the offset chain, the projection math and the FString decode
// without needing a vulnerable kernel driver or a running client.
//
// It proves the *code*, not the *offsets* - the synthetic image is built from
// the same offsets.hpp the live path uses, so a wrong offset is invisible
// here and still wrong against a real client.
namespace mock {

// Runs every check. Prints a PASS/FAIL line per check. Returns true if all
// checks passed.
bool run();

} // namespace mock