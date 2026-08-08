import { describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import { inspectElf64X86_64 } from "../../src/ctf/solver/elf-inspection";

function elf64(
	programHeaders: readonly Readonly<{
		type: number;
		flags: number;
		fileOffset: number;
		fileSize: number;
		memorySize: number;
	}>[] = [],
): Uint8Array {
	const bytes = new Uint8Array(64 + programHeaders.length * 56);
	const view = new DataView(bytes.buffer);
	bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]);
	view.setUint16(16, 3, true);
	view.setUint16(18, 62, true);
	view.setUint32(20, 1, true);
	view.setBigUint64(24, 0x401000n, true);
	view.setBigUint64(32, programHeaders.length === 0 ? 0n : 64n, true);
	view.setUint16(52, 64, true);
	view.setUint16(54, 56, true);
	view.setUint16(56, programHeaders.length, true);
	for (const [index, header] of programHeaders.entries()) {
		const offset = 64 + index * 56;
		view.setUint32(offset, header.type, true);
		view.setUint32(offset + 4, header.flags, true);
		view.setBigUint64(offset + 8, BigInt(header.fileOffset), true);
		view.setBigUint64(offset + 16, 0x400000n, true);
		view.setBigUint64(offset + 32, BigInt(header.fileSize), true);
		view.setBigUint64(offset + 40, BigInt(header.memorySize), true);
	}
	return bytes;
}

describe("ELF inspection", () => {
	it("reports bounded structural facts for ELF64 little-endian x86-64 bytes", () => {
		const bytes = elf64([
			{ type: 0x6474e551, flags: 6, fileOffset: 0, fileSize: 0, memorySize: 0 },
			{ type: 0x6474e552, flags: 4, fileOffset: 0, fileSize: 0, memorySize: 0 },
		]);
		expect(inspectElf64X86_64(bytes)).toEqual({
			inputSha256: createHash("sha256").update(bytes).digest("hex"),
			class: "ELF64",
			endianness: "little",
			machine: "x86-64",
			type: "ET_DYN",
			entry: "0x401000",
			programHeaders: [
				{
					type: 0x6474e551,
					flags: 6,
					offset: "0x0",
					virtualAddress: "0x400000",
					fileSize: "0x0",
					memorySize: "0x0",
				},
				{
					type: 0x6474e552,
					flags: 4,
					offset: "0x0",
					virtualAddress: "0x400000",
					fileSize: "0x0",
					memorySize: "0x0",
				},
			],
			mitigations: { pie: "unknown", nx: "enabled", relroSegment: true },
		});
	});
	it("honors typed-array windows rather than inspecting the backing buffer", () => {
		const source = elf64();
		const backing = new Uint8Array(source.byteLength + 16);
		backing.fill(0xff);
		backing.set(source, 8);
		const window = backing.subarray(8, 8 + source.byteLength);
		expect(inspectElf64X86_64(window)).toMatchObject({
			inputSha256: createHash("sha256").update(source).digest("hex"),
			class: "ELF64",
			machine: "x86-64",
		});
	});
	it("does not infer NX when the GNU stack header is absent", () => {
		expect(inspectElf64X86_64(elf64()).mitigations.nx).toBe("unknown");
		expect(
			inspectElf64X86_64(elf64([{ type: 0x6474e551, flags: 7, fileOffset: 0, fileSize: 0, memorySize: 0 }]))
				.mitigations.nx,
		).toBe("disabled");
		expect(() =>
			inspectElf64X86_64(
				elf64([
					{ type: 0x6474e551, flags: 6, fileOffset: 0, fileSize: 0, memorySize: 0 },
					{ type: 0x6474e551, flags: 7, fileOffset: 0, fileSize: 0, memorySize: 0 },
				]),
			),
		).toThrow(/malformed/);
	});

	it("rejects malformed, truncated, wrong-identity, out-of-range, and count-overflow-shaped inputs", () => {
		const malformed = [new Uint8Array(63), elf64(), elf64(), elf64(), elf64(), elf64()];
		malformed[1]![4] = 1;
		new DataView(malformed[2]!.buffer).setUint16(18, 3, true);
		new DataView(malformed[3]!.buffer).setBigUint64(32, 32n, true);
		new DataView(malformed[4]!.buffer).setBigUint64(32, 63n, true);
		new DataView(malformed[5]!.buffer).setUint16(56, 33, true);
		for (const bytes of malformed) expect(() => inspectElf64X86_64(bytes)).toThrow(/malformed/);
		expect(() => inspectElf64X86_64(new Uint8Array(16 * 1024 * 1024 + 1))).toThrow(/malformed/);
		expect(() =>
			inspectElf64X86_64(elf64([{ type: 1, flags: 0, fileOffset: 1000, fileSize: 1, memorySize: 1 }])),
		).toThrow(/malformed/);
		expect(() =>
			inspectElf64X86_64(elf64([{ type: 1, flags: 0, fileOffset: 0, fileSize: 2, memorySize: 1 }])),
		).toThrow(/malformed/);
		const oversizedTable = elf64([{ type: 1, flags: 0, fileOffset: 0, fileSize: 0, memorySize: 0 }]);
		new DataView(oversizedTable.buffer).setBigUint64(32, BigInt(Number.MAX_SAFE_INTEGER) + 1n, true);
		expect(() => inspectElf64X86_64(oversizedTable)).toThrow(/malformed/);
		const oversizedSegment = elf64([{ type: 1, flags: 0, fileOffset: 0, fileSize: 0, memorySize: 0 }]);
		new DataView(oversizedSegment.buffer).setBigUint64(64 + 8, BigInt(Number.MAX_SAFE_INTEGER) + 1n, true);
		expect(() => inspectElf64X86_64(oversizedSegment)).toThrow(/malformed/);
	});
});
