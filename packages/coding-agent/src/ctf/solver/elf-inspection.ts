import { createHash } from "node:crypto";

const ELF_HEADER_BYTES = 64;
const PROGRAM_HEADER_BYTES = 56;
const MAX_ELF_BYTES = 16 * 1024 * 1024;
const MAX_PROGRAM_HEADERS = 32;
const PT_GNU_STACK = 0x6474_e551;
const PT_GNU_RELRO = 0x6474_e552;
const PF_X = 1;

export type ElfProgramHeaderSummary = Readonly<{
	type: number;
	flags: number;
	offset: string;
	virtualAddress: string;
	fileSize: string;
	memorySize: string;
}>;

export type ElfInspection = Readonly<{
	inputSha256: string;
	class: "ELF64";
	endianness: "little";
	machine: "x86-64";
	type: "ET_EXEC" | "ET_DYN";
	entry: string;
	programHeaders: readonly ElfProgramHeaderSummary[];
	mitigations: Readonly<{
		pie: "disabled" | "unknown";
		nx: "enabled" | "disabled" | "unknown";
		relroSegment: boolean;
	}>;
}>;

function malformed(): never {
	throw new Error("ELF inspection rejected malformed input");
}

function hex(value: bigint): string {
	return `0x${value.toString(16)}`;
}

function checkedRange(offset: bigint, size: bigint, length: number): number {
	if (offset > BigInt(Number.MAX_SAFE_INTEGER) || size > BigInt(Number.MAX_SAFE_INTEGER)) malformed();
	const start = Number(offset);
	const count = Number(size);
	if (start < 0 || count < 0 || start > length || count > length - start) malformed();
	return start;
}

function u64(view: DataView, offset: number): bigint {
	if (offset < 0 || offset > view.byteLength - 8) malformed();
	return view.getBigUint64(offset, true);
}

/** Inspects only a bounded, in-memory ELF byte sequence; it never resolves paths or executes content. */
export function inspectElf64X86_64(bytes: Uint8Array): ElfInspection {
	if (!(bytes instanceof Uint8Array) || bytes.byteLength < ELF_HEADER_BYTES || bytes.byteLength > MAX_ELF_BYTES)
		malformed();
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	if (
		view.getUint8(0) !== 0x7f ||
		view.getUint8(1) !== 0x45 ||
		view.getUint8(2) !== 0x4c ||
		view.getUint8(3) !== 0x46 ||
		view.getUint8(4) !== 2 ||
		view.getUint8(5) !== 1 ||
		view.getUint8(6) !== 1 ||
		view.getUint8(7) !== 0
	)
		malformed();
	const type = view.getUint16(16, true);
	if (type !== 2 && type !== 3) malformed();
	if (view.getUint16(18, true) !== 62 || view.getUint32(20, true) !== 1) malformed();
	if (view.getUint16(52, true) !== ELF_HEADER_BYTES || view.getUint16(54, true) !== PROGRAM_HEADER_BYTES) malformed();
	const programHeaderCount = view.getUint16(56, true);
	if (programHeaderCount > MAX_PROGRAM_HEADERS) malformed();
	const programHeaderOffset = u64(view, 32);
	const programHeaderBytes = BigInt(programHeaderCount) * BigInt(PROGRAM_HEADER_BYTES);
	let programHeaderStart = 0;
	if (programHeaderCount === 0) {
		if (programHeaderOffset !== 0n) malformed();
	} else {
		programHeaderStart = checkedRange(programHeaderOffset, programHeaderBytes, bytes.byteLength);
		if (programHeaderStart < ELF_HEADER_BYTES) malformed();
	}
	const programHeaders: ElfProgramHeaderSummary[] = [];
	let nx: "enabled" | "disabled" | "unknown" = "unknown";
	let relroSegment = false;
	let stackHeaderSeen = false;
	for (let index = 0; index < programHeaderCount; index++) {
		const offset = programHeaderStart + index * PROGRAM_HEADER_BYTES;
		const segmentType = view.getUint32(offset, true);
		const flags = view.getUint32(offset + 4, true);
		const fileOffset = u64(view, offset + 8);
		const virtualAddress = u64(view, offset + 16);
		const fileSize = u64(view, offset + 32);
		const memorySize = u64(view, offset + 40);
		if (fileSize > memorySize) malformed();
		checkedRange(fileOffset, fileSize, bytes.byteLength);
		if (segmentType === PT_GNU_STACK) {
			if (stackHeaderSeen) malformed();
			stackHeaderSeen = true;
			nx = (flags & PF_X) === 0 ? "enabled" : "disabled";
		}
		if (segmentType === PT_GNU_RELRO) relroSegment = true;
		programHeaders.push(
			Object.freeze({
				type: segmentType,
				flags,
				offset: hex(fileOffset),
				virtualAddress: hex(virtualAddress),
				fileSize: hex(fileSize),
				memorySize: hex(memorySize),
			}),
		);
	}
	return Object.freeze({
		inputSha256: createHash("sha256").update(bytes).digest("hex"),
		class: "ELF64",
		endianness: "little",
		machine: "x86-64",
		type: type === 2 ? "ET_EXEC" : "ET_DYN",
		entry: hex(u64(view, 24)),
		programHeaders: Object.freeze(programHeaders),
		mitigations: Object.freeze({ pie: type === 2 ? "disabled" : "unknown", nx, relroSegment }),
	});
}
